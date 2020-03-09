# -*- coding: utf-8 -*-
# Check Malicious DDE
import os, re
import xml
import xml.etree.ElementTree as etree
import logging
from ooxml_malclassifier import xml_parser, _name


class DdeMethod(object):
    def __init__(self):
        self.dde_run_str = ['cmd.exe', 'powershell', 'mshta.exe']
        self.dde_instr_dict = None
        self.ddelink_dict = None

    @staticmethod
    def unquote(field):
        # https://github.com/decalage2/oletools/blob/master/oletools/msodde.py
        """ if QUOTE exist many times in text"""
        if "QUOTE" not in field:
            return field
        else:
            parts = field.strip().replace("QUOTE", "").split(" ")
            ddestr = ""
            for part in parts:
                try:
                    if part == '':
                        character = ' '
                    else:
                        character = chr(int(part))
                except ValueError:
                    character = part
                ddestr += character
            return ddestr

    def get_instr_text(self, unzip_dir):
        instr_dict = {}
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                # dir search and find .xml
                instr_list = []
                if filename.lower() == "document.xml" or bool(re.match('header\d{1}.xml', filename)) or bool(re.match('footer\d{1}.xml', filename)):  # e.g. document.xml
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_txt = f.read()
                    utf8_parser = etree.XMLParser(encoding='utf-8')
                    try:
                        ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                        for elem in ooxml.iter():
                            # Paragraph
                            instrText = elem.find(_name('{{{w}}}instrText'))
                            if instrText is not None:  # If it has OLE object
                                instr_list.append(instrText.text)
                            fldSimples = elem.findall(_name('{{{w}}}fldSimple'))
                            if len(fldSimples) > 0:
                                for fldSimple in fldSimples:
                                    if _name('{{{w}}}instr') in fldSimple.attrib.keys():
                                        fldSimple_instr = fldSimple.attrib[_name('{{{w}}}instr')]
                                        instr_list.append(fldSimple_instr)
                        if not filename in instr_dict.keys():
                            instr_dict[filename] = ""
                        instr_dict[filename] += self.unquote("".join(instr_list).strip())
                    except xml.etree.ElementTree.ParseError as parse_err:
                        logging.warning(parse_err)
                        logging.warning("Error path: {file_path}".format(file_path=file_path))
        return instr_dict  # dict

    def get_ddelink(self, unzip_dir):
        ret = False
        ddelink_dict = {}
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                # dir search and find .xml
                if bool(re.match('externalLink\d{1,2}.xml', filename)):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_txt = f.read()
                    utf8_parser = etree.XMLParser(encoding='utf-8')
                    try:
                        ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                        for elem in ooxml.iter():
                            # Paragraph
                            ddeLink = elem.find(_name('{{{xl}}}ddeLink'))
                            if ddeLink is not None:  # If it has OLE object
                                ddelink_dict[filename] = dict()
                                ddelink_dict[filename]['ddeService'] = ddeLink.attrib['ddeService']
                                ddelink_dict[filename]['ddeTopic'] = ddeLink.attrib['ddeTopic']
                                ret = True
                    except xml.etree.ElementTree.ParseError as parse_err:
                        logging.warning(parse_err)
                        logging.warning("Error path: {file_path}".format(file_path=file_path))
        return ret, ddelink_dict

    def get_ddes(self, unzip_dir):
        ret = False
        dde_list = []
        ddelink_list = []
        if self.dde_instr_dict is None:
            instr_dict = self.get_instr_text(unzip_dir)
            if len(instr_dict) > 0:
                dde_matched = {}
                for key_, instr_text in instr_dict.items():
                    if re.search('DDE ', instr_text) or re.search(' DDE', instr_text) or re.search('DDEAUTO', instr_text):
                        dde_list.append(key_)
                        dde_matched[key_] = instr_text
                        ret = True
                self.dde_instr_dict = dde_matched
            else:
                self.dde_instr_dict = {}
        flag_ddelink, self.ddelink_dict = self.get_ddelink(unzip_dir)
        if len(self.ddelink_dict) > 0:
            for fname, _ in self.ddelink_dict.items():
                ddelink_list.append(fname)
        if flag_ddelink:
            ret = True
            dde_list = dde_list + ddelink_list
        return ret, dde_list

    def check_dde_sysrun(self, unzip_dir, office_type=""):
        ret = False
        if self.dde_instr_dict is None:
            instr_dict = self.get_instr_text(unzip_dir)
            if len(instr_dict) > 0:
                dde_matched = {}
                for key_, instr_text in instr_dict.items():
                    if re.search('DDE ', instr_text) or re.search(' DDE', instr_text) or re.search('DDEAUTO', instr_text):
                        dde_matched[key_] = instr_text
                        ret = True
                        break
                self.dde_instr_dict = dde_matched
            else:
                self.dde_instr_dict = {}
        for _, instr_text in self.dde_instr_dict.items():
            for run_str in self.dde_run_str:
                if re.search(run_str, instr_text, re.IGNORECASE):
                    ret = True
                    break
        return ret

    # 3     CVE-2016-7262 # only on excel
    def check_ddelink_external(self, unzip_dir, office_type=""):
        """
        Excel
        :param unzip_dir:
        :return:
        """
        # Precondition
        if office_type != 'xl':
            return False
        ret = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find .xml
                if bool(re.match('externalLink\d{1,2}.xml', filename)):
                    if self.ddelink_dict is None:
                        _, self.ddelink_dict = self.get_ddelink(unzip_dir)
                    if len(self.ddelink_dict) > 0:
                        for _, ddelink in self.ddelink_dict.items():
                            if ddelink['ddeService'].lower() in ('cmd', 'powershell', 'dde'):
                                ret = True
                                break
                            run_str = ['cmd.exe', 'powershell.exe', 'bitsadmin', 'calc.exe', 'certutil']
                            if "DDE " in ddelink['ddeTopic']:
                                ddelink['ddeTopic'] = self.unquote(ddelink['ddeTopic'])
                            for str_ in run_str:
                                if str_ in ddelink['ddeTopic'].lower():
                                    ret = True
                                    break
        return ret
