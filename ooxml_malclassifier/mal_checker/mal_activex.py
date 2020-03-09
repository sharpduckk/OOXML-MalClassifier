# -*- coding: utf-8 -*-
# Check Malicious ActiveX
import os
import re
import xml.etree.ElementTree as etree
from ooxml_malclassifier import xml_parser, _name
from olefile import olefile


class ActiveXMethod(object):
    def __init__(self):
        self.activeX_xml = {}
        self.xml_tree = {}
        self.activeX_bin = {}
        pass

    def check_activeX_abnormal_number(self, unzip_dir, office_type=""):
        ret = False
        cnt = 0
        threshold_cnt = 10
        flag_activeX_bin = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find activeX[digit].xml
                if bool(re.match('activeX\d{1,2}.xml', filename)):  # e.g. document.xml.rels
                    cnt += 1
                elif bool(re.match('activeX\d{1,2}.bin', filename)):
                    flag_activeX_bin = True
                if cnt >= threshold_cnt and flag_activeX_bin:
                    ret = True
                    break
        return ret

    # 8     CVE-2018-4878
    def check_activeX_ole_contents_swf(self, unzip_dir, office_type=""):
        """
        Condition:
            activeX & SWF
        :param unzip_dir:
        :return:
        """
        # Precondition
        if office_type == 'ppt':
            return False
        ret = False
        bin_docfile = b"\xD0\xCF\x11\xE0"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if bool(re.match('activeX\d{1,2}.bin', filename)):
                    if filename not in self.activeX_bin.keys():
                        with open(file_path, "r+b") as f:
                            self.activeX_bin[filename] = f.read()
                    if self.activeX_bin[filename][:4] == bin_docfile:
                        ole_ = olefile.OleFileIO(self.activeX_bin[filename])
                        for stream in ole_.listdir():
                            if stream[-1] == "Contents":
                                content = ole_.openstream(stream).read()
                                if content[8:11] == b'FWS':
                                    ret = True
                                    break
        return ret

    # 9     CVE-2012-1856
    def check_activeX_mscomctl(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'ppt':
            return False
        ret = False
        flag_mscomctl = False
        flag_match_min_fileSize = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                # dir search and find activeX[digit].xml
                if bool(re.match('activeX\d{1,2}.xml', filename)):  # e.g. document.xml.rels
                    if filename not in self.activeX_xml.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            # xml_txt = f.read()
                            self.activeX_xml[filename] = f.read()
                    if filename not in self.xml_tree.keys():
                        utf8_parser = etree.XMLParser(encoding='utf-8')
                        self.xml_tree = etree.fromstring(self.activeX_xml[filename], parser=utf8_parser)
                    if self.xml_tree.tag == _name('{{{ax}}}ocx'):
                        elements = self.xml_tree
                        if elements.attrib[_name('{{{ax}}}classid')] == '{1EFB6596-857C-11D1-B16A-00C0F0283628}':  # MSCOMCTL.OCX
                            flag_mscomctl = True
                elif bool(re.match('activeX\d{1,2}.bin', filename)):
                    file_path = os.path.join(root, filename)
                    if os.path.getsize(file_path) > 500 * 1024:
                        flag_match_min_fileSize = True
                if flag_mscomctl and flag_match_min_fileSize:
                    ret = True
                    break
        return ret

    # malicious
    def check_adobe_flash_malicious_method(self, unzip_dir, office_type=""):
        bin_clsid_flash = b"\x6E\xDB\x7C\xD2\x6D\xAE\xCF\x11\x96\xB8\x44\x45\x53\x54\x00\x00"
        ret = False
        flag_adobe_flash = False
        flag_persist_storage = False
        flag_bin_clsid_flash = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if bool(re.match('activeX\d{1,2}.xml', filename)):  # e.g. document.xml.rels
                    if filename not in self.activeX_xml.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            # xml_txt = f.read()
                            self.activeX_xml[filename] = f.read()
                    if filename not in self.xml_tree.keys():
                        utf8_parser = etree.XMLParser(encoding='utf-8')
                        self.xml_tree = etree.fromstring(self.activeX_xml[filename], parser=utf8_parser)
                    if self.xml_tree.tag == _name('{{{ax}}}ocx'):
                        elements = self.xml_tree
                        if elements.attrib[_name('{{{ax}}}classid')] == '{D27CDB6E-AE6D-11CF-96B8-444553540000}':  # MSCOMCTL.OCX
                            flag_adobe_flash = True
                            if _name('{{{ax}}}persistence') in elements.attrib.keys() and elements.attrib[_name('{{{ax}}}persistence')] in ('persistStorage', 'persistStreamInit'):
                                flag_persist_storage = True
                elif bool(re.match('activeX\d{1,2}.bin', filename)):
                    if filename not in self.activeX_bin.keys():
                        with open(file_path, "r+b") as f:
                            self.activeX_bin[filename] = f.read()
                    if re.search(bin_clsid_flash, self.activeX_bin[filename]) is not None:
                        flag_bin_clsid_flash = True
                if flag_adobe_flash and flag_persist_storage and flag_bin_clsid_flash:
                    ret = True
                    break
        return ret
