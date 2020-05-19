# -*- coding: utf-8 -*-
# Check Malicious OLE Object
import os
import re
import struct
import logging
from olefile import olefile
from oletools import oleobj
import xml.etree.ElementTree as etree
from ooxml_malclassifier import xml_parser, _name
import urllib.parse


class OleObjectMethod(object):
    def __init__(self):
        self.oleObject_bin = {}
        self.external_rels = {}
        self.susp_ext = ['.exe', '.scr', '.com', '.pif', '.jar', '.vbs', '.vbe', '.js', '.jse', '.lnk', '.swf', '.rar', '.7z:', '.bat', '.cmd']

    def check_ole_stream_malicious_executable_data(self, unzip_dir, office_type=""):
        ret = False
        bin_docfile = b"\xD0\xCF\x11\xE0"
        for (root, _, files) in os.walk(unzip_dir):
            # print(root, files)
            for filename in files:
                if bool(re.match('oleObject\d{1,2}.bin', filename)):
                    if filename not in self.oleObject_bin.keys():
                        filepath = os.path.join(root, filename)
                        with open(filepath, "r+b") as f:
                            self.oleObject_bin[filename] = f.read()
                    if self.oleObject_bin[filename][:4] == bin_docfile:
                        ole_ = olefile.OleFileIO(self.oleObject_bin[filename])
                        for stream in ole_.listdir():
                            if stream[-1] == "\x01Ole10Native":
                                try:
                                    content = ole_.openstream(stream).read()
                                    stream = oleobj.OleNativeStream(content)
                                    if os.path.splitext(stream.src_path)[1].lower() in self.susp_ext:
                                        ret = True
                                        break
                                except IndexError as indErr:
                                    logging.warning("get_ole_stream_malicious_executable_data: {indErr}".format(indErr=indErr))
                                    logging.warning("[filename]: {unzip_dir}".format(unzip_dir=unzip_dir))
                                except struct.error as structErr:
                                    logging.warning("get_ole_stream_malicious_executable_data: {structErr}".format(structErr=structErr))
                                    logging.warning("[filename]: {unzip_dir}".format(unzip_dir=unzip_dir))
        return ret

    # 1     CVE-2017-11882
    # 6     CVE-2018-0802 # (it covered by same method as #1 CVE-2017-11882)
    def check_equation_editor_harmful_face(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'ppt':
            return False
        ret = False
        bin_docfile = b"\xD0\xCF\x11\xE0"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                if bool(re.match('oleObject\d{1,2}.bin', filename)):
                    if filename not in self.oleObject_bin.keys():
                        filepath = os.path.join(root, filename)
                        with open(filepath, "r+b") as f:
                            self.oleObject_bin[filename] = f.read()
                    if self.oleObject_bin[filename][:4] == bin_docfile:
                        ole_ = olefile.OleFileIO(self.oleObject_bin[filename])
                        for stream in ole_.listdir():
                            if stream[-1].lower() == 'equation native':
                                try:
                                    if ole_.openstream(stream).read()[0x23] == 8:
                                        ret = True
                                        break
                                except IndexError as indErr:
                                    logging.warning("check_equation_editor_harmful_face: {indErr}".format(indErr=indErr))
                                    logging.warning("[filename]: {unzip_dir}".format(unzip_dir=unzip_dir))
        return ret

    def check_equation_editor_harmful_face2(self, unzip_dir, office_type=""):
        ret = False
        bin_docfile = b"\xD0\xCF\x11\xE0"
        bin_eqn_clsid = b"\x02\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                if bool(re.match('oleObject\d{1,2}.bin', filename)):
                    if filename not in self.oleObject_bin.keys():
                        filepath = os.path.join(root, filename)
                        with open(filepath, "r+b") as f:
                            self.oleObject_bin[filename] = f.read()
                    if self.oleObject_bin[filename][:4] == bin_docfile:
                        if re.search(bin_eqn_clsid, self.oleObject_bin[filename]) is not None:
                            ole_ = olefile.OleFileIO(self.oleObject_bin[filename])
                            for stream in ole_.listdir():
                                if stream[-1].lower() == "\x01ole10native" or stream[-1].lower() == 'equation native':
                                    try:
                                        content = ole_.openstream(stream).read(4)
                                        if content != b'\x1C\x00\x00\x00':
                                            ret = True
                                            break
                                    except IndexError as indErr:
                                        logging.warning("check_equation_editor_harmful_face: {indErr}".format(indErr=indErr))
                                        logging.warning("[filename]: {unzip_dir}".format(unzip_dir=unzip_dir))
        return ret

    # 7     CVE-2014-6352
    def get_external_ole_packagershell(self, unzip_dir, office_type=""):
        # Precondition
        if office_type != 'ppt':
            return False
        ret = False
        r_id = ""
        flag_package_shell = False
        flag_cmd = False
        flag_embed = False
        flag_embedding_ole = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find .xml
                file_path = os.path.join(root, filename)
                if bool(re.match('slide\d{1}.xml.rels', filename)):
                    if filename not in self.external_rels.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            xml_txt = f.read().encode("utf-8")
                        xp = xml_parser.XmlParser()
                        xp.parse_relationship(xml_txt)
                        self.external_rels[filename] = xp.relationships
                    for relationship in self.external_rels[filename]:
                        if relationship['id'] == r_id:
                            decode_url = urllib.parse.unquote(relationship['target'])
                            if "../embeddings/oleObject" in decode_url:
                                flag_embedding_ole = True
                elif bool(re.match('slide\d{1}.xml', filename)):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_txt = f.read()
                    xp = xml_parser.XmlParser()
                    utf8_parser = etree.XMLParser(encoding='utf-8')
                    ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                    for elem in ooxml.iter():
                        p_ole = elem.find(_name('{{{p}}}oleObj'))
                        if p_ole is not None:  # If it has OLE object
                            elements = xp.parse_object(p_ole)
                            if elements['attrib']['progId'] == 'Package':
                                flag_package_shell = True
                            r_id = elements['attrib'][_name('{{{r}}}id')]
                            for sub in elements['sub']:
                                if sub.tag == _name('{{{p}}}embed'):
                                    flag_embed = True
                                    break
                        p_cmd = elem.find(_name('{{{p}}}cmd'))
                        if p_cmd is not None:  # If it has OLE object
                            elements = xp.parse_object(p_cmd)
                            if 'type' in elements['attrib'].keys() and 'cmd' in elements['attrib'].keys():
                                if elements['attrib']['type'] == 'verb' and elements['attrib']['cmd'] == '3':
                                    flag_cmd = True
                if flag_package_shell and flag_embed and flag_cmd and flag_embedding_ole:
                    ret = True
                    break
        return ret

    # 8     CVE-2018-4878
    def check_ole_swf_exploitable_data(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'ppt':
            return False
        ret = False
        bin_docfile = b"\xD0\xCF\x11\xE0"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                if bool(re.match('oleObject\d{1,2}.bin', filename)):
                    if filename not in self.oleObject_bin.keys():
                        filepath = os.path.join(root, filename)
                        with open(filepath, "r+b") as f:
                            self.oleObject_bin[filename] = f.read()
                    if self.oleObject_bin[filename][:4] == bin_docfile:
                        ole_ = olefile.OleFileIO(self.oleObject_bin[filename])
                        for stream in ole_.listdir():
                            if stream[-1] == "\x01Ole10Native":
                                try:
                                    content = ole_.openstream(stream).read()
                                    stream = oleobj.OleNativeStream(content)
                                    if stream.data is not None and stream.data[0:3] == b'FWS' and os.path.splitext(stream.filename)[1] == ".swf":
                                        ret = True
                                        break
                                except IndexError as indErr:
                                    logging.warning("get_ole_swf_exploitable_data: {indErr}".format(indErr=indErr))
                                    logging.warning("[filename]: {unzip_dir}".format(unzip_dir=unzip_dir))
                                except struct.error as structErr:
                                    logging.warning("get_ole_swf_exploitable_data: {structErr}".format(structErr=structErr))
                                    logging.warning("[filename]: {unzip_dir}".format(unzip_dir=unzip_dir))
        return ret

    # 10	CVE-2018-8414
    def check_ole_settingcontent_ms(self, unzip_dir, office_type=""):
        # Precondition
        if office_type != 'word':
            return False
        ret = False
        bin_docfile = b"\xD0\xCF\x11\xE0"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                if bool(re.match('oleObject\d{1,2}.bin', filename)):
                    if filename not in self.oleObject_bin.keys():
                        filepath = os.path.join(root, filename)
                        with open(filepath, "r+b") as f:
                            self.oleObject_bin[filename] = f.read()
                    if self.oleObject_bin[filename][:4] == bin_docfile:
                        ole_ = olefile.OleFileIO(filepath)
                        for stream in ole_.listdir():
                            if stream[-1] == "\x01Ole10Native":
                                try:
                                    content = ole_.openstream(stream).read()
                                    stream = oleobj.OleNativeStream(content)
                                    if stream.data is not None and b'{12B1697E-D3A0-4DBC-B568-CCF64A3F934D}' in stream.data:  # settingcontent-ms
                                        ret = True
                                        break
                                except IndexError as indErr:
                                    logging.warning("check_ole_settingcontent_ms: {indErr}".format(indErr=indErr))
                                    logging.warning("[filename]: {filepath}".format(filepath=filepath))
                                except struct.error as structErr:
                                    logging.warning("check_ole_settingcontent_ms: {structErr}".format(structErr=structErr))
                                    logging.warning("[filename]: {filepath}".format(filepath=filepath))
        return ret
