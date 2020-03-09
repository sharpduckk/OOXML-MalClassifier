# -*- coding: utf-8 -*-
# Check Malicious External Object
import os
import re
import xml.etree.ElementTree as etree
import logging
from ooxml_malclassifier import xml_parser, _name
import urllib.parse
external_types = ['http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject']
external_types_frame = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame'
external_types_attachedTemplate = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate'


class ExternalsMethod(object):
    def __init__(self):
        self.external_rels = {}

    def get_externals(self, unzip_dir):
        ret = False
        external_files = []
        for (root, _, files) in os.walk(unzip_dir):
            # print(root, files)
            for filename in files:
                _, ext = os.path.splitext(filename)
                file_path = os.path.join(root, filename)
                # dir search and find .xml
                try:
                    if ext == '.rels':  # e.g. document.xml.rels
                        if filename not in self.external_rels.keys():
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                xml_txt = f.read().encode("utf-8")
                            xp = xml_parser.XmlParser()
                            xp.parse_relationship(xml_txt)
                            self.external_rels[filename] = xp.relationships
                        for relationship in self.external_rels[filename]:
                            if relationship['target_mode'] == "External":
                                ret = True
                                if filename not in external_files:
                                    external_files.append(filename)
                except etree.ParseError as parse_err:
                    logging.exception(parse_err)
                    logging.exception("Error path: {file_path}".format(file_path=file_path))
                    ret = False
        return ret, external_files

    def check_dynamic_load_externals(self, unzip_dir, office_type=""):
        ret = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find .xml
                _, ext = os.path.splitext(filename)
                file_path = os.path.join(root, filename)
                try:
                    if ext == '.rels':  # e.g. document.xml.rels
                        if filename not in self.external_rels.keys():
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                xml_txt = f.read().encode("utf-8")
                            xp = xml_parser.XmlParser()
                            xp.parse_relationship(xml_txt)
                            self.external_rels[filename] = xp.relationships
                        for relationship in self.external_rels[filename]:
                            if relationship['target_mode'] == "External":
                                if relationship['type'] in external_types:
                                    decode_url = urllib.parse.unquote(relationship['target'])
                                    _, ext = os.path.splitext(decode_url)
                                    if ext in ('.doc', '.docx', '.docm', '.dotm', '.scr', '.exe'):
                                        ret = True
                                elif relationship['type'] == external_types_frame:
                                    ret = True
                                    break
                    if ret is True: break  # Escape
                except etree.ParseError as parse_err:
                    logging.warning(parse_err)
                    logging.warning("Error path: {file_path}".format(file_path=file_path))
                    ret = False
        return ret

    # 2     CVE-2017-0199 (1)
    def get_exteranl_ole_link_type(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'xl':
            return False
        ret = False
        r_id = ""
        flag_ole_link = False
        flag_external = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find .xml
                _, ext = os.path.splitext(filename)
                file_path = os.path.join(root, filename)
                try:
                    if ext == ".xml":  # e.g. document.xml
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            xml_txt = f.read()
                        xp = xml_parser.XmlParser()
                        utf8_parser = etree.XMLParser(encoding='utf-8')
                        ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                        for elem in ooxml.iter():
                            o_oleobject = elem.find(_name('{{{o}}}OLEObject'))
                            if o_oleobject is not None:  # If it has OLE object
                                xp.parse_o_oleobject(o_oleobject)
                                if xp.oleobject_attrib['Type'] == "Link" and xp.oleobject_attrib['child']['o_LinkType'] == "EnhancedMetaFile":
                                    r_id = xp.oleobject_attrib['r_id']
                                    flag_ole_link = True
                                elif xp.oleobject_attrib['Type'] == "Link" and xp.oleobject_attrib['child']['o_LinkType'] == "Picture":
                                    if r"\f 0" in xp.oleobject_attrib['child']['o_FieldCodes']:
                                        r_id = xp.oleobject_attrib['r_id']
                                        flag_ole_link = True
                    if ext == '.rels':  # e.g. document.xml.rels
                        if filename not in self.external_rels.keys():
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                xml_txt = f.read().encode("utf-8")
                            xp = xml_parser.XmlParser()
                            xp.parse_relationship(xml_txt)
                            self.external_rels[filename] = xp.relationships
                        for relationship in self.external_rels[filename]:
                            if relationship['id'] == r_id and relationship['target_mode'] == "External":
                                flag_external = True
                    if flag_ole_link and flag_external:
                        ret = True
                        break
                except etree.ParseError as parse_err:
                    logging.warning(parse_err)
                    logging.warning("Error path: {file_path}".format(file_path=file_path))
                    ret = False
        return ret

    # 2     CVE-2017-0199 (2)
    def get_exteranl_ole_link(self, unzip_dir, office_type=""):
        # Precondition
        if office_type != 'ppt':
            return False
        ret = False
        r_id = ""
        flag_ole_link = False
        flag_external = False
        flag_target_hta = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                _, ext = os.path.splitext(filename)
                file_path = os.path.join(root, filename)
                # dir search and find .xml
                if bool(re.match('slide\d{1}.xml', filename)):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_txt = f.read()
                    xp = xml_parser.XmlParser()
                    utf8_parser = etree.XMLParser(encoding='utf-8')
                    ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                    for elem in ooxml.iter():
                        p_ole = elem.find(_name('{{{p}}}oleObj'))
                        if p_ole is not None:  # If it has OLE object
                            elements = xp.parse_object(p_ole)
                            r_id = elements['attrib'][_name('{{{r}}}id')]
                            for sub in elements['sub']:
                                if sub.tag == _name('{{{p}}}link'):
                                    flag_ole_link = True
                                    break
                if filename == 'slide1.xml.rels':  # e.g. document.xml.rels
                    if filename not in self.external_rels.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            xml_txt = f.read().encode("utf-8")
                        xp = xml_parser.XmlParser()
                        xp.parse_relationship(xml_txt)
                        self.external_rels[filename] = xp.relationships
                    for relationship in self.external_rels[filename]:
                        if relationship['id'] == r_id and relationship['target_mode'] == "External":
                            flag_external = True
                            decode_url = urllib.parse.unquote(relationship['target'])
                            _, ext = os.path.splitext(decode_url)
                            if ext == '.hta':
                                flag_target_hta = True
                                break
                if flag_ole_link and flag_external and flag_target_hta:
                    ret = True
                    break
        return ret

    # 4     CVE-2017-8570
    def get_script_moniker_object(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'word':
            return False
        ret = False
        flag_external = False
        flag_script_moniker = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find .xml
                _, ext = os.path.splitext(filename)
                file_path = os.path.join(root, filename)
                if ext == '.rels':  # e.g. document.xml.rels
                    if filename not in self.external_rels.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            xml_txt = f.read().encode("utf-8")
                        xp = xml_parser.XmlParser()
                        xp.parse_relationship(xml_txt)
                        self.external_rels[filename] = xp.relationships
                    for relationship in self.external_rels[filename]:
                        if relationship['target_mode'] == "External":
                            flag_external = True
                            decode_url = urllib.parse.unquote(relationship['target'])
                            if decode_url.lower()[0:7] == "script:":
                                flag_script_moniker = True
                                break
                if flag_external and flag_script_moniker:
                    ret = True
                    break
        return ret

    # 5     CVE-2017-8759
    def get_soap_moniker_object(self, unzip_dir, office_type=""):
        ret = False
        flag_external = False
        flag_script_moniker = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                # dir search and find .xml
                _, ext = os.path.splitext(filename)
                file_path = os.path.join(root, filename)
                if ext == '.rels':  # e.g. document.xml.rels
                    if filename not in self.external_rels.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            xml_txt = f.read().encode("utf-8")
                        xp = xml_parser.XmlParser()
                        xp.parse_relationship(xml_txt)
                        self.external_rels[filename] = xp.relationships
                    for relationship in self.external_rels[filename]:
                        if relationship['target_mode'] == "External":
                            flag_external = True
                            decode_url = urllib.parse.unquote(relationship['target'])
                            if decode_url.lower()[0:9] == "soap:wsdl":
                                flag_script_moniker = True
                                break
                if flag_external and flag_script_moniker:
                    ret = True
                    break
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
                if bool(re.match('slide\d{1}.xml', filename)):
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
                elif bool(re.match('slide\d{1}.xml.rels', filename)):
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
                if flag_package_shell and flag_embed and flag_cmd and flag_embedding_ole:
                    ret = True
                    break
        return ret

    def check_external_framset_linkedToFile(self, unzip_dir, office_type=""):
        # Precondition
        if office_type != 'word':
            return False
        ret = False
        r_id = ""
        flag_link2file = False
        flag_external = False
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                # dir search and find .xml
                if filename == "webSettings.xml" or filename == "settings.xml":
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_txt = f.read()
                    try:
                        xp = xml_parser.XmlParser()
                        utf8_parser = etree.XMLParser(encoding='utf-8')
                        ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                        for elem in ooxml.iter():
                            p_ole = elem.find(_name('{{{w}}}frame'))
                            if p_ole is not None:  # If it has OLE object
                                elements = xp.parse_object(p_ole)
                                for sub in elements['sub']:
                                    if sub.tag == _name('{{{w}}}sourceFileName'):
                                        r_id = sub.attrib[_name('{{{r}}}id')]
                                    elif sub.tag == _name('{{{w}}}linkedToFile'):
                                        flag_link2file = True
                    except etree.ParseError as parseErr:
                        logging.warning(parseErr)
                        logging.warning("file path: {file_path}".format(file_path=file_path))
                if filename == 'webSettings.xml.rels' or filename == "settings.xml.rels":
                    file_path = os.path.join(root, filename)
                    if filename not in self.external_rels.keys():
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            xml_txt = f.read().encode("utf-8")
                        xp = xml_parser.XmlParser()
                        xp.parse_relationship(xml_txt)
                        self.external_rels[filename] = xp.relationships
                    for relationship in self.external_rels[filename]:
                        if relationship['id'] == r_id and relationship['target_mode'] == "External":
                            flag_external = True
                if flag_link2file and flag_external:
                    ret = True
                    break
        return ret
