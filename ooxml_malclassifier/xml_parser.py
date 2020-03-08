# -*- coding: utf-8 -*-
"""
    Parse OOXML structure.
    module author:: Aleksandar Erkalovic <aerkalov@gmail.com>
    https://github.com/booktype/python_ooxml/blob/master/ooxml/parse.py
"""
from lxml import etree
from ooxml_malclassifier import NAMESPACES


def _name(name):
    """Returns full name for the attribute.
    It checks predefined namespaces used in OOXML documents.
    >>> _name('{{{w}}}rStyle')
    '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}rStyle'
    """
    return name.format(**NAMESPACES)


class XmlParser(object):
    def __init__(self):
        self.oleobject_attrib = {'Type': "", "ProgID": "", "r_id": "", "ShapeID": "",
                           "child": {"o_LinkType": "", "o_LockedField": "", "o_FieldCodes": ""}
                           }
        self.relationships = []

    def parse_relationship(self, xmlcontent):
        """Parse relationship document.
        Relationships hold information like external or internal references for links.
        Relationships are placed in file '_rels/document.xml.rels'.
        """
        try:
            # https://stackoverflow.com/questions/3402520/is-there-a-way-to-force-lxml-to-parse-unicode-strings-that-specify-an-encoding-i
            utf8_parser = etree.XMLParser(encoding='utf-8')
            et = etree.fromstring(xmlcontent, parser=utf8_parser)

            for elem in et:
                if elem.tag == _name('{{{pr}}}Relationship'):
                    rel = {'id': elem.attrib['Id'],
                           'target': elem.attrib['Target'],
                           'type': elem.attrib['Type'],
                           'target_mode': elem.attrib.get('TargetMode', 'Internal')}  # if not exist -> 'internal'

                    self.relationships.append(rel)
        except ValueError as ve:
            print(ve)
            print(xmlcontent)

    def parse_object(self, element):
        """

        :param element:  using xml.etree.ElementTree.Element
        :return:
        """
        elements = {}
        elements['attrib'] = element.attrib
        elements['sub'] = []
        for elem in element.iter():
            elements['sub'].append(elem)
        return elements

    def parse_o_oleobject(self, element):
        """

        :param element:  using xml.etree.ElementTree.Element
        :return:
        """
        self.oleobject_attrib['Type'] = element.attrib['Type']
        self.oleobject_attrib['ProgID'] = element.attrib['ProgID']
        self.oleobject_attrib['r_id'] = element.attrib[_name('{{{r}}}id')]
        self.oleobject_attrib['ShapeID'] = element.attrib['ShapeID']

        o_linktype = element.find(_name('{{{o}}}LinkType'))
        if o_linktype is not None:
            self.oleobject_attrib['child']['o_LinkType'] = o_linktype.text

        o_lockfield = element.find(_name('{{{o}}}LockedField'))
        if o_lockfield is not None:
            self.oleobject_attrib['child']['o_LockedField'] = o_lockfield.text

        o_fieldcodes = element.find(_name('{{{o}}}FieldCodes'))
        if o_fieldcodes is not None:
            self.oleobject_attrib['child']['o_FieldCodes'] = o_fieldcodes.text

    def parse_w_object(self, element):
        o_oleobject = element.find(_name('{{{o}}}OLEObject'))
        if o_oleobject is not None:
            self.parse_o_oleobject(o_oleobject)
