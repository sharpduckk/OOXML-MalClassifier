# -*- coding: utf-8 -*-
from lxml import etree
from ooxml_malclassifier import XMLSPEC


class XmlParser(object):
    def __init__(self):
        self.oleobject_attrib = {'Type': "", "ProgID": "", "r_id": "", "ShapeID": "", "child": {"o_LinkType": "", "o_LockedField": "", "o_FieldCodes": ""}}
        self.relationships = []

    def parse_relationship(self, xml_content):
        try:
            lxml_etree = etree.fromstring(xml_content, parser=etree.XMLParser(encoding='utf-8'))
            for elem in lxml_etree:
                if elem.tag == '{{{pr}}}Relationship'.format(**XMLSPEC):
                    rel = {'id': elem.attrib['Id'], 'target': elem.attrib['Target'], 'type': elem.attrib['Type'],
                           'target_mode': elem.attrib.get('TargetMode', 'Internal')}
                    self.relationships.append(rel)
        except ValueError as ve:
            print(ve, xml_content)

    @staticmethod
    def parse_object(element):
        """
        :param element:  using xml.etree.ElementTree.Element
        :return:
        """
        elements = dict()
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
        self.oleobject_attrib['r_id'] = element.attrib['{{{r}}}id'.format(**XMLSPEC)]
        self.oleobject_attrib['ShapeID'] = element.attrib['ShapeID']

        o_linktype = element.find('{{{o}}}LinkType'.format(**XMLSPEC))
        if o_linktype is not None:
            self.oleobject_attrib['child']['o_LinkType'] = o_linktype.text

        o_lockfield = element.find('{{{o}}}LockedField'.format(**XMLSPEC))
        if o_lockfield is not None:
            self.oleobject_attrib['child']['o_LockedField'] = o_lockfield.text

        o_fieldcodes = element.find('{{{o}}}FieldCodes'.format(**XMLSPEC))
        if o_fieldcodes is not None:
            self.oleobject_attrib['child']['o_FieldCodes'] = o_fieldcodes.text

    def parse_w_object(self, element):
        o_oleobject = element.find('{{{o}}}OLEObject'.format(**XMLSPEC))
        if o_oleobject is not None:
            self.parse_o_oleobject(o_oleobject)