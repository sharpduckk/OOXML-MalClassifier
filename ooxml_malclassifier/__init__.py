# -*- coding: utf-8 -*-

VERSION = '0.13+'


def _name(name):
    """
    Returns full name for the attribute.
    It checks predefined namespaces used in OOXML documents.
    >>> _name('{{{w}}}rStyle')
    '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}rStyle'
    """
    return name.format(**NAMESPACES)


NAMESPACES = {
    'mo': 'http://schemas.microsoft.com/office/mac/office/2008/main',
    'o': 'urn:schemas-microsoft-com:office:office',
    've': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    # Text Content (word)
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'w10': 'urn:schemas-microsoft-com:office:word',
    'wne': 'http://schemas.microsoft.com/office/word/2006/wordml',
    # Text Content (PowerPoint)
    'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
    # Text Content (Excel)
    'xl': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    # Drawing
    'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
    'm': 'http://schemas.openxmlformats.org/officeDocument/2006/math',
    'mv': 'urn:schemas-microsoft-com:mac:vml',
    'mc': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    'mo': 'http://schemas.microsoft.com/office/mac/office/2008/main',
    'pic': 'http://schemas.openxmlformats.org/drawingml/2006/picture',
    'v': 'urn:schemas-microsoft-com:vml',
    'wp': ('http://schemas.openxmlformats.org/drawingml/2006/wordprocessing'
           'Drawing'),
    # Properties (core and extended)
    'cp': ('http://schemas.openxmlformats.org/package/2006/metadata/core-pr'
           'operties'),
    'dc': 'http://purl.org/dc/elements/1.1/',
    'ep': ('http://schemas.openxmlformats.org/officeDocument/2006/extended-'
           'properties'),
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    # Content Types
    'ct': 'http://schemas.openxmlformats.org/package/2006/content-types',
    # Package Relationships
    'r': ('http://schemas.openxmlformats.org/officeDocument/2006/relationships'),
    'atdtp': ('http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate'),
    'fr': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame',
    'con': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/control',
    'ole': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject',
    'pr': 'http://schemas.openxmlformats.org/package/2006/relationships',

    # Dublin Core document properties
    'dcmitype': 'http://purl.org/dc/dcmitype/',
    'dcterms': 'http://purl.org/dc/terms/',
    # --------------------
    'ax': 'http://schemas.microsoft.com/office/2006/activeX',
}
