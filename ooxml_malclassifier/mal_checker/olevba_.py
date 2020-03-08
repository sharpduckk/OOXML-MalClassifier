from oletools import olevba
import logging
# https://github.com/decalage2/oletools


def filter_vba(vba_code):
    """
    Filter VBA source code to remove the first lines starting with "Attribute VB_",
    which are automatically added by MS Office and not displayed in the VBA Editor.
    This should only be used when displaying source code for human analysis.

    Note: lines are not filtered if they contain a colon, because it could be
    used to hide malicious instructions.

    :param vba_code: str, VBA source code
    :return: str, filtered VBA source code
    """
    vba_lines = vba_code.splitlines()
    vba_lines = [str(lines) for lines in vba_lines ]
    start = 0

    for line in vba_lines:
        if line.startswith("Attribute VB_") and not ':' in line:
            start += 1
        else:
            break
    vba = '\n'.join(vba_lines[start:])
    return vba


def get_macros(data_stream):
    """

    :param data_stream:  binary data stream
    :return: macro
    [{'vba_filename': 'ThisDocument.cls', 'subfilename': 'vba', 'ole_stream': 'VBA/ThisDocument', 'code': 'this_is_code_space'}, ...]
    """
    vba2 = olevba.VBA_Parser(filename="vba", data=data_stream)
    macros = []
    try:
        if vba2.detect_vba_macros():
            for (subfilename, stream_path, vba_filename, vba_code) in vba2.extract_all_macros():
                curr_macro = {}
                if vba_code is None:
                    continue
                vba_code_filtered = filter_vba(vba_code)

                curr_macro['vba_filename'] = vba_filename
                curr_macro['subfilename'] = subfilename
                curr_macro['ole_stream'] = stream_path
                curr_macro['code'] = vba_code_filtered.strip()
                if curr_macro['code'] != '':
                    macros.append(curr_macro)
    except TypeError as te:
        logging.exception("get_macros: {te}".format(te=te))
    return macros


