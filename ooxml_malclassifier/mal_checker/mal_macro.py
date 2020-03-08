# -*- coding: utf-8 -*-
# Check Malicious VBA(Macro) Samples
import os
import re
import logging
import xml.etree.ElementTree as etree
from ooxml_malclassifier import xml_parser, _name
from ooxml_malclassifier.mal_checker import olevba_


class MacroMethod(object):
    def __init__(self):
        self.macro_text = None
        self.vbaProject_bin = None
        # https://github.com/DidierStevens/DidierStevensSuite/blob/master/vba.yara
        self.VBA_AUTORUN = [b'AutoExec', b'autoopen', b'AutoOpen', b'DocumentOpen', b'AutoExit', b'AutoClose',
                       b'Document_Close', b'DocumentBeforeClose', b'Document_Open', b'Document_BeforeClose',
                       b'Auto_Open', b'Workbook_Open', b'Workbook_Activate', b'Auto_Close', b'Workbook_Close']
        self.VBA_SUSP_S = ['CreateObject\("WScript.Shell"\)', 'CreateObject\("WinHttp.WinHttpRequest',
                      'CreateObject\("Microsoft.XMLHTTP"\)', 'Shell\(', 'powershell', 'Private Sub workbook_open\(\)',
                      'ShellExecute']
        self.VBA_SUSP_CreateObject = ['CreateObject("WScript.Shell")', 'CreateObject("WinHttp.WinHttpRequest',
                                 'CreateObject("Microsoft.XMLHTTP")']
        self.XML_MACRO_AUTORUN = ['.AUTOEXEC', '.AUTOOPEN', '.DOCUMENTOPEN', '.AUTOEXIT', '.AUTOCLOSE', '.DOCUMENT_CLOSE',
                             '.DOCUMENTBEFORECLOSE', '.DOCUMENT_OPEN', '.DOCUMENT_BEFORECLOSE', '.AUTO_OPEN',
                             '.WORKBOOK_OPEN', '.WORKBOOK_ACTIVATE', '.AUTO_CLOSE', '.WORKBOOK_CLOSE']
        self.ACTIVEX_AUTORUN = ['Frame1_Layout', 'MultiPage1_Layout', 'ImageCombo21_Change', 'InkEdit1_GotFocus',
                           'InkPicture1_Painted', 'InkPicture1_Painting', 'InkPicture1_Resize',
                           'SystemMonitor1_GotFocus', 'SystemMonitor1_LostFocus']
        self.ACTIVEX_RUN_MOUSE_ON = ['Frame1_MouseMove', 'MultiPage1_MouseMove', 'InkEdit1_MouseMove',
                                'InkPicture1_MouseMove', 'InkPicture1_MouseHover', 'InkPicture1_MouseEnter',
                                'InkPicture1_MouseLeave', 'CheckBox1_MouseMove', 'ComboBox1_MouseMove',
                                'CommandButton1_MouseMove', 'Image1_MouseMove', 'Label1_MouseMove',
                                'ListBox1_MouseMove', 'OptionButton1_MouseMove', 'TabStrip1_MouseMove',
                                'TextBox1_MouseMove', 'ToggleButton1_MouseMove', 'ListView41_MouseMove',
                                'ProgressBar21_MouseMove', 'Slider21_MouseMove', 'StatusBar31_MouseMove',
                                'TabStrip31_MouseMove', 'Toolbar31_MouseMove', 'TreeView41_MouseMove',
                                'AMSREdit1_MouseMove']

    @staticmethod
    def _get_concat_function_declare(raw_text):
        susp_function_name_list = []
        try:
            for match_text in re.findall('CreateObject\(.*\)', raw_text):
                text_ = match_text.split('+')
                text_ = [text__.strip().strip('"').strip("'") for text__ in text_]
                text_ = "".join(text_)
                susp_function_name_list.append(text_)
            return susp_function_name_list
        except:
            logging.exception("Fail to _get_concat_function_declare")
            return susp_function_name_list

    def get_vba_keyword_autoopen(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'xl':
            return False
        ret = False
        flag_xml_autoopen = False
        flag_vbaproject_bin = False
        flag_signature = False  # "vbaProjectSignature.bin"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                if filename == 'vbaData.xml':
                    file_path = os.path.join(root, filename)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        xml_txt = f.read()
                    utf8_parser = etree.XMLParser(encoding='utf-8')
                    ooxml = etree.fromstring(xml_txt, parser=utf8_parser)
                    for elem in ooxml.iter():
                        mcd = elem.find(_name('{{{wne}}}mcd'))
                        if mcd is not None:  # If it has OLE object
                            # if XML_MACRO_AUTORUN
                            if _name('{{{wne}}}macroName') in mcd.attrib.keys():
                                for xml_auto_keyword in self.XML_MACRO_AUTORUN:
                                    if xml_auto_keyword in mcd.attrib[_name('{{{wne}}}macroName')].upper():
                                        flag_xml_autoopen = True
                elif filename == 'vbaProject.bin':
                    flag_vbaproject_bin = True
                elif filename == 'vbaProjectSignature.bin':
                    flag_signature = True
                    break
            if flag_xml_autoopen and flag_vbaproject_bin and flag_signature is False:
                ret = True
        return ret

    def get_vba_keyword_autoopen2(self, unzip_dir, office_type=""):
        # Precondition
        if office_type == 'xl':
            return False
        ret = False
        flag_bin_autoopen = False
        flag_signature = False  # "vbaProjectSignature.bin"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if filename == 'vbaProject.bin':
                    if self.vbaProject_bin is None:
                        with open(file_path, "r+b") as f:
                            self.vbaProject_bin = f.read()
                    # Binary Search Mode
                    for auto_keyword in self.VBA_AUTORUN:
                        # if auto_keyword in vba_data:
                        if re.search(auto_keyword, self.vbaProject_bin, re.IGNORECASE):
                            flag_bin_autoopen = True
                elif filename == 'vbaProjectSignature.bin':
                    flag_signature = True
                    break
            if flag_bin_autoopen and flag_signature is False:
                ret = True
        return ret

    def check_activeX_autoopen_keywords(self, unzip_dir, office_type=""):
        # https://www.greyhathacker.net/?tag=macros
        ret = False
        flag_keyword = False
        flag_activeX = False
        flag_signature = False  # "vbaProjectSignature.bin"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if bool(re.match('activeX\d{1,2}.xml', filename)):
                    flag_activeX = True
                elif filename == 'vbaProject.bin':
                    if self.vbaProject_bin is None:
                        with open(file_path, "r+b") as f:
                            self.vbaProject_bin = f.read()
                    # VBA Code Search Mode
                    if self.macro_text is None:
                        macros = olevba_.get_macros(self.vbaProject_bin)
                        self.macro_text = "".join([macro_dict['code'] for macro_dict in macros])
                    for keyword in self.ACTIVEX_AUTORUN + self.ACTIVEX_RUN_MOUSE_ON:
                        if keyword in self.macro_text:
                            flag_keyword = True
                            break
                elif filename == 'vbaProjectSignature.bin':
                    flag_signature = True
                    break
            if flag_activeX and flag_keyword and flag_signature is False:
                ret = True
        return ret

    def check_text_code_run(self, unzip_dir, office_type=""):
        ret = False
        flag_keyword = False
        flag_activeX = False
        flag_signature = False  # "vbaProjectSignature.bin"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if bool(re.match('activeX\d{1,2}.xml', filename)):
                    flag_activeX = True
                elif filename == 'vbaProject.bin':
                    if self.vbaProject_bin is None:
                        with open(file_path, "r+b") as f:
                            self.vbaProject_bin = f.read()
                    # VBA Code Search Mode
                    if self.macro_text is None:
                        macros = olevba_.get_macros(self.vbaProject_bin)
                        self.macro_text = "".join([macro_dict['code'] for macro_dict in macros])
                    if 'CreateObject' in self.macro_text and 'CommandButton1_Click' in self.macro_text:
                            flag_keyword = True
                            break
                elif filename == 'vbaProjectSignature.bin':
                    flag_signature = True
                    break
            if flag_keyword and flag_activeX and flag_signature is False:
                ret = True
        return ret

    def get_vba_keyword_system_activities(self, unzip_dir, office_type=""):
        # Precondition
        """
        if office_type == 'xl':
            return False
        """
        ret = False
        flag_susp_code = False
        flag_signature = False  # "vbaProjectSignature.bin"
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if filename == 'vbaProject.bin':
                    if self.vbaProject_bin is None:
                        with open(file_path, "r+b") as f:
                            self.vbaProject_bin = f.read()
                    # VBA Code Search Mode
                    if self.macro_text is None:
                        macros = olevba_.get_macros(self.vbaProject_bin)
                        self.macro_text = "".join([macro_dict['code'] for macro_dict in macros])
                    for susp_text in self.VBA_SUSP_S:
                        if re.search(susp_text, self.macro_text, re.IGNORECASE):
                            flag_susp_code = True
                            break
                    # for split text in suspicious function
                    susp_func_str = self._get_concat_function_declare(self.macro_text)
                    if flag_susp_code is False and len(susp_func_str) > 0:
                        for susp_text in self.VBA_SUSP_CreateObject:
                            if susp_text in susp_func_str:
                                flag_susp_code = True
                elif filename == 'vbaProjectSignature.bin':
                    flag_signature = True
                    break
            if flag_susp_code and flag_signature is False:
                ret = True
        return ret


def main():
    pass


if __name__ == "__main__":
    main()
