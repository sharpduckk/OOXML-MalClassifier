# -*- coding: utf-8 -*-
import os, sys
import hashlib
import re
import timeit
import zlib
import logging
import json
import multiprocessing
from itertools import repeat
from zipfile import ZipFile, BadZipFile
logging.basicConfig(level=logging.INFO)
sys.path.extend([os.getcwd()])

from ooxml_malclassifier.mal_checker import mal_macro
from ooxml_malclassifier.mal_checker import mal_oleobject
from ooxml_malclassifier.mal_checker import mal_activex
from ooxml_malclassifier.mal_checker import mal_dde
from ooxml_malclassifier.mal_checker import mal_eps
from ooxml_malclassifier.mal_checker import mal_externals

from zip import zip_analysis, logger

class OoxmlClassifier(object):
    """
        OoxmlClassifier
        input: single file path
    """
    def __init__(self, file_path):
        file_name = os.path.basename(file_path)
        self.file_path = file_path
        self.dst_unzip = ""
        md5 = self.get_md5(file_path)
        self.file_info = {
            'fileName': file_name,
            'md5': md5,
            'officeType': "",  # {word | xl | ppt | unknown(exception)}
            'result': None,  # { malicious | suspicious | normal }
            'objects': {
                'Macro': [],
                'OLE': [],
                'activeX': [],
                'DDE': [],
                'EPS': [],
                'External': [],
            },  # e.g. dde, ole..
            'CVE': "",  # CVE-2017-11882
            'description': "",
            'zip': "",
        }
        self.analysis_result = None  # True(Success), False(Fail), None(not yet)
        # Analysis Data
        self.externals_method = mal_externals.ExternalsMethod()
        self.dde_method = mal_dde.DdeMethod()

    @staticmethod
    def get_md5(fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def get_office_type_unzip(unzip_dir):
        flag_office = False
        office_type = ""
        dirs = os.listdir(unzip_dir)
        content_types = "[Content_Types].xml"
        if content_types in dirs:
            if 'word' in dirs:
                office_type = 'word'
                flag_office = True
            elif 'xl' in dirs:
                office_type = 'xl'
                flag_office = True
            elif 'ppt' in dirs:
                office_type = 'ppt'
                flag_office = True
        return flag_office, office_type

    @staticmethod
    def get_office_type_zip(file_path):
        flag_pk = False
        flag_office = False
        office_type = ""
        try:
            with open(file_path, "r+b") as f:
                file_header = f.read(2)
                if file_header.hex() == '504b':  # zlib
                    flag_pk = True
            str_content_types = "[Content_Types].xml"
            zf = ZipFile(file_path)
            entry_names = [entry_name.filename for entry_name in zf.infolist()]
            if (str_content_types in entry_names) and flag_pk is True:
                logging.info("OOXML file: {file_path}".format(file_path=file_path))
                # office type
                for entry_name in entry_names:
                    if entry_name.split('/')[0] == 'word':
                        office_type = 'word'
                        flag_office = True
                        break
                    elif entry_name.split('/')[0] == 'xl':
                        office_type = 'xl'
                        flag_office = True
                        break
                    elif entry_name.split('/')[0] == 'ppt':
                        office_type = 'ppt'
                        flag_office = True
                        break
            else:
                logging.info("Not file OOXML : {file_path}".format(file_path=file_path))

        except BadZipFile as bad_zip_err:
            logging.warning("zip parse failed. file path: {file_path}".format(file_path=file_path))
            logging.warning("ERR: {bad_zip_err}".format(bad_zip_err=bad_zip_err))
        except OSError as os_err:
            _, value, _ = sys.exc_info()
            if value.args[0] == 22:  # 'Invalid argument'
                logging.warning("zip parse failed. file path: {file_path}".format(file_path=file_path))
                logging.warning("ERR: {os_err}".format(os_err=os_err))
            else:
                raise os_err

        return flag_pk and flag_office, office_type

    def extract_metadata(self, dst_dir=""):
        """
        Unzip and Extract all metadata
        if extracted metadata already, it just pass below step.
        :param dst_dir: The dir path to be extracted (not included filename)
        :return:
        """
        if dst_dir == "":
            dst_dir = os.path.dirname(self.file_path)+"_unzip"
        if not (os.path.isdir(dst_dir)):
            os.makedirs(dst_dir)
        file_name = os.path.basename(self.file_path)

        flag_office, office_type = self.get_office_type_zip(self.file_path)
        if flag_office is True:
            self.file_info['officeType'] = office_type
            try:
                if self.dst_unzip == "":  # unzip path not set yet
                    self.dst_unzip = os.path.join(dst_dir, file_name)
                if not os.path.exists(self.dst_unzip):  # dir not exist
                    with ZipFile(self.file_path) as zf:
                        zf.extractall(self.dst_unzip)
                else:
                    pass  # Already exist extracted metadata
                ret_flag = True
            # Exception Cases
            except BadZipFile as bz:
                logging.warning("[Fail] extract_metadata: {file_name}".format(file_name=file_name))
                logging.warning("ERR: {bz}".format(bz=bz))
                ret_flag = False
            except zlib.error as ze:
                logging.warning("[Fail] extract_metadata: {file_name}".format(file_name=file_name))
                logging.warning("ERR: {ze}".format(ze=ze))
                ret_flag = False
            except OSError as oe:
                logging.warning("[Fail] extract_metadata: {file_name}".format(file_name=file_name))
                logging.warning("ERR: {oe}".format(oe=oe))
                ret_flag = False
            return ret_flag
        else:
            self.file_info['result'] = 'NotOOXML'

    def check_malicious_macro(self):
        start = timeit.default_timer()
        macro_method = mal_macro.MacroMethod()
        if macro_method.get_vba_keyword_autoopen(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'vba_keyword_autoopen'
            self.file_info['result'] = 'malicious'
        elif macro_method.get_vba_keyword_autoopen2(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'vba_keyword_autoopen2'
            self.file_info['result'] = 'malicious'
        elif macro_method.check_activeX_autoopen_keywords(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'activeX_autoopen_keywords'
            self.file_info['result'] = 'malicious'
        elif macro_method.check_text_code_run(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'text_code_run'
            self.file_info['result'] = 'malicious'
        elif macro_method.get_vba_keyword_system_activities(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'vba_keyword_system_activities'
            self.file_info['result'] = 'malicious'
        stop = timeit.default_timer()
        logging.debug("[Macro]time: {time}".format(time=str(stop - start)))

    def check_malicious_oleobject(self):
        start = timeit.default_timer()
        oleObject_method = mal_oleobject.OleObjectMethod()
        if oleObject_method.check_equation_editor_harmful_face(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2017-11882'
            self.file_info['description'] = 'equation_editor_harmful_face'
            self.file_info['result'] = 'malicious'
        elif oleObject_method.check_equation_editor_harmful_face2(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2017-11882'
            self.file_info['description'] = 'equation_editor_harmful_face2'
            self.file_info['result'] = 'malicious'
        elif oleObject_method.get_external_ole_packagershell(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2014-6352'
            self.file_info['description'] = 'external_ole_packagershell'
            self.file_info['result'] = 'malicious'
        elif oleObject_method.check_ole_swf_exploitable_data(self.dst_unzip, self.file_info['officeType']):
            # self.file_info['CVE'] = 'CVE-2018-4878'
            self.file_info['description'] = 'ole_swf_exploitable_data'
            self.file_info['result'] = 'malicious'
        elif oleObject_method.check_ole_settingcontent_ms(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2018-8414'
            self.file_info['description'] = 'ole_settingcontent_ms'
            self.file_info['result'] = 'malicious'
        elif oleObject_method.check_ole_stream_malicious_executable_data(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'ole_stream_malicious_executable_data'
            self.file_info['result'] = 'malicious'
        stop = timeit.default_timer()
        logging.debug("[oleObject]time: {time}".format(time=str(stop - start)))

    def check_malicious_activex(self):
        start = timeit.default_timer()
        activeX_method = mal_activex.ActiveXMethod()
        if activeX_method.check_activeX_mscomctl(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2012-1856'
            self.file_info['description'] = 'activeX_ole_contents_swf'
            self.file_info['result'] = 'malicious'
        elif activeX_method.check_activeX_abnormal_number(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'activeX_abnormal_number'
            self.file_info['result'] = 'malicious'
        elif activeX_method.check_activeX_ole_contents_swf(self.dst_unzip, self.file_info['officeType']):
            # self.file_info['CVE'] = 'CVE-2018-4878'
            self.file_info['description'] = 'activeX_ole_contents_swf'
            self.file_info['result'] = 'malicious'
        elif activeX_method.check_adobe_flash_malicious_method(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'adobe_flash_malicious_method'
            self.file_info['result'] = 'malicious'

        stop = timeit.default_timer()
        logging.debug("[activeX]time: {time}".format(time=str(stop - start)))

    def check_malicious_dde(self):
        start = timeit.default_timer()
        if self.dde_method.check_ddelink_external(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2016-7262'
            self.file_info['description'] = 'ddelink_external'
            self.file_info['result'] = 'malicious'
        elif self.dde_method.check_dde_sysrun(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'dde_sysrun'
            self.file_info['result'] = 'malicious'
        stop = timeit.default_timer()
        logging.debug("[DDE]time: {time}".format(time=str(stop - start)))

    def check_malicious_eps(self):
        if mal_eps.check_abnormal_eps_exploit_object(self.dst_unzip, self.file_info['officeType']):
            # self.file_info['CVE'] = 'CVE-2015-2545'
            self.file_info['description'] = 'abnormal_eps_exploit_object'
            self.file_info['result'] = 'malicious'

    def check_malicious_externals(self):
        start = timeit.default_timer()
        if self.externals_method.get_exteranl_ole_link(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2017-0199'
            self.file_info['description'] = 'exteranl_ole_link'
            self.file_info['result'] = 'malicious'
        elif self.externals_method.get_script_moniker_object(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2017-8570'
            self.file_info['description'] = 'script_moniker_object'
            self.file_info['result'] = 'malicious'
        elif self.externals_method.get_soap_moniker_object(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2017-8759'
            self.file_info['description'] = 'soap_moniker_object'
            self.file_info['result'] = 'malicious'
        elif self.externals_method.get_exteranl_ole_link_type(self.dst_unzip, self.file_info['officeType']):
            self.file_info['CVE'] = 'CVE-2017-0199'  # suspicious
            self.file_info['description'] = 'exteranl_ole_link_type'
            self.file_info['result'] = 'malicious'
        elif self.externals_method.check_external_framset_linkedToFile(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'external_framset_linkedToFile'
            self.file_info['result'] = 'malicious'
        elif self.externals_method.check_dynamic_load_externals(self.dst_unzip, self.file_info['officeType']):
            self.file_info['description'] = 'dynamic_load_externals'
            self.file_info['result'] = 'malicious'
        stop = timeit.default_timer()
        logging.debug("[Externals]time: {time}".format(time=str(stop - start)))

    def detect_malicious_properties(self):
        """
        Call mal checker for each object type (e.g. macro)
        """
        if self.dst_unzip == "" or self.file_info['officeType'] == "":  # not set value yet.
            return False

        if self.file_info['result'] == 'suspicious' and self.file_info['objects']['Macro']:
            self.check_malicious_macro()
        self.check_malicious_oleobject()
        if self.file_info['result'] == 'suspicious' and self.file_info['objects']['activeX']:
            self.check_malicious_activex()
        if self.file_info['result'] == 'suspicious' and self.file_info['objects']['DDE']:
            self.check_malicious_dde()
        if self.file_info['result'] == 'suspicious' and self.file_info['objects']['EPS']:
            self.check_malicious_eps()
        if self.file_info['result'] == 'suspicious' and self.file_info['objects']['External']:
            self.check_malicious_externals()

    def get_object_properties(self, unzip_dir=""):
        if unzip_dir == "":
            unzip_dir = self.dst_unzip
        for (root, _, files) in os.walk(unzip_dir):
            for filename in files:
                if filename == 'vbaProject.bin':
                    self.file_info['objects']['Macro'].append(filename)
                if bool(re.match('oleObject\d{1,2}.bin', filename)):  # e.g. document.xml.rels
                    self.file_info['objects']['OLE'].append(filename)
                if bool(re.match('activeX\d{1,2}.bin', filename)):  # e.g. document.xml.rels
                    self.file_info['objects']['activeX'].append(filename)
                if ".eps" in filename:  # entry name contains ".eps"
                    self.file_info['objects']['EPS'].append(filename)
                elif ".ps" in filename:  # entry name contains ".ps"
                    self.file_info['objects']['EPS'].append(filename)

        flag_dde, ddes = self.dde_method.get_ddes(unzip_dir)
        if flag_dde:
            self.file_info['objects']['DDE'] = ddes  # ddes : file name list
        flag_external, externals = self.externals_method.get_externals(unzip_dir)
        if flag_external:
            self.file_info['objects']['External'] = externals  # externals : file name list

        # If it has any of objects
        if any([True if len(flag_) else False for _, flag_ in self.file_info['objects'].items()]):
            self.file_info['result'] = 'suspicious'
        elif self.file_info['result'] is None:
            self.file_info['result'] = 'normal'

    def get_zip_analysis(self):
        logger_ = logger.ValidationLogger(self.file_path)
        zip_analysis.Zip(self.file_path, logger_)
        self.file_info['zip'] = logger_.data_summary

    def get_result(self):
        pass


def _classifier(root, file_, manager_dict):
    file_path = os.path.join(root, file_)
    # 0) Initialize
    classifier = OoxmlClassifier(file_path)
    # 1) Check OOXML & Extract ooxml under pkzip
    classifier.extract_metadata()
    # 2) Detect each object using detection method
    classifier.get_object_properties()
    # 3) Detect malicious object with CVE vulnerability case
    classifier.detect_malicious_properties()
    # 4) Detect malicious zip structure
    classifier.get_zip_analysis()
    if 'verbose' in manager_dict.keys():
        print(classifier.file_info)
    if classifier.file_info['result'] != 'NotOOXML':
        manager_dict['file_info'][classifier.file_info['md5']] = classifier.file_info
    if classifier.file_info['result'] == 'malicious':
        manager_dict['malicious'].append(file_)
    elif classifier.file_info['result'] == 'suspicious':
        manager_dict['suspicious'].append(file_)
    elif classifier.file_info['result'] == 'normal':
        manager_dict['normal'].append(file_)


def main():
    # Arg Parser#
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dirpath', help='directory path to be classified', required=True)
    parser.add_argument('-o', '--output', help='result output path')
    parser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')
    args = parser.parse_args()

    # arg set on edit configuration

    start = timeit.default_timer()
    root_path = args.dirpath
    input_list = os.listdir(root_path)

    manager = multiprocessing.Manager()
    pool_dict = manager.dict()
    # Save Result Class
    pool_dict['malicious'] = manager.list()
    pool_dict['suspicious'] = manager.list()
    pool_dict['normal'] = manager.list()
    # Save file info
    pool_dict['file_info'] = manager.dict()
    # print processing data on console
    if args.verbose is True:
        pool_dict['verbose'] = True

    num_cores = multiprocessing.cpu_count()  # number of cpu core
    pool = multiprocessing.Pool(num_cores)
    pool.starmap(_classifier, zip(repeat(root_path), input_list, repeat(pool_dict)))
    pool.close()
    pool.join()

    print("I think we're done job.")
    stop = timeit.default_timer()
    logging.info("time taken: {time}".format(time=str(stop - start)))

    output = "output.json"
    if args.output is not None:
        output = args.output
    with open(output, "w") as write_file:
        json.dump(pool_dict['file_info'].copy(), write_file, indent=4)

    print("[Result (File)]")
    print("mal: ", pool_dict['malicious'])
    print("suspicious: ", pool_dict['suspicious'])
    print("normal: ", pool_dict['normal'])

    print("[Result (Count)]")
    print("mal: ", len(pool_dict['malicious']))
    print("suspicious: ", len(pool_dict['suspicious']))
    print("normal: ", len(pool_dict['normal']))


if __name__ == "__main__":
    main()
