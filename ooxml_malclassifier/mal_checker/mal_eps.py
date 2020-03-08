# -*- coding: utf-8 -*-
import os
import re


# 11	CVE-2015-2545
def check_abnormal_eps_exploit_object(unzip_dir, office_type=""):
    """
    Condition:
        EPS
    :param unzip_dir:
    :return:
    """
    # Precondition
    if office_type != 'word':
        return False
    ret = False
    for (root, _, files) in os.walk(unzip_dir):
        for filename in files:
            if bool(re.match('image\d{1}.eps', filename)):  # e.g. image1.eps
                filepath = os.path.join(root, filename)
                with open(filepath, "r") as f:
                    eps_text = f.read()
                if "90000300000004000000" in eps_text:  # after 'MZ' pe stream
                    ret = True
                elif "string dup 0 77 put dup 1 90 put dup 2" in eps_text:
                    ret = True
                elif bool(re.search('def <[a-f0-9]{100}', eps_text)):
                    ret = True
            if ret is True: break
    return ret
