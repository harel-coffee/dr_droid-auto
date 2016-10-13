#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
# Ke modified the source codes


# Global imports
import sys, re, logging

# OptionParser imports
#from optparse import OptionParser

# Androguard imports
PATH_INSTALL = "./androguard/"
sys.path.append(PATH_INSTALL)

# Androwarn modules import
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)
from androwarn.core.core import *
from androwarn.search.search import *
from androwarn.util.util import *
from androwarn.report.report import *
from androwarn.analysis.analysis import *

# Logger definition
log = logging.getLogger('log')
log.setLevel(logging.ERROR)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)

from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes import *
from NewApp import *



def show_path( paths ):
        accessPathList = []
        for path in paths:
            if isinstance(path,analysis.PathP):
                if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL:
                    accessPath = ("%s %s %s (@%s-0x%x)  --->  %s %s %s") % (path.get_method().get_class_name(), path.get_method().get_name(), \
                                                                     path.get_method().get_descriptor(), path.get_bb().get_name(), path.get_bb().start + path.get_idx(), \
                                                                     path.get_class_name(), path.get_name(), path.get_descriptor())
                    
                    print (accessPath)
                    accessPath_class_name = ("%s") % ( path.get_method().get_class_name() )
                    if  accessPath_class_name not  in accessPathList:
                        accessPathList.append(accessPath_class_name)
            
        return accessPathList

##
# input VManalysis object
#
##
def permission_really_used( _apk , _vmx ):
    
    perm_list = _apk.get_permissions()
    # get permission list from androimanifest xml file 
       
    #print (perm_list)
    pathDict = {}
    perm_access = _vmx.tainted_packages.get_permissions([])    
    print (" Permission Total {}  || Used  {} ".format( len(perm_list), len( perm_access.keys() )) )

    for perm in perm_access:
            pathDict[perm] = show_path(perm_access[perm])
    
    print (pathDict)
    exit(0)
    #print (perm_access) 


def main():
     
    try:
        input_file = sys.argv[1]
    except:
        print("none inputfile")
        exit(0) 

    #new_app =newStart(input_file)
    _apk = APK(input_file)
    _vm = DalvikVMFormat(_apk.get_dex())
    _vmx = analysis.VMAnalysis(_vm)
    #permission_really_used( _apk , _vmx )
    

    temp = gather_telephony_services_abuse(_apk,_vmx)
    print (temp)

    """
    for m in allMethods:
        invokingMethod = m.get_class_name() + " " + m.get_descriptor() +"," + m.get_name()
        code =  m.get_code()
        if code == None:
            continue
        else:
            bc = code.get_bc()
            instructions_list = [i for i in bc.get_instructions()]
            for i in range(0, len(instructions_list)):
                current_instruction = instructions_list[i]
                registers_found = {}  
                instruction_name, local_register_number, local_register_value, registers_found =  match_current_instruction(current_instruction, registers_found)
                print ("%s %s" %(current_instruction.get_name(), current_instruction.get_output()))
                print ("%s %s %s %s" %(instruction_name, local_register_number, local_register_value, registers_found) )
                print ("\n")
    """

if __name__ == "__main__" :

    file1  = "apks/Geinimi--2e998614b17adbafeb55b5fb9820f63aec5ce8b4.apk"
    file2 = "FakePlayer--02c489d727cfdbaf2b08e5659030261e5cbea461.apk"
    f = "AnserverBot--4d97042425ca899292c6419d82b070b595fce5b0.apk"
    main()
       
