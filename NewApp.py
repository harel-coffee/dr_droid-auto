#!/usr/bin/python

#code for generating call graphs
#then we need to add both struture and behavior features into it 

# -*- coding: utf-8 -*-

import sys
import time
import os


if sys.path[0] =="":
    SYSPATH = sys.path[1]
else:
    SYSPATH = sys.path[0]
    

if sys.path[0] == "":
	sys.path.append(sys.path[1]+"/androguard/")
	PATH_INSTALL = sys.path[1]+"/androguard"
else:
	sys.path.append(sys.path[0]+"/androguard/")
	PATH_INSTALL = sys.path[0]+"/androguard"

sys.path.append(PATH_INSTALL + "/core/bytecodes/dvm")
sys.path.append(PATH_INSTALL + "/core/analysis/")


from GetMethods import *

from apk import *
from analysis import *
from dvm import *
import Global

from Callinout import *

#graphs
import networkx as nx
#import pygraphviz as pgv

##
# all in android.core.analysis.analysis.py  
##
def show_path( paths ):
    accessPathList = []
    for path in paths:
        if isinstance(path,PathP):
            if path.get_access_flag() == TAINTED_PACKAGE_CALL:
                 s1 = "%s %s %s"  % (path.get_method().get_class_name(), path.get_method().get_name(),path.get_method().get_descriptor()) 
                 s2 = "%s %s %s"  % (path.get_class_name(), path.get_name(), path.get_descriptor())
                 path_t  = s1 + " ---> " + s2  
                 #print (accessPath)
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
    #print ("Permission Total {}  || Used  {} ".format( len(perm_list), len( perm_access.keys() )) )

    for perm in perm_access:
            pathDict[perm] = show_path(perm_access[perm])

    return (pathDict, len(perm_list), len(perm_access.keys()))

class newStart:
      CL = None
      _Callinout = None
      _apk = None
      _vm = None 
      _vmx = None
      fname = None
      classlist = None
      permissionDic = None
      num_of_permission = None
      permission_used = None

      new_nodelist = None
      subgraph_num = None
      def __init__(self,filename):
          """
          Constructor
          """
          self.fname = filename
          self.Tab_initialize_apk(self.fname)
          self.Tab_Methods(self._apk, self._vm, self._vmx)
          self.Tab_CallInOut()
          self.Tab_split()
          self.get_permission_detail()
          #self.clean() 

      def Tab_initialize_apk(self,filename):       
          """
          this part of the codes is based on the APKInfo.py

          """      
          self._apk = APK(filename)
          if not self._apk.is_valid_APK():
            print "not valid apk"
          else:
            self._vm = DalvikVMFormat(self._apk.get_dex())
            self._vmx = VMAnalysis(self._vm)
          #print "OK"   
         
      def Tab_Methods(self, a, vm, vmx):
          """
            Build the Method Tab
            @params: the apk, its vm and vmx 
            based on the : GetMethods.py
          """
          self.CL = None
          self.CL = CLASS(a, vm, vmx)
          classes = self.CL.get_class()
          maxdepth = self.CL.get_maxdepth()
        
          self.classlist = self.CL.get_classlist()
          self.classlist.sort()

      
      def Tab_CallInOut(self):
          """
            Build the CallInOut 
            generate different graphs
            Based on the callinout.py
          """ 
          self._Callinout = None
          M,C, allClasses = self.CL.get_methodInvoke()
          self.classlist = allClasses  #refine the class set
          self._Callinout = YY_CallInOut(M,C,self.classlist) 
          del M
          del C
        
      def Tab_split(self):
          UG1 = self._Callinout.fcgnx_class_level.to_undirected(reciprocal=False) 
          nodelist = list(nx.connected_components(UG1))
          
          #for i in nodelist:
          #    print i
          threshold = 5 #from 5 to 10
          del UG1    
          max_nodes = max([len(i) for i in nodelist])
          
          if max_nodes < threshold or Global.WHOLE_PROGRAM_ANALYSIS:
             #not split
             t = []
             for i in nodelist:
                 t = t + i
             self.new_nodelist = t
             self.subgraph_num = 1     
          else:
             self.new_nodelist = [ i for i in nodelist if len(i) >= threshold ]
             self.subgraph_num = len(self.new_nodelist) 
       
      # this part is to find the major components 
      def __del__(self):
           
          self.CL = None 
          self._apk = None
          self._vm = None
          self._vmx = None
          self.classlist = None
          self._Callinout = None
      
      #this part is handling with permissions used in the application
      def get_permission_detail(self):
          
          self.permissionDic, self.num_of_permission, self.permission_used = permission_really_used( self._apk ,self. _vmx )          
          #print "permission# {0} used {1}".format(self.num_of_permission, self.permission_used)
          #print (self.permissionDic)






