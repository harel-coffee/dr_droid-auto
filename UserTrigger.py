#!/usr/bin/env python

# ketian @ 2016
# -*- coding: utf-8 -*-
# Ke modified the source codes

"""
this part is to generating features  from subgraphs and permissions.

including call-graph/control-flow/data dependence 

feature 1
API length

feature 2
user trigger?

feature 3
number of user interactions?

feature 4
Permission 

"""

# Global imports
import sys
import re 

# OptionParser imports
#from optparse import OptionParser

# Androguard imports
PATH_INSTALL = "./androguard/"
sys.path.append(PATH_INSTALL)

# Androwarn modules import
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

sys.setrecursionlimit(100)

from androwarn.core.core import *
from androwarn.search.search import *

# Androguard imports
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes import *

import networkx as nx
from networkx.algorithms import *

from FeatureList import *
from NewApp import *

####
#  sensitive API really used for each subgraph
#  option for choose whether use subgraph tech or not
#
####

############################### SENSITIVE API USAGE ############################################
def sensitive_API_used_subgraph(_vmx, subgraph_num, new_nodelist, option):
    x= _vmx
    subgraph_api ={}
    if option and subgraph_num > 1:
       for i in range(0,subgraph_num):
            subgraph_api[i] = [0]*len(APIList)
    else:
        subgraph_api[0] = [0]*len(APIList)
    
    i = 0
    for destination in APIList:
        names = destination.split("; ")
        class_name = names[0]
        method_name = names[1]
        #print (destination)
        structural_analysis_results = x.tainted_packages.search_methods(class_name,method_name, ".")
        for result in range(0,len(structural_analysis_results)) :
            method = structural_analysis_results[result].get_method()
            class_name = method.get_class_name()
            method_name = method.get_name()
            if option and subgraph_num > 1:
               for r in range(0,subgraph_num):                 
                   if class_name in new_nodelist[r]:
                      subgraph_api[r][i] = subgraph_api[r][i] + 1
            else:
                subgraph_api[0][i] = subgraph_api[0][i] + 1
        i=i+1 
            #print ("{0} {1}".format(class_name,method_name))
    #print (subgraph_api)        
    return (subgraph_api)

####################################permission related feature#################################################
##
#   permission used for subgraph
#   subgraph_permission = {} is the used permissions
#   subgraph_permission_cat = {} is the category of used permissions 
#
##
Manifest = str("MANIFEST_PERMISSION")
def permission_real_used_feature(subgraph_num, Dic, new_nodelist, option):
    
    if subgraph_num > 1 and option:
       subgraph_permission = {}
       subgraph_permission_cat = {}
       for r in range(0,subgraph_num):
           subgraph_permission[r]=[] 
           
       for i in Dic.keys():
           for j in Dic[i]: 
               for r in range(0,subgraph_num):                 
                   if j in new_nodelist[r]:
                      subgraph_permission[r].append(i)

       for r in range(0,subgraph_num):
           subgraph_permission[r]=list(set(subgraph_permission[r]))

           subgraph_permission_cat[r] = []
           for t in subgraph_permission[r]:
               #try:
                    subgraph_permission_cat[r].append(DVM_PERMISSIONS[Manifest][t][0])
               #except:
               #     print (DVM_PERMISSIONS[Manifest][t][0])
      
    else:
       subgraph_permission = {}
       subgraph_permission_cat = {}
       r = 0 
       subgraph_permission[r]=[]
       subgraph_permission_cat[r] =[]
       for i in Dic.keys():
           for j in Dic[i]:
               subgraph_permission[r].append(i) 
       subgraph_permission[r]=list(set(subgraph_permission[r]))
       for t in subgraph_permission[r]:
             #try:
                    subgraph_permission_cat[r].append(DVM_PERMISSIONS[Manifest][t][0])
             #except:
             #       print (DVM_PERMISSIONS[Manifest][t][0])
    """
    for i in subgraph_permission.keys():
        print (subgraph_permission[i]) 
        print (subgraph_permission_cat[i]) 
    """
    return (subgraph_permission,subgraph_permission_cat)      

##
#  this is to generate a vector to present the permission used
#
##

def permission_used_feature_to_vector(subgraph_permission={},subgraph_permission_cat={}):
    permission_cat =['normal','dangerous','signature','signatureOrSystem'] 
    length = len(DVM_PERMISSIONS[Manifest])
    permission_total = ['1']*length
    r =0
    for i in DVM_PERMISSIONS[Manifest].keys():
        permission_total[r]=i
        r = r+1

    #print (subgraph_permission_cat)
    key_len = len(subgraph_permission.keys())
    vector_per = {}
    vector_per_cat ={} 
    for i in range(0,key_len):
        vector_per[i] = [0]*length
        vector_per_cat[i]=[0]*len(permission_cat) 

        for j in subgraph_permission[i]:
            vector_per[i][permission_total.index(j)] = 1          

        for j in subgraph_permission_cat[i]:
            t = permission_cat.index(j)
            vector_per_cat[i][t] = vector_per_cat[i][t]+1            
     
    return (vector_per, vector_per_cat) 

############################### USER ACTION ############################################

def find_class_name(method_name):
    class_name = method_name.split(' ')[0]
    return class_name  


def find_function_name(method_name):
    function_name = method_name.split(' ')[1]
    return function_name 

##
#   user action cover feature
#
##
# option for choosing whether or not using subgraph method 
def user_action_cover_feature(fcgnx, subgraph_num, new_nodelist, _vmx , classlist, option):
    
    vector_user= {}
    vector_coverage= {}
    vector_method={}
    vector_rate ={}    
    #print (new_nodelist)
    if subgraph_num > 1 and option:
       for r in range(0,subgraph_num):
           vector_user[r] =  [0]*len(user_action_list)
           vector_coverage[r] = []
           vector_method[r] = []
           vector_rate[r]=[]
    else:  
           vector_user[0] =  [0]*len(user_action_list)
           vector_coverage[0] = []
           vector_method[0]=[]
           vector_rate[0]=[]

    for j in fcgnx.nodes():
        function_name = find_function_name(j)
        class_name = find_class_name(j)
        if class_name in classlist:           
           if subgraph_num > 1 and option:
              for r in range(0,subgraph_num):
                  if class_name in new_nodelist[r]:
                     vector_method[r].append(str(j))
           else :
              vector_method[0].append(str(j)) 
           

        if function_name in user_action_list:
           pos =  user_action_list.index(function_name)
           if subgraph_num > 1 and option :
              for r in range(0,subgraph_num):
                  if class_name in new_nodelist[r]:
                     vector_user[r][pos] = vector_user[r][pos] + 1
                     successors_nodes = fcgnx.successors(j) 
                     vector_coverage[r] = list(set((vector_coverage[r] + list(successors_nodes))))
           else :    
              vector_user[0][pos] = vector_user[0][pos] + 1
              successors_nodes = fcgnx.successors(j) 
              vector_coverage[0] = list(set((vector_coverage[0] + list(successors_nodes)))) 

    #print (vector_method)
    for r in vector_coverage.keys():
        vector_coverage[r] =  list(set(vector_coverage[r]).intersection(set(vector_method[r])))
        #print (vector_coverage[r])
        #print (vector_method[r])
        rate = float(len(vector_coverage[r])+0.0)/len(vector_method[r])
        vector_rate[r].append(rate) 
        
    
    return vector_user, vector_rate 
    

############################### USER TRIGGER ############################################

#  user_action_list has a seiries of user action names
#  give a node, find whether it has certain string 
# source 
def source_node_check(str1):
    flag = False 
    for i in user_action_list:
        if i in str(str1):     
           flag = True
           return flag

    return flag

def sink_node_check(str1):
    flag = False 
    for i in APIList:
        if i in str(str1):     
           flag = True
           return flag

    return flag

#####
##
#  Data flow analysis based on the modified androwarn.core
##
def user_DDG_API(structural_analysis_results, result, _vmx,):
       
    T_or_F = data_flow_analysis(structural_analysis_results, result, _vmx)	
    return T_or_F


####
#    Control flow analysis based on method_level graph
####
def user_CFG_API(fcgnx, source_node_list, j):
    
    flag=False 
    for i in source_node_list:  
       if nx.has_path(fcgnx, i, j): 
          print (" {} ->  {}".format(i,j)) 
          #print (nx.dijkstra_path(fcgnx,i,j))               
          flag = True
          break
    return flag    
    
###
#  user trigger feature
###
def user_trigger_feature(fcgnx, _vmx):
    
    sink_node_list =[]
    source_node_list = []
    sink_map = {}

    """
    for node in fcgnx.nodes():
        if sink_node_check(node):
           sink_node_list.append(node)
    """
    num_total = 0
    num_trigger = 0
 
    for node in fcgnx.nodes():
        if source_node_check(node):
           source_node_list.append(node)
    
    print ("Trigger relationship")
    for destination in APIList:
        
        names = destination.split("; ")
        class_name = names[0]
        method_name = names[1]
        structural_analysis_results = _vmx.tainted_packages.search_methods(class_name,method_name, ".")

        for result in range(0,len(structural_analysis_results)):
            
            method = structural_analysis_results[result].get_method()
            p_class_name = method.get_class_name()
            p_method_name = method.get_name()
            
            node = str(p_class_name + " " + p_method_name)

            #T_or_F = False
            T_or_F = user_DDG_API(structural_analysis_results, result, _vmx)

            #if T_or_F:
            #   print ("#########") 

            T_F = user_CFG_API(fcgnx, source_node_list, node)

            sink_node_list.append(node)
            
            if node in sink_map.keys():
               sink_map[node].append(destination)
            else:         
               sink_map[node]= []
               sink_map[node].append(destination)
            
            if T_or_F or T_F:
               num_trigger=num_trigger+1           
            
            num_total=num_total+1
    print ("MAP method A : [sensitive APIs in this method A]")
    print (sink_map)  
    print ("total API number {}".format(num_total))
    rate = float(num_trigger+0.0)/num_total
    print ("user trigger rate {}".format(rate))  
        
    assert isinstance(sink_node_list, list)
    assert isinstance(sink_map, dict)

    #print ("{} {}".format(sink_node_list, sink_map))
    return rate 

###
#  New _user_trigger_API 
#  
###
def run_test(input_file):

    new_app = newStart(input_file)
    #r = user_trigger_feature(new_app._Callinout.fcgnx,new_app._vmx) 
    new_nodelist = None
    x1 , x2 = user_action_cover_feature(new_app._Callinout.fcgnx, new_app.subgraph_num, new_app.new_nodelist , new_app._vmx, new_app.classlist, option=False) 
    new_app = None
    

if __name__ == "__main__" :

    file  = "apk/Geinimi--2e998614b17adbafeb55b5fb9820f63aec5ce8b4.apk"
    #user_trigger_API()
    
    #try:
    input_file = sys.argv[1]
    run_test(input_file)
    print ("DONE!")
    #except:
    #    print("none inputfile")
    #    exit(0) 

 
