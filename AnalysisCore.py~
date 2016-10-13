#!/usr/bin/env python
"""
this part is buiding the vector for features 
and analyzing the features 
"""

import os
import sys
import pydot
import numpy as np
import decimal 
import pygraphviz as pgv
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.mlab as mlab 
import time

### import the part for analyze 
from NewApp import *
from FeatureList import *
from UserTrigger import *

from androguard.core.bytecodes.dvm_permissions import *
# the path to read all the App


def get_filepaths(directory):
    """
    this function will generate the fienames in a directory
    """ 
    file_paths = []
    #walk tree  
    for root,directories,files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root,filename)
            file_paths.append(filepath)
    
    return file_paths    

def get_app_list():
    path = _PATH
    file_paths = get_filepaths(path)
    app_list = []
    for f in file_paths :
        f1 = f.split("/")[-1] 
        app_list.append(f1)
        print f1   

#this function is using to write a list into files
def write_list_into_files_int(list_n, f):
    for i in range(0,len(list_n),1):
        f.write("%d " % list_n[i])
    f.write("\n") 
    f.close()    

def write_list_into_files_float(list_n, f):
    for i in range(0,len(list_n),1):
        f.write("%f " % list_n[i])
    f.write("\n")
    f.close()

#count the number bigger than 0
def count_occupation(list1):
    assert isinstance(list1, list)
    return (sum(1 for x in list1 if x > 0 )) 

#rate calculate for get the properties
def rate_calculate(dic):
    assert isinstance(dic, dict)
    union = []
    intersec = dic[0]
    sym_dif = dic[0]
    max_v = []
    for i in dic.keys():
        union = list(set(union + dic[i]))
        intersec=list(set(intersec).intersection(set(dic[i])))
        if i > 0:
           sym_dif =list(set(sym_dif).symmetric_difference(set(dic[i])))   
        if len(dic[i]) > len(max_v):
           max_v = dic[i] 

    psr_rate = 1.0 - float(len(max_v)+0.0)/len(union)
    jaccord_rate = float(len(intersec)+0.0)/len(union)
    sym_dif_rate = float(len(sym_dif)+0.0)/len(union)

    return psr_rate,jaccord_rate,sym_dif_rate
 

#this is the partfor building the features 
class build_features_each_app: 
   
    #Dic_v = None
    split_nodelist = None
    feature_dic = None
    subgraph_number = None
    def __init__(self, new_app, option):
        self.divide_subgraph(new_app, option)   
        pass

    def __del__(self):
        self.split_nodelist = None
        self.feature_dic = None
        self.subgraph_number = None
        # option = false means consider as a whole one subgraph

    def divide_subgraph(self, new_app, option):
        
        new_nodelist = new_app.new_nodelist 
        self.split_nodelist = new_app.new_nodelist 
        Dic = new_app.permissionDic
        self.subgraph_number = new_app.subgraph_num
        subgraph_num= new_app.subgraph_num
                        
        subgraph_permission, subgraph_permission_cat = permission_real_used_feature(subgraph_num, Dic, new_nodelist, option)
        vector_per, vector_per_cat = permission_used_feature_to_vector(subgraph_permission,subgraph_permission_cat)        
        subgraph_api = sensitive_API_used_subgraph(new_app._vmx, subgraph_num, new_nodelist, option)
        vector_user, vector_rate = user_action_cover_feature(new_app._Callinout.fcgnx, subgraph_num, new_nodelist , new_app._vmx, new_app.classlist, option)
        
        assert isinstance(vector_per, dict)
        assert isinstance(vector_per_cat, dict)
        assert isinstance(subgraph_api, dict)
        assert isinstance(vector_user, dict) 
        assert isinstance(vector_rate, dict)          

        self.feature_dic = {}
        l = len(vector_per.keys())

        #f2 = open('zz_vector_malicious_1_subgraph.txt' , 'a')
        #f3 = open('zz_vector_malicious_more_subgraph.txt' , 'a') 
        total_vector = []
        if l > 1:  
           for i in vector_per.keys():
               self.feature_dic[i] = []
               t1 = [sum(vector_per[i])]
               t11 =[count_occupation(vector_per[i])]

               t2 = [sum(vector_per_cat[i])]
               t22 =[count_occupation(vector_per_cat[i])]

               t3 = [sum(subgraph_api[i])]
               t33 =[count_occupation(subgraph_api[i])]

               t4 = [sum(vector_user[i])]
               t44 = [count_occupation(vector_user[i])]

               t5 =  vector_rate[i] 
               # +[0] malicious +[1]benign
               total_vector = vector_per[i]+t1+t11+vector_per_cat[i]+t2+t22+subgraph_api[i]+t3+t33+vector_user[i]+t4+t44+t5 #+[1]
               self.feature_dic[i] = total_vector 
           
           
           t = max((len(i) for i in new_nodelist))
           #print ("*********************{}".format(t))
           #print ("Multiple and ignore")
           """
           for i in range(0,subgraph_num):
               if len(new_nodelist[i]) == t :      
                  write_list_into_files_float(self.feature_dic[i], f1)
                  break
           """ 
        else:
               t1 = [sum(vector_per[0])]
               t2 = [sum(vector_per_cat[0])]
               t3 = [sum(subgraph_api[0])]
               t4 = t4 = [sum(vector_user[0])] 
               t11 =[count_occupation(vector_per[0])]
               t22 =[count_occupation(vector_per_cat[0])]
               t33 =[count_occupation(subgraph_api[0])]
               t44 = [count_occupation(vector_user[0])]
               t5 =  vector_rate[0]
               total_vector = vector_per[0]+t1+t11+vector_per_cat[0]+t2+t22+subgraph_api[0]+t3+t33+vector_user[0]+t4+t44+t5 #+[0] #benign
               self.feature_dic[0] = total_vector
               #write_list_into_files_float(total_vector, f1)
               
        #print (Dic)
        #raw_input(0 )

_ExceptList = ["your exception apks"]

#####################################################################################
def handle_all_apps_to_vectors(file_read_path): 

    files =get_filepaths(file_read_path)
    i = 0 
    c = 0  
    time_graph =[]
    time_feature = []
    for f in files:
        print (i)
        if f in _ExceptList:
           continue
        print "{0}".format(f)
        new_app = None        
        try :
           time_start = time.time() 
           new_app = newStart(f)
           m_secs =(time.time() - time_start)*1000
           print ("graph generating mi-seconds {}".format(m_secs)) 
           time_graph.append(m_secs)

           time_start = time.time()  
           bfea = build_features_each_app(new_app, option=True)
           #print (bfea.feature_dic)
           m_secs =(time.time() - time_start)*1000
           print ("feature extraction mi-seconds {}".format(m_secs)) 
           time_feature.append(m_secs)
           c = c+1
           
        except:
           print ("{0} failed analyzing ".format(f))
           pass   
        
        i = i +1
    
    f=open('z_graph_generating_time.txt','w')
    for i in range(0,len(time_graph),1):
        f.write("%f " % time_graph[i])
    f.write("\n")
    f.close()
    f =open('z_feature_extracting_time.txt','w')
    for i in range(0,len(time_feature),1):
        f.write("%f " % time_feature[i])
    f.write("\n")     
    f.close()
    
    print ("done")
    print ("total analysze apps #{0}".format(c))

############ TEST   RUN ############
def run_ana_test(input_file):

    new_app = newStart(input_file)
    new_nodelist = None
    
    option = True
    bfea = build_features_each_app(new_app, option)
    print (bfea.feature_dic)
   
    del new_app

   
 
