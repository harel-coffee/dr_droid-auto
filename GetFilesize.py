#!/usr/bin/python

# ke's code for generating call graphs
#then we need to add both struture and behavior features into it 

# -*- coding: utf-8 -*-

import sys
import os

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

#this function is using to write a list into files
def write_list_into_files_int(list_n, f):
    for i in range(0,len(list_n),1):
        f.write("%d " % list_n[i])
    f.write("\n") 
    f.close()    


def getSize(filename):
    st = os.stat(filename)
    size = st.st_size
    return size

def get_size_list_of_files(file_path): 
    list1=[]    
    file_paths = get_filepaths(file_path)
    for f in file_paths:
        size = getSize(f)
        print (size)
        list1.append(size)
    return list1
     

if __name__=="__main__":
   #the TEST PATH contain several apks for testing
   TEST_PATH = "apks/"
   f3 = open("file_size.txt",'w+')
   list1= get_size_list_of_files(TEST_PATH)
   write_list_into_files_int(list1, f3)
   f3.close()
