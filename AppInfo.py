"""
Output the basic information for the app
including class and method information
"""
from NewApp import *

def analyse_CDG_MCG(CDG,MCG):
    CDG1 =CDG
    MCG1= MCG
    CDG = CDG.to_undirected()
    MCG = MCG.to_undirected()
    subgraph_num_CDG = sorted(nx.connected_components(CDG), key= len, reverse=True)
    subgraph_num_MCG = sorted(nx.connected_components(MCG), key= len, reverse=True)
    print ("Method-level Node Size:  {}".format(len(subgraph_num_MCG)))
    print ("CLSS-level Node Size:    {}".format(len(subgraph_num_CDG)))
        
#test the method graph woth permissions used 
def runApkInfo(apk):
    #python measurment performance 
    try:
        input_file = apk
    except:
        print("none inputfile detected, use a test input file ")
        input_file ="apks/com.andromo.dev4168.app4242.apk"

    new_app = newStart(input_file)

    file = open('ClassList.txt','w')
    for list_id in new_app.classlist :
              file.write('%s\n' % list_id)
    file.close()
    print ("The class list is in the ClassList.txt")

    print ("Size Subgraphs: {}".format(new_app.subgraph_num))

    #print Graphs
    nx.write_dot(new_app._Callinout.fcgnx, 'FCGNX_method.dot') 
    nx.write_dot(new_app._Callinout.fcgnx_class_level, 'FCGNX_class.dot') 

    print ("OUtput Graph as FCGNX_method.dot and FCGNX_class.dot")

    #analyse the properties
    UG1 = new_app._Callinout.fcgnx_class_level
    UG2 = new_app._Callinout.fcgnx
    
    analyse_CDG_MCG(UG1,UG2)
