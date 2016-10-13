#!/usr/bin/env python
# this part is usnig the SVM to train the datasets 
# in sum, we will build a feature vector for each app which represents the behavior and structure properties.


from sklearn import svm,datasets
from sklearn.cross_validation import train_test_split,cross_val_score,StratifiedKFold
from sklearn.metrics import *


from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import *

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn.feature_selection import SelectKBest, chi2, SelectPercentile, f_classif

from AnalysisCore import *


def _read_lists(filename):
    data = np.loadtxt(filename)
    x_len, y_len = data.shape
    #print data.shape
    X = data[:,  : (y_len-1)]
    y = data[:, y_len-1]
    return X,y

def _read_lists_vectors(filename):
    data = np.loadtxt(filename)
    x_len, y_len = data.shape
    y = [0]* x_len
    return data,y


#this function is using to write a list into files
def write_list_into_files(list_n, f):
    for i in range(0,len(list_n),1):
        f.write("%f " % list_n[i])
    f.write("\n")  
   
def _dataset_sample():
    iris = datasets.load_iris()
    X = iris.data
    y = iris.target 
    return X,y

###################################### SHELL TO RUN EACH APP ###############
def run_each_app(X_original,y,f):
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto', min_density=None, min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)
   
    skb = SelectKBest(f_classif, k=80).fit(X_original,y)
    X = skb.fit_transform(X_original,y)
    
    clt = rforest.fit(X,y)  
    signal.signal(signal.SIGALRM,handler)
    signal.alarm(100) 
    try: 
           new_app = newStart(f)  
           bfea = build_features_each_app(new_app, option=True) 
           del new_app
           if len(bfea.feature_dic.keys()) > 1:               
               vv = []
               vv_len = []
               for j in bfea.feature_dic.keys():
                   vector = bfea.feature_dic[j]
                   classification_vector = skb.transform(vector) 
                   if (occupy_vector_all_zero(classification_vector)):
                      t = 0
                   else:   
                      t =  int(clt.predict(skb.transform(vector)))
                      
                   vv.append(t)
                   vv_len.append(len(bfea.split_nodelist[j]))
               sub_rate = calculate_sub_mali_rate(vv)

               ss = "predict dis: {} #classes-dis:{} sub_rate{}\n".format(vv,vv_len,sub_rate)
               print (ss)
               
           else:
               t =  int(clt.predict(skb.transform (bfea.feature_dic[0])))
               ss = " single {}\n".format(t)   
               print (ss)

           del bfea
    except:
           print ("failed\n")
           sys.exit(0)

################################## FInal To show the predicting on multiple subgraphs ###############
#test whether it is repackaged/have benign componnets/malicious components 
def predict_new_app(y_pred):    
    x = None
    #t = len(y_pred)
    if 0 in y_pred and 1 not in y_pred:
       x = 0
    if 1 in y_pred and 0 not in y_pred:
       x = 1
    if 1 in y_pred and 0 in y_pred:
       x = 2     
    return x

def calculate_mali_rate(vv, vv_len):
 
    assert isinstance(vv, list)
    assert isinstance(vv_len, list)
    
    total_len = 0
    mali_len = 0
    rate = 0.0
    for i in range(len(vv)):
        total_len = total_len + vv_len[i]
        if vv[i] == 1: 
           mali_len = mali_len + vv_len[i]
    
    rate = float (mali_len +0.0)/total_len
    ben_len = total_len - mali_len
    return (rate, mali_len, ben_len)

def calculate_sub_mali_rate(vv):
    assert isinstance(vv, list)
    total_v = 0
    mal_v = 0
    for i in range(len(vv)):
        total_v = total_v +1
        if vv[i] == 1:
           mal_v = mal_v + 1
    
    rate = float(mal_v +0.0)/total_v
    return (rate)

def occupy_vector_all_zero(_list):
    for i in _list:
        if i.any() > 0:
           return False
    return True 

import signal
def handler(signum,frame):
    print ("time out")
    raise RuntimeError    


######################################READ DATA####################################################
def read_data_onesubgraph():

    file1 = 'data/z_benign_doublechecked_one_subgraph.txt' #994
    file4 = 'data/z_benign_doublechecked_new_one_subgraph.txt' #825

    file2 = 'data/z_mali_genome_one_subgraph.txt'  #409
    file3 = 'data/z_mali_virus_share_one_subgraph.txt' #1097
    

    X1,y1 =_read_lists(file1)
    X4,y4 =_read_lists(file4)
    X2,y2 =_read_lists(file2)
    X3,y3 =_read_lists(file3)
     

    y11 = [0]*len(y1)
    y44 = [0]*len(y4)

    y22 = [1]*len(y2)
    y33 = [1]*len(y3)

    X = np.concatenate((X1,X2,X3,X4), axis = 0)
    y = np.concatenate((y11,y22,y33,y44), axis = 0)
    

    del file1,file2,file3,file4
    del X1,X2,X3,y1,y2,y3,y11,y22,y33
    return X,y   
  
if __name__ == "__main__":

   X, y =read_data_onesubgraph()
   try:
        input_file = sys.argv[1]
   except:
        print("none inputfile detected, use a test input file ")
        input_file ="apks/com.andromo.dev4168.app4242.apk"

   run_each_app(X,y,input_file)
