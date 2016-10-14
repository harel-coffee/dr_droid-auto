import sys
import os
import numpy as np
import signal

import sklearn

from sklearn.cross_validation import train_test_split,cross_val_score,StratifiedKFold


from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, chi2, SelectPercentile, f_classif

from AnalysisCore import *



#this part is reading benign parts
def _read_lists(filename):
    data = np.loadtxt(filename)
    x_len, y_len = data.shape
    #print data.shape
    X = data[:,  : (y_len-1)]
    y = data[:, y_len-1]
    return X,y


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
    
    #print ("************")
    #print (X.shape)
    del file1,file2,file3,file4
    del X1,X2,X3,y1,y2,y3,y11,y22,y33
    return X,y   

def occupy_vector_all_zero(_list):
    for i in _list:
        if i.any() > 0:
           return False
    return True 



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


def my_get_fp_fn_inter(clt,X,y):
    # 10 fold validation
    skf = StratifiedKFold(y, 10)
    fn_v =[]
    fp_v =[]
    accu_v =[]
    for train_index, test_index in skf:
        X_train,X_test = X[train_index], X[test_index]
        y_train,y_test = y[train_index], y[test_index]
        y_predict = clt.fit(X_train,y_train).predict(X_test)
        
        # 1 is malicious 0 is bening
        y_predict_tolist= y_predict.tolist()
        y_test_tolist =  y_test.tolist()
        fn = 0
        fp = 0
        accu = 0
        N = 0
        P = 0
        for i in range(0,len(y_predict_tolist)):
            if int(y_test_tolist[i]) == 1 and int(y_predict_tolist[i]) == 0:
               #false nagative
               fn =fn +1       
            if int(y_test_tolist[i]) == 0 and int(y_predict_tolist[i]) == 1:            
               fp = fp+1    
            if int(y_test_tolist[i]) == 0:
               N = N +1
            if int(y_test_tolist[i])== 1:
               P = P +1
            if int(y_test_tolist[i]) == int(y_predict_tolist[i]):
               accu = accu + 1
            
        accu_score = float(accu+0.0)/len(y_predict_tolist)
        fn_score =float(fn+0.0)/N
        fp_score =float(fp+0.0)/P 
        fn_v.append(fn_score)
        fp_v.append(fp_score)
        accu_v.append(accu_score)
    
    fn_array= np.array(fn_v)
    fp_array=np.array(fp_v)
    accu_array = np.array(accu_v)
    print("fn: %0.4f (+/- %0.4f)" % (fn_array.mean(), fn_array.std()))
    print("fp: %0.4f (+/- %0.4f)" % (fp_array.mean(), fp_array.std()))
    print("Accuracy: %0.4f (+/- %0.4f)" % (accu_array.mean(), accu_array.std()))

###############################################Examples to show the difference of features representation ##################################
from FeatureList import *
from androguard.core.bytecodes.dvm_permissions import *


def features_representation_difference(X_original,y,f):
   
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',  min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)
    #rforest= svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3, gamma=0.0, kernel='rbf', max_iter=-1, probability=True, random_state=None,
    #shrinking=True, tol=0.001, verbose=False)

    skb = SelectKBest(f_classif, k=80).fit(X_original,y)
    X = skb.fit_transform(X_original,y)
    #print (skb.get_support(indices=False))
    clt = rforest.fit(X,y)
    my_get_fp_fn_inter(rforest,X,y)

    features_80_ = skb.get_support(indices=False).tolist()
    len1 = len(features_80_)  #242
    feature_map = {}
    key = 0 
    for i in range(len1):
        if (features_80_[i]):
           feature_map[key]=i  
           key=key+1

    #############description about features
    
    
    Manifest = str("MANIFEST_PERMISSION")
    permission_category =['normal','dangerous','signature','signatureOrSystem'] 
    length = len(DVM_PERMISSIONS[Manifest])
    permission_des = ['1']*length
    r =0
    for i in DVM_PERMISSIONS[Manifest].keys():
        permission_des[r]=i
        r = r+1

    #print (len(permission_des))  #137 permissions + 1 sum +1 occu
    #print (len(permission_category)) # 4 permission category + 1 sum +1 occu
    #print (len(karim_api_list))  # 57 APIs + 1 sum + 1 occu
    #print (len(user_action_list)) # 35 user actions + 1 sum +1 occu

    description_vector = []
    description_vector = list(permission_des) + ['per sum'] + ['per occu'] 
    description_vector = description_vector + list(permission_category) + ['per_cat sum'] + ['per_cat occu']
    description_vector = description_vector + list(APIList) + ['api sum'] + ['api occu']
    description_vector = description_vector + list(user_action_list) + ['action sum'] + ['action occu']
    description_vector = description_vector + ['cover rate']
   
    
    print (f)
    print ("total featuers with description # {}".format(len(description_vector)))

    #to show the description vector
    #for i in range(len(description_vector)): 
        #if (i > 140):   
           # print ("{} -- > {} ".format(i,description_vector[i]))
    #raw_input()

    sms_cat = [145, 146,147, 148,149, 150] 
    phoneid_cat =[151,152,153,161,162,165,166,167]
    network_cat = [154,155,156,163,164,175,176,177,178,179,199,200,201]
    geo_cat = [157,158,159,160,]
    database_cat =[168,169,170,171,172,173,174]
    accounts_cat = [181,182]
    tasks_cat =[183,184,185]
    file_cat = [186,187,188,189,190,191,192,193,194,195,196,197]

    print ("induced features into #{} with importances rates".format(len(rforest.feature_importances_.tolist())))
    feature_importance_v = rforest.feature_importances_.tolist()    

    sorted_feature_imp = sorted(feature_importance_v , key=float, reverse=True)
    indices  = [i[0] for i in sorted(enumerate(feature_importance_v), key=lambda x:x[1])]
  
    new_app = newStart(f)

    bfea = build_features_each_app(new_app, option=True) 
    if len(bfea.feature_dic.keys()) > 1 :
       vv = []
       vv_len = []
       p_transformed_dic = {}
       vv_list = []*len(bfea.feature_dic.keys())
       for j in bfea.feature_dic.keys():
           vector = bfea.feature_dic[j]
           print (vector) 
           classification_vector = skb.transform(vector)
           
           if (occupy_vector_all_zero(classification_vector)):
               print ("all zero vector detected")
               t = 0
           else:   
               t =  int(clt.predict(skb.transform(vector)))

           #print (rforest.predict_proba(skb.transform(vector)).tolist())
           p_transformed_dic[j] = skb.transform(vector)
           vv.append(t)
           vv_len.append(len(bfea.split_nodelist[j]))
           print (bfea.split_nodelist[j])

       sub_rate = calculate_sub_mali_rate(vv) 
       #print ("predict dis: {} len {} sub_rate{}".format(vv,vv_len,sub_rate))
               
       bfea_non = build_features_each_app(new_app, option=False)
       t =  int(clt.predict(skb.transform (bfea_non.feature_dic[0])))
       nonp_transformed_v = skb.transform (bfea_non.feature_dic[0])
       #print ("non predict: {}\n".format(t))
       
       v3 = nonp_transformed_v.tolist()[0] 
       
       #to compute the feature difference just focus on Apps with two subgraphs
       
       for r in indices:   
           imp_value = rforest.feature_importances_.tolist()[r] 
           impp = float("{:10.4f}".format(imp_value))  
           ind = sorted_feature_imp.index(imp_value) 
           for i in range(len(bfea.feature_dic.keys())): 
               v1 = p_transformed_dic[i].tolist()[0]             
               p1 = float("{:10.4f}".format(v1[r]))
               print (str(p1)+ " "),
           p3 = float("{:10.4f}".format(v3[r]))     
           index = feature_map[r]
           print (" Nonbased " +str(p3)  + " || "+ str(feature_map[r]) + "  " + description_vector[index] + " || " + " weight "+ str(ind)+ " value " +str(impp) )

       #print the features as API category for each subgraph
       
       
       for i in range(len(bfea.feature_dic.keys())):
           v1 = p_transformed_dic[i].tolist()[0]
           
           sms = []
           phoneid = []
           network = []
           geo =[]
           database = []
           accounts = []
           tasks =[]
           files =[]
           for r in indices:
               p1 = float("{:10.4f}".format(v1[r])) 
               if not (p1 > 0) :
                  continue
               index = int(feature_map[r])
               description = description_vector[index]

               if index in sms_cat:
                  sms.append(description) 
               elif index in phoneid_cat:
                  phoneid.append(description)
               elif index in network_cat:
                  network.append(description)
               elif index in geo_cat:
                  geo.append(description)
               elif index in database_cat:
                  database.append(description)
               elif index in accounts_cat:
                  accounts.append(description)
               elif index in tasks_cat:
                  tasks.append(description) 
               elif index in file_cat:
                  files.append(description)
               else:
                  pass

           #do something 
           print ("subgraph #{}".format(i))
           print ("SMS: {}".format(sms))    
           print ("PHONEID: {}".format(phoneid)) 
           print ("NETWORK: {}".format(network))   
           print ("GEO: {}".format(geo))
           print ("DATABASE: {}".format(database))
           print ("ACCOUNT: {}".format(accounts))
           print ("TASK: {}".format(tasks))
           print ("FILES: {}".format(files))
           print ("------------")
           
           for j in range(len(bfea.feature_dic[i])):
               if (j < 138) and (bfea.feature_dic[i][j] > 0):
                   print ("{}".format(description_vector[j])) 
             

    else:
       print (bfea.split_nodelist[0])
       t =  int(rforest.predict(skb.transform (bfea.feature_dic[0])))
       nonp_transformed_v = skb.transform (bfea.feature_dic[0])

       for i in range(len(bfea.feature_dic[0])):
           if (i < 138) and (bfea.feature_dic[0][i] > 0):
              print ("{}".format(description_vector[i]))        
  
       v3 = nonp_transformed_v.tolist()[0]
       for r in indices:   
           imp_value = rforest.feature_importances_.tolist()[r] 
           impp = float("{:10.4f}".format(imp_value))  
           ind = sorted_feature_imp.index(imp_value)               
           p3 = float("{:10.4f}".format(v3[r]))     
           index = feature_map[r]
           print (str(p3)  + " || "+ str(feature_map[r]) + "  " + description_vector[index] + " || " + " weight "+ str(ind)+ " value " +str(impp) )
       #print (bfea.feature_dic[0])
       print (t)  
       p_transformed = []
       p_transformed = skb.transform(bfea.feature_dic[0])
       v1 = p_transformed.tolist()[0]
           
       sms = []
       phoneid = []
       network = []
       geo =[]
       database = []
       accounts = []
       tasks =[]
       files =[]
       for r in indices:
           p1 = float("{:10.4f}".format(v1[r])) 
           if not (p1 > 0) :
              continue
           index = int(feature_map[r])
           description = description_vector[index]

           if index in sms_cat:
                  sms.append(description) 
           elif index in phoneid_cat:
                  phoneid.append(description)
           elif index in network_cat:
                  network.append(description)
           elif index in geo_cat:
                  geo.append(description)
           elif index in database_cat:
                  database.append(description)
           elif index in accounts_cat:
                  accounts.append(description)
           elif index in tasks_cat:
                  tasks.append(description) 
           elif index in file_cat:
                  files.append(description)
           else:
                  pass

       #do something 
       print ("subgraph #{}".format(i))
       print ("SMS: {}".format(sms))    
       print ("PHONEID: {}".format(phoneid)) 
       print ("NETWORK: {}".format(network))   
       print ("GEO: {}".format(geo))
       print ("DATABASE: {}".format(database))
       print ("ACCOUNT: {}".format(accounts))
       print ("TASK: {}".format(tasks))
       print ("FILES: {}".format(files))
       print ("------------")
         
if __name__ == "__main__":
   
   try:
        input_file = sys.argv[1]
   except:
        print("none inputfile detected, use a test input file ")
        input_file ="apks/com.andromo.dev4168.app4242.apk"
        #exit(0)

   X, y =read_data_onesubgraph()
   features_representation_difference(X,y, input_file)

