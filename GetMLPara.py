#!/usr/bin/env python
# this part is usnig the SVM to train the datasets
# in sum, we will build a feature vector for each app which represents the behavior and structure properties.

import sys
import os
import matplotlib.pyplot as plt
import numpy as np
import signal

import sklearn
from sklearn import svm,datasets
from sklearn.cross_validation import train_test_split,cross_val_score,StratifiedKFold
from sklearn.metrics import *

from sklearn.datasets import make_classification
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import *

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn import linear_model
from sklearn.feature_selection import SelectKBest, chi2, SelectPercentile, f_classif

from AnalysisCore import *

#print(__doc__)

#this part is reading benign parts
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


################## this is to find the best feature selection###############
def find_best_feature_selections(X,y):

    #select the best features usin different technique
    X_new = SelectKBest(chi2, k=80).fit_transform(X,y)
    X_new1 = SelectPercentile(chi2, percentile=20).fit_transform(X,y)

    X_new2 = SelectKBest(f_classif, k=80).fit_transform(X,y) #this one has the best performance
    X_new22 = SelectPercentile(f_classif, percentile=20).fit_transform(X,y)

    X_new3 = SelectKBest(f_classif, k=70).fit_transform(X,y)
    X_new4 = SelectKBest(f_classif, k=60).fit_transform(X,y)

    print (X_new.shape)
    #selection_parameters_for_classfier(X_new,y)
    #print (y.shape)
    train_and_test(X_new,y)
    train_and_test(X_new1,y)
    train_and_test(X_new2,y)
    train_and_test(X_new22,y)
    train_and_test(X_new3,y)
    train_and_test(X_new4,y)
    #X,y = _dataset_sample()

################################PARAMETER  Selected################################
#TODO some problem happens when using the parameter max_leaf_nodes in Dtree and RandomForest
"""
Results for recommendation:

parameters selecting to make the onesubgraph works better
KNN :(algorithm='auto', leaf_size=30, metric='minkowski', n_neighbors=5, p=2, weights='uniform')
+1

nbg = GaussianNB()
nbm = MultinomialNB()
nbb = BernoulliNB() performs best
-1

decision tree
estimator=DecisionTreeClassifier( criterion='gini',max_depth=None, max_features=None, max_leaf_nodes=None,
 min_samples_leaf=1, min_samples_split=2, random_state=None, splitter='best')
-1

random forest
estimator=RandomForestClassifier(bootstrap=True,  criterion='gini', max_depth=None, max_features='auto',
max_leaf_nodes=None,  min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=None, verbose=0
+1

SVM
estimator=SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=False, random_state=None,
shrinking=True, tol=0.001, verbose=False)
+1
"""

# we make each classifier's parameters as the dic and put it into grid search to find the best parameter required
def selection_parameters_for_classfier(X,y):

    from sklearn import grid_search

    #paras={ 'n_neighbors':[1,10], 'weights':['uniform', 'distance'], 'algorithm':['auto', 'ball_tree','kd_tree', 'brute'], 'leaf_size':[20,50]}
    #knn = KNeighborsClassifier()

    #naive_bayes
    #nbg = GaussianNB()
    #nbm = MultinomialNB()
    #nbb = BernoulliNB()

    #decision tree
    #paras={ 'criterion':['gini','entropy'], 'splitter':['random', 'best'], 'max_features':[None, 'auto','sqrt', 'log2'], 'min_samples_split':[1,10]}
    #dtree = DecisionTreeClassifier()

    #random forest
    #rforest = RandomForestClassifier()
    #paras={ 'n_estimators':[2,15], 'criterion':['gini','entropy'], 'max_features': ['auto','sqrt', 'log2'], 'min_samples_split':[1,10]}

    #svm
    svmm = svm.SVC()
    paras={'kernel':['rbf','linear','poly']}


    clt =grid_search.GridSearchCV(svmm, paras, cv=5)
    clt.fit(X,y)
    print (clt)
    #print (clt.get_params())
    print (clt.set_params())
    print (clt.score(X,y))

    #scores = cross_val_score(clt,X,y,cv=10)
    #print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))


#this is to get score using cross_validation
def get_scroe_using_cv(clt, X, y):
    scores = cross_val_score(clt,X,y,cv=10)
    print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))

#just want to draw a confusion matrix to make it look fantanstic
def draw_confusion_matrix(y_test, y_pred):

    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # Show confusion matrix in a separate window
    plt.matshow(cm)
    plt.title('Confusion matrix')
    plt.colorbar()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()


####################10 CV FALSE POSITIVE FLASE NEGATIVe#################################################
def my_get_fp_fn_CV(X_original,y):

    #generate classfiers
    knn = KNeighborsClassifier(algorithm='auto', leaf_size=30, metric='minkowski', n_neighbors=5, p=2, weights='uniform')

    #decision tree
    dtree = DecisionTreeClassifier( criterion='gini', min_samples_leaf=4, min_samples_split=2, random_state=None, splitter='best')

    #naive
    #nbbern = BernoulliNB()

    #random forest
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',  min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)

    #svm
    svmrbf= svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=True, random_state=None,
shrinking=True, tol=0.001, verbose=False)

    #reduce the size
    #X = SelectKBest(f_classif, k=80).fit_transform(X_original,y)
    skb = SelectKBest(f_classif, k=80).fit(X_original,y)
    X = skb.fit_transform(X_original,y)

    print ("KNN")
    my_get_fp_fn_inter(knn,X,y)
    print ("DTree")
    my_get_fp_fn_inter(dtree,X,y)
    print ("rforest")
    my_get_fp_fn_inter(rforest,X,y)
    #print ("naive bayes")
    #my_get_fp_fn_inter(nbbern,X,y)
    print ("SVMrbf")
    my_get_fp_fn_inter(svmrbf,X,y)

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



#####################################################################
#this part is using for trainig and test to see different cv score
def train_and_test(X,y):

    #KNN
    knn = KNeighborsClassifier(algorithm='auto', leaf_size=30, metric='minkowski', n_neighbors=5, p=2, weights='uniform')

    #naive-bayees
    nbbern = BernoulliNB()

    #decision tree
    dtree = DecisionTreeClassifier( criterion='gini', min_samples_leaf=4, min_samples_split=2, random_state=None, splitter='best')

    #random forest
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',  min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)

    #svm
    svmrbf= svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=False, random_state=None,
shrinking=True, tol=0.001, verbose=False)


    get_scroe_using_cv(knn, X, y)
    get_scroe_using_cv(nbbern, X, y)
    get_scroe_using_cv(dtree, X, y)
    get_scroe_using_cv(rforest, X, y)
    get_scroe_using_cv(svmrbf, X, y)
    print ("\n")

######################################################################

#this is to draw the Roc curve example by splitting the dataset
#just want a figure to make it more beautiful
def get_fpr_tpr(clt, X, y):

    random_state = np.random.RandomState(0)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25 , random_state = 0)

    #from sklearn import tree
    #clt = tree.DecisionTreeClassifier( criterion='entropy', min_samples_leaf=2, min_samples_split=2, random_state=None, splitter='best')
    clt = clt.fit(X_train,y_train)
    #from sklearn.externals.six import StringIO
    #with open("iris_plus.dot", 'w') as f:
    #     f = tree.export_graphviz(clt, out_file=f)

    y_pred = clt.predict(X_test)

    #accuracy score
    _accuracy_score = accuracy_score(y_test, y_pred)

    print ("Accuracy score {}".format(_accuracy_score))

    #roc curve
    probas_ = clt.predict_proba(X_test)
    #print (probas_)
    #draw_confusion_matrix(y_test,y_pred)

    #print probas_
    fpr, tpr, thresholds = roc_curve(y_test, probas_[:, 1])
    #print (fpr, tpr,thresholds)
    roc_auc = auc(fpr, tpr)
    print ("Area under the ROC curve : %f" % roc_auc)

    return fpr, tpr , roc_auc


# this is used to draw
def get_my_pecision_recall(clt, X, y):

    random_state = np.random.RandomState(0)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25 , random_state = 0)

    clt =clt.fit(X_train,y_train)

    probas_ = clt.predict_proba(X_test)

    precision, recall, _ = precision_recall_curve(y_test, probas_[:, 1])

    auc_pr = auc(recall, precision)

    print ( "precision score :%f"  %auc_pr)
    return precision, recall, auc_pr

######################################FINAL RESULT SHOW PERFORMANCE###################################
"""
after preparation, we select 4 different machine learning technique and 80 features with f_classif approach
also cv score selected
"""

def final_train_and_test_after_preparation(X_original,y):

    #KNN
    knn = KNeighborsClassifier(algorithm='auto', leaf_size=30, metric='minkowski', n_neighbors=5, p=2, weights='uniform')

    #decision tree
    dtree = DecisionTreeClassifier( criterion='entropy', min_samples_leaf=4, min_samples_split=2, random_state=None, splitter='best')

    #random forest
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',   min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)

    #svm
    svmrbf= svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=True, random_state=None,
shrinking=True, tol=0.001, verbose=False)

    #naive bayes
    #nbb = BernoulliNB()

    X = SelectKBest(f_classif, k=80).fit_transform(X_original,y)
    #X = X_original
    print (X.shape)
    #get_scroe_using_cv(knn, X, y)
    #get_scroe_using_cv(dtree, X, y)
    #get_scroe_using_cv(rforest, X, y)
    #get_scroe_using_cv(svmrbf, X, y)

    fpr_knn, tpr_knn, auc_knn = get_fpr_tpr(knn, X, y)
    fpr_dtree, tpr_dtree, auc_dtree = get_fpr_tpr(dtree, X, y)
    fpr_rforest, tpr_rforest, auc_rforest = get_fpr_tpr(rforest, X, y)
    fpr_svmrbf, tpr_svmrbf ,auc_svmrbf= get_fpr_tpr(svmrbf, X, y)
    #fpr_nbb, tpr_nbb ,auc_nbb= get_fpr_tpr(nbb, X, y)

    plt.clf()
    plt.plot(fpr_svmrbf, tpr_svmrbf, 'y.--', label ='SVM AUC=%0.4f'% auc_svmrbf)
    plt.plot(fpr_knn, tpr_knn, 'r^--', label='KNN AUC=%0.4f' %auc_knn)
    plt.plot(fpr_dtree, tpr_dtree, 'b>--', label ='D.Tree AUC=%0.4f'% auc_dtree)
    plt.plot(fpr_rforest, tpr_rforest, 'go--', label ='R.Forest AUC=%0.4f'% auc_rforest)
    #plt.plot(fpr_nbb, tpr_nbb, 'c*--', label ='Random Forest auc=%0.4f'% auc_nbb)


    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([-0.02, 1.02])
    plt.ylim([-0.02, 1.02])
    plt.xlabel('FPR(False Positive Rate)',fontsize=20)
    plt.ylabel('TPR(True Positive Rate)',fontsize=20)
    #plt.title('Receiver operating characteristic ')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.grid()
    plt.show()

    del X
    del y

##################################DRAW P-R  CURVE#######################################################
############3  this is the precisio and recall curve
def precision_recall_curve_draw(X_o,y):

    X = SelectKBest(f_classif, k=80).fit_transform(X_o,y)
    print (X.shape)
    print (y.shape)

    svmrbf= svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=True, random_state=None,
shrinking=True, tol=0.001, verbose=False)
    knn = KNeighborsClassifier(algorithm='auto', leaf_size=30, metric='minkowski', n_neighbors=5, p=2, weights='uniform')

    dtree = DecisionTreeClassifier( criterion='gini', min_samples_leaf=1, min_samples_split=2, random_state=None, splitter='best')

    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',  min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)

    p_svmrbf, r_svmrbf, auc_svmrbf = get_my_pecision_recall(svmrbf,X,y)


    p_knn, r_knn, auc_knn = get_my_pecision_recall(knn, X, y)
    p_dtree, r_dtree, auc_dtree = get_my_pecision_recall(dtree, X, y)
    p_rforest, r_rforest, auc_rforest = get_my_pecision_recall(rforest, X, y)

    plt.clf()
    plt.plot(r_svmrbf,p_svmrbf, 'y.--', label ='SVM auc=%0.3f'% auc_svmrbf)
    plt.plot(r_knn, p_knn, 'r^--', label='KNN auc=%0.3f' %auc_knn)
    plt.plot(r_dtree, p_dtree, 'b>--', label ='Decision Tree auc=%0.3f'% auc_dtree)
    plt.plot(r_rforest, p_rforest, 'go--', label ='Random Forest auc=%0.3f'% auc_rforest)

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.0])
    plt.xlabel('recall rate')
    plt.ylabel('precision rate')
    plt.title('precision-recall curve')
    plt.legend(loc="lower right")
    plt.show()

    del X
    del y
###############################################Examples to show the difference of features representation ##################################
from FeatureList import *
from androguard.core.bytecodes.dvm_permissions import *

# f is the apk file name

def features_representation_difference(X_original,y,f):

    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',  min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)
    #rforest= svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=True, random_state=None,
    #shrinking=True, tol=0.001, verbose=False)

    skb = SelectKBest(f_classif, k=80).fit(X_original,y)
    X = skb.fit_transform(X_original,y)
    #print (skb.get_support(indices=False))
    rforest.fit(X,y)
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
    #feature_map =sorted(feature_map)
    #print (feature_map)


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
       for j in bfea.feature_dic.keys():
           vector = bfea.feature_dic[j]
           print (vector)
           classification_vector = skb.transform(vector)

           if (occupy_vector_all_zero(classification_vector)):
               print ("all zero vector detected")
               t = 0
           else:
               t =  int(rforest.predict(skb.transform(vector)))
               print (t)

           #print (rforest.predict_proba(skb.transform(vector)).tolist())
           p_transformed_dic[j] = skb.transform(vector)
           vv.append(t)
           vv_len.append(len(bfea.split_nodelist[j]))
           print (bfea.split_nodelist[j])

       sub_rate = calculate_sub_mali_rate(vv)
       print ("predict dis: {} len {} sub_rate{}".format(vv,vv_len,sub_rate))

       bfea_non = build_features_each_app(new_app, option=False)
       t =  int(rforest.predict(skb.transform (bfea_non.feature_dic[0])))
       nonp_transformed_v = skb.transform (bfea_non.feature_dic[0])
       print ("non predict: {}\n".format(t))

       v1 = p_transformed_dic[0].tolist()[0]
       v2 = p_transformed_dic[1].tolist()[0]
       v3 = nonp_transformed_v.tolist()[0]

       #to compute the feature difference just focus on Apps with two subgraphs
       for r in indices:
           imp_value = rforest.feature_importances_.tolist()[r]
           impp = float("{:10.4f}".format(imp_value))
           ind = sorted_feature_imp.index(imp_value)
           p1 = float("{:10.4f}".format(v1[r]))
           p2 = float("{:10.4f}".format(v2[r]))
           p3 = float("{:10.4f}".format(v3[r]))
           index = feature_map[r]
           print (str(p1) + "  " + str(p2) + " Nonbased " +str(p3)  + " || "+ str(feature_map[r]) + "  " + description_vector[index] + " || " + " weight "+ str(ind)+ " value " +str(impp) )

    else:
       t =  int(rforest.predict(skb.transform (bfea.feature_dic[0])))
       nonp_transformed_v = skb.transform (bfea_non.feature_dic[0])
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

import time
def predict_mulitple_subgraphs(X_original,y):

    time_start = time.time()
    #X = SelectKBest(f_classif, k=80).fit_transform(X_original,y)
    rforest = RandomForestClassifier(bootstrap=True, criterion='gini', max_depth=None, max_features='auto',   min_samples_leaf=1, min_samples_split=2, n_estimators=10, n_jobs=1, oob_score=False, random_state=3)
    #rforest = svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0, degree=3,  kernel='rbf', max_iter=-1, probability=True, random_state=None, shrinking=True, tol=0.001, verbose=False)

    #rforest = KNeighborsClassifier(algorithm='auto', leaf_size=30, metric='minkowski', n_neighbors=5, p=2, weights='uniform')

    #rforest = DecisionTreeClassifier( criterion='gini', min_samples_leaf=1, min_samples_split=2, random_state=None, splitter='best')

    skb = SelectKBest(f_classif, k=80).fit(X_original,y)
    X = skb.fit_transform(X_original,y)
    print (skb.get_support(indices=False))

    rforest.fit(X,y)
    #my_get_fp_fn_inter(rforest,X,y)

    #m_secs =(time.time() - time_start)*1000
    #print ("training mi-seconds {}".format(m_secs))

    f_test_new_released = 'apks/'
 
    files = get_filepaths(f_test_new_released)

    subgraph_property(files, rforest, skb)

import gc
def subgraph_property(files, clt , skb):

    files = sorted(files, key=str.lower)
    files = (files[0:50])
    subgraph_num = []
    malicious_rate = []

    string = "DESCRIBE_YOUR_APKS"
    subgraph_num_file = str(string)  + "_subgraph_number.txt"
    malicious_rate_file = str(string) + "_malicious_rate.txt"

    for f in files:
        print ("{0}".format(f))
        new_app = None
        bfea = None
        if f in _ExceptList :
           continue

        signal.signal(signal.SIGALRM,handler)
        try:
           #signal.alarm(0)
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

               #if sub_rate > 0:
               #   _f_mul_mal_nouseraction.write(f+'\n')
               #if (sub_rate > 0):
               ss = "predict dis: {} #classes-dis:{} sub_rate{}".format(vv,vv_len,sub_rate)
               print (ss)
               #sub_num_multi_v.append(len(vv))
               #sub_num_all_v.append(len(vv))
               #test_vector.append(sub_rate)
               subgraph_num.append(len(vv))
               malicious_rate.append(sub_rate)

               #bfea_non = build_features_each_app(new_app, option=False)
               #t =  int(clt.predict(skb.transform (bfea_non.feature_dic[0])))
               #non_test_vector.append(t)
               #rate_non_partition_multiple.append(t)
               #rate_non_partition_all.append(t)
               #print ("non predict: {}\n".format(t))

           else:
               t =  int(clt.predict(skb.transform (bfea.feature_dic[0])))
               #sub_num_all_v.append(1)

               subgraph_num.append(1)
               malicious_rate.append(t)
               #if (t > 0):
               ss = " single {}".format(t)
               print (ss)
               #if t > 0 :
               #   _f_single_mal_no_useraction.write(f+'\n')
               #test_vector.append(float(t))

           del bfea
        except:
           print ("failed")
           del new_app, bfea
           continue
        #signal.alarm(0)
        gc.collect()

    fnew = open(subgraph_num_file,'w')
    write_list_into_files(subgraph_num, fnew)
    fnew.close()

    fnew = open( malicious_rate_file ,'w')
    write_list_into_files(malicious_rate, fnew)
    fnew.close()

####################################################################################
def feature_importances(X,y):
    # the output does not stable because of the randomness
    # Build a classification task using 3 informative features
    #X, y = make_classification(n_samples=1000,n_features=10,n_informative=3,n_redundant=0,n_repeated=0,n_classes=2,n_state=0,shuffle=False)
    # Build a forest and compute the feature importances
    from sklearn.ensemble import ExtraTreesClassifier
    forest = ExtraTreesClassifier(n_estimators= 25, criterion = 'entropy' , random_state=None)
    forest.fit(X, y)
    importances = forest.feature_importances_

    std = np.std([tree.feature_importances_ for tree in forest.estimators_],axis=0)
    indices = np.argsort(importances)[::-1]
    # print (indices)
    # Print the feature ranking
    print("Feature ranking:")
    sum1 = 0.0
    for f in range(80):
        print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))
        sum1 = sum1 +  importances[indices[f]]
    print (sum1)
    # Plot the feature importances of the forest
    #width = 0.5
    x_len = range(len(importances))
    plt.figure()
    plt.title("Feature importances")
    plt.bar(x_len, importances[indices] ,color="r", yerr=std[indices], align="center")
    plt.xticks(x_len, indices)
    plt.xlim([-1, max(x_len)+1])
    plt.show()

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

    print ("************")
    print ("The training data size: {}".format(X.shape))
    del file1,file2,file3,file4
    del X1,X2,X3,y1,y2,y3,y11,y22,y33
    return X,y

if __name__ == "__main__":

   X, y =read_data_onesubgraph()
   feature_importances(X,y)
   #my_get_fp_fn_CV(X,y)
   final_train_and_test_after_preparation(X,y)
   precision_recall_curve_draw(X,y)





