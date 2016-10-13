# A Static Android Analyzing Tool with Graph Analysis and Machine Learning

## Description
The tool builds a dependence graph of an app and partitions it into different regions based on the graph connection.
Each region is independently classified via machine learning algorithms. The tool provides more insight code structure information than conventional whole-program-based machine learning.


## How to run
Code information of the apk: print the code structure of the app, generate dot graphs for analyzing. 
```python
 python AppInfo.py ApkPath
```
Features information of the apk:print the feature information of the app
```python
 python FeatureInfo.py  ApkPath
```

Train and Predict the apk: train based on existing dataset and predict a new apk.
```python
 python FeatureInfo.py ApKPath
```
Statistics of the apk:
```python
python Dir_With_APKs
```
Machine Learning info: show how we choose a machine learning algorithm based on ROC and precision-recall curves.
```python 
python GetMLPara.py
```

## Dependences:

[Sklearn](http://scikit-learn.org/stable/), [NetworkX](https://networkx.github.io/),
[Androguard](https://github.com/androguard), [Androwarn](https://github.com/maaaaz/androwarn)
[MatplotLib](http://matplotlib.org/)
