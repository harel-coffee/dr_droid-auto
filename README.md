# A Static Android Malware Analyzing Tool with Graph Analysis and Machine Learning

## Description
The tool builds a dependence graph of an app and partitions it into different regions based on the graph connection.
Each region is independently classified via machine learning algorithms. The tool provides more insight code structure information than conventional whole-program-based machine learning.


## How to run
Code information of the apk: print the code structure of the app, generate dot graphs for analyzing. 
```python
 usage: main.py [-h] [-w] [+w] [-a] [-f] [-m] [-p PREDICT]

running analysis...

optional arguments:
  -h, --help            show this help message and exit
  -w                    Turn whole-program-analysis off, use regions
  +w                    Turn whole-program-analysis on
  -a, --apkinfo         get Application information
  -f, --feainfo         get Feature information
  -m, --mlparameters    show how we choose a machine learning algorithm based
                        on ROC and precision-recall curves.
  -p PREDICT, --predict PREDICT
                        predict a new apk

```

## Extra functions:

Statistics of the apk files:
```python
python Dir_With_APKs
```
Machine Learning info: show how we choose a machine learning algorithm based on ROC and precision-recall curves.
```python 
python GetMLPara.py
```

## Dependences:

[Sklearn](http://scikit-learn.org/stable/), [NetworkX](https://networkx.github.io/),
[Androguard](https://github.com/androguard), [Androwarn](https://github.com/maaaaz/androwarn),
[MatplotLib](http://matplotlib.org/)
