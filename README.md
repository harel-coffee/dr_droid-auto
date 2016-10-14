# A Static Android Malware Analyzing Tool with Graph Analysis and Machine Learning

## Description
The tool builds a dependence graph of an app and partitions it into different regions based on the graph connection.
Each region is independently classified via machine learning algorithms. The tool provides more insight code structure information than conventional whole-program-based machine learning.


## How to run
Code information of the apk: print the code structure of the app, generate dot graphs for analyzing. 
```bash
python main.py -h
usage: main.py [-h] [-w] [+w] [-a] [-f] [-m] [-p PREDICT]

running analysis...

optional arguments:
  -h, --help            show this help message and exit
  -w                    Turn whole-program-analysis off, use regions for
                        classification
  +w                    Turn whole-program-analysis on, ignore code structure
  -a, --apkinfo         get Application information
  -f, --feainfo         get Feature information
  -m, --mlparameters    show how we choose a machine learning algorithm based
                        on ROC and precision-recall curves.
  -p PREDICT, --predict PREDICT
                        predict a tested apk: 1-malicious 0-benign
```


## Example command lines:

use region analysis:
```python
 python main.py -w -a -f -p apks/Geinimi--2e998614b17adbafeb55b5fb9820f63aec5ce8b4.apk 
```

use whole program anlysis:
```python
 python main.py +w -a -f -p apks/Geinimi--2e998614b17adbafeb55b5fb9820f63aec5ce8b4.apk 
```

get ML parameters:
```python
 python main.py -m
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


## Discussions
## version 0.1
