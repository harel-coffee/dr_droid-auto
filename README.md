# A Static Android Malware Analyzing Tool with Graph Analysis and Machine Learning

## Description
The tool builds a dependence graph of an app and partitions it into different regions based on the graph connection.
Each region is independently classified via machine learning algorithms. The tool provides more insight code structure information than conventional whole-program-based machine learning.


## How to run
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
                        predict a tested apk: 1-malicious 0-benign [0-1]:
                        malicious score

```


## Example command lines:

use region analysis:
```bash
 python main.py -w -a -f -p apks/Geinimi--2e998614b17adbafeb55b5fb9820f63aec5ce8b4.apk 
```

use whole program anlysis:
```bash
 python main.py +w -a -f -p apks/Geinimi--2e998614b17adbafeb55b5fb9820f63aec5ce8b4.apk 
```

get ML parameters:
```python
 python main.py -m
```

## Extra functions (TODO):

Statistics of the apk files: (TODO implement more features )
```python
python Dir_With_APKs
```

## Dependences:

[Sklearn](http://scikit-learn.org/stable/), [NetworkX](https://networkx.github.io/),
[Androguard](https://github.com/androguard), [Androwarn](https://github.com/maaaaz/androwarn),
[MatplotLib](http://matplotlib.org/)

```bash
Python 2.7.6 (default, Jun 22 2015, 17:58:13) 
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pkg_resources
>>> pkg_resources.get_distribution("networkx").version
'1.9.1'
>>> >>> import sklearn
>>> sklearn.__version__
'0.14.1'
>>> import numpy
>>> numpy.__version__
'1.8.2'
```


## version 0.1.1

If you like this tool, citing the paper "Analysis of Code Heterogeneity for High-Precision Classification of Repackaged Malware." In Proceedings of Mobile Security Technologies (MoST), in conjunction with the IEEE Symposium on Security and Privacy. San Jose, CA. May 2016. is highly appreciated.
