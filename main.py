#!/usr/bin/env python
# -*- coding: utf-8 -*-

#ke @ 2016

from FeatureInfo import runFeatureInfo
from AppInfo import runApkInfo
from TrainAndPredict import runTrainAndPredict
import Global
import argparse
import sys


def parse_options():
    parser = argparse.ArgumentParser(description="running analysis...", prefix_chars='-+/')

    parser.add_argument('-w', action="store_false", default=None,
                        help='Turn whole-program-analysis off, use regions for classification')
    parser.add_argument('+w', action="store_true", default=None,
                        help='Turn whole-program-analysis on, ignore code structure')

    parser.add_argument('-a', '--apkinfo', action='store_true',default=False, help='get Application information')
    parser.add_argument('-f', '--feainfo', action='store_true',default=False, help='get Feature information' )
    parser.add_argument('-m', '--mlparameters', action='store_true',default=False,
                        help='show how we choose a machine learning algorithm based on ROC and precision-recall curves.' )

    parser.add_argument('-p', '--predict', type=str, help='predict a tested  apk: 1-malicious 0-benign' )
    args = parser.parse_args()

    return args


if __name__ == "__main__":


   input_file ="apks/com.andromo.dev4168.app4242.apk"
   args = parse_options()

   print (args)

   if args.w :
       Global.WHOLE_PROGRAM_ANALYSIS = True
   else:
       Global.WHOLE_PROGRAM_ANALYSIS = False

   input_file = args.predict
   if args.apkinfo:
        runApkInfo(input_file)
   if args.feainfo:
        runFeatureInfo(input_file)

   runTrainAndPredict(input_file)