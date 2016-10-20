#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright 2016 [ketian@2016]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
#ke @ 2016

from FeatureInfo import runFeatureInfo
from AppInfo import runApkInfo
from TrainAndPredict import runTrainAndPredict
from GetMLPara import runML
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

    parser.add_argument('-p', '--predict', type=str, help='predict a tested  apk: 1-malicious 0-benign [0-1]: malicious score' )
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


   if args.mlparameters:
       runML()


   input_file = args.predict

   if input_file == None:
       print ("No apk input, system exit")
       sys.exit(0)

   if args.apkinfo:
        runApkInfo(input_file)
   if args.feainfo:
        runFeatureInfo(input_file)


   runTrainAndPredict(input_file)
