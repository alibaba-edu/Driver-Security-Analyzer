#!/usr/bin/python

# Copyright (C) 2020 Alibaba Group Holding Limited

import sys
import os
import subprocess
import argparse
import plistlib
from datetime import datetime
import batchUtils
from batchUtils import *
import json
import time


thisScriptFilePath = os.path.realpath(__file__)
macOSScriptsDir = os.path.join(os.path.dirname(thisScriptFilePath), "../x86_64")
processMacKEXTScriptPath = os.path.join(macOSScriptsDir, "X64Analyzer.py")
skipanalysis = False
logDirPath = os.path.join(os.path.dirname(thisScriptFilePath), "../logs/batchLogs")

processedKEXTCnt = 0

def processSingleKEXT(dirPath, outputDirPath, isOverride, logFilePath="log", checker=None):
    kextInfo = getInfoFromKEXT(dirPath, outputDirPath)
    if not None is kextInfo:
        global processedKEXTCnt 
        processedKEXTCnt += 1
        binFilePath = kextInfo[0]
        idbFilePath = kextInfo[1]
        print "[+] Process {} {} to {}".format(processedKEXTCnt, binFilePath, idbFilePath)
        if (not os.path.isfile(idbFilePath + ".i64")) and (not os.path.isfile(idbFilePath + ".id0")):
            # Both id64 and id0 not exist
            processMacKEXTByIDAFromScratch(binFilePath, idbFilePath, logFilePath, processMacKEXTScriptPath if not skipanalysis else None, checker)
        else:
            if (os.path.isfile(idbFilePath + ".id0")) or (isOverride):
                processMacKEXTByIDAWithExistence(idbFilePath, logFilePath, processMacKEXTScriptPath if not skipanalysis else None, checker)
        
        if (not os.path.isfile(idbFilePath + ".i64")) or (os.path.isfile(idbFilePath + ".id0")):
            alertStr = "[!] Failed {}, Log at {} ".format(binFilePath, logFilePath)
            print alertStr
            notifyInSystem("batchProcessMacKEXTS", alertStr)
            raise Exception(alertStr)
        else:
            print "[+] Done {}".format(binFilePath)

def getNowDateStr():
    now = datetime.now()
    return now.strftime("%Y-%m-%d-%H-%M-%S")




def main():
    parser = argparse.ArgumentParser(description = "Batch process kexts to idbs")
    parser.add_argument("-s", dest="single", help="path for a single kext")
    parser.add_argument("-k", dest="dirpath", help="dir path for kexts")
    parser.add_argument("-i", dest="i64dirpath", help="dir path of existing i64")
    parser.add_argument("-o", dest="outputdirpath", help="output dir path of i64 files")
    parser.add_argument("-j", dest="jobs", help="jobs count for batch process")
    parser.add_argument("-O", action='store_true', dest="isoverride", help="whether to override the existent idb file")
    parser.add_argument("-N", action='store_true', dest="skipanalysis", help="just load kext files into ida without analysis")
    parser.add_argument("-c", dest="checker", type=int, help="checker index")
    parser.add_argument("-t", dest="timefile", type=int, help="file to record time")
    args = parser.parse_args()
    kextDirPath = args.dirpath
    outputDirPath = args.outputdirpath
    isOverride = args.isoverride if not None is args.isoverride else False
    singleKEXTPath = args.single
    jobs = args.jobs

    if ((None is singleKEXTPath and None is kextDirPath) or None is outputDirPath) and None is args.i64dirpath:
        print "[!] output is required, either single or dir is required"
        parser.print_usage()
        return

    nowdatetime = getNowDateStr()

    checkerIdx = args.checker

    parsingPath = singleKEXTPath if not None is singleKEXTPath else kextDirPath
    parsingPath = args.i64dirpath if None is parsingPath else parsingPath
    logFileNameSuffix = parsingPath.replace("/", "_") + ".idealog"

    global skipanalysis 
    if args.skipanalysis:
        skipanalysis = True

    checker = None
    if not None is checkerIdx:
        checker = "_".join(["checker", str(checkerIdx), nowdatetime, parsingPath.replace("/", "_")])
        isOverride = True

    logFileName = nowdatetime + logFileNameSuffix
    logFilePath = os.path.join(logDirPath, logFileName)

    if not None is outputDirPath and not os.path.isdir(outputDirPath):
        subprocess.call(["mkdir", "-p", outputDirPath])

    startTime = time.time()

    if not singleKEXTPath is None:
        processSingleKEXT(singleKEXTPath, outputDirPath, isOverride, logFilePath, checker)
    elif not None is kextDirPath:
        for root, dirs, files in os.walk(kextDirPath):
            for dirName in dirs:
                dirPath = os.path.join(root, dirName)
                processSingleKEXT(dirPath, outputDirPath, isOverride, logFilePath,  checker)
    elif not None is args.i64dirpath:
        i64fns = os.listdir(args.i64dirpath)
        for fn in i64fns:
            if fn.endswith(".i64"):
                i64fp = os.path.join(args.i64dirpath, fn)
                global processedKEXTCnt 
                processedKEXTCnt += 1
                print "[+] Process {} {} with checker {}".format(processedKEXTCnt, i64fp, checker)
                processMacKEXTByIDAWithI64(i64fp, logFilePath, processMacKEXTScriptPath if not skipanalysis else None, checker)

    endTime = time.time()
    durTime = endTime-startTime
    timeStr = "startTime: {}, endTime: {}, durTime: {}".format(startTime, endTime, durTime)
    print timeStr
    if not None is args.timefile:
        with open(args.timefile, "w") as fp:
            fp.write(timeStr + "\n")
    
if __name__ == "__main__":
    main()
