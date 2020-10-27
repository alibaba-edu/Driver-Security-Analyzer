#!/usr/bin/python

# Copyright (C) 2020 Alibaba Group Holding Limited

import sys
import os
import subprocess
import argparse
import plistlib

def isMachOFile(filePath):
    if not None is filePath:
        f = open(filePath, "r")
        header = f.read(4)
        if header in ["\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe"]:
            return True
        #fileOutput = subprocess.check_output(["/usr/bin/file", filePath])
        #if " Mach-O " in fileOutput:
        #    return True
    return False

def getInfoFromInfoPlist(plistFilePath):
    bundleExec = None
    bundleId = None
    plist = plistlib.readPlist(plistFilePath)
    if "CFBundleIdentifier" not in plist:
        print plistFilePath
    return plist["CFBundleExecutable"] if "CFBundleExecutable" in plist else None, plist["CFBundleIdentifier"].replace(" ", "") if "CFBundleIdentifier" in plist else None, plist["OSBundleLibraries"] if "OSBundleLibraries" in plist else {}

def findBinaryByBundleId(kextDirPath):
    None


def getInfoFromKEXT(kextPath, idbDirPath=None):
    #if kextPath.endswith(".kext") or kextPath.endswith(".plugin") or kextPath.endswith("bundle"):
    infoPlistFilePath = os.path.join(kextPath, "Contents/Info.plist")
    if os.path.isfile(infoPlistFilePath):
        CFBundleExecutable, CFBundleIdentifier, OSBundleLibraries = getInfoFromInfoPlist(infoPlistFilePath)
    else:
        return None
    #macOSDirPath = os.path.join(kextPath, "Contents/MacOS/")
    macOSDirPath = kextPath
    for macOSDirPathRoot, binDirs, binFiles in os.walk(macOSDirPath):
        #if len(binFiles) > 1:
        #    print "[!] More than 1 file in %s"%macOSDirPath
        for binFileName in binFiles:
            if binFileName == CFBundleExecutable:
                #binFileName = binFiles[0]
                binFilePath = os.path.join(macOSDirPathRoot, binFileName)
                if isMachOFile(binFilePath):
                    idbFilePathWOSuffix = os.path.join(idbDirPath, CFBundleIdentifier).replace(" ", "\\ ") if not None is idbDirPath else None
                    deps = OSBundleLibraries.keys()
                    for dep in list(deps):
                        if dep.startswith("com.apple.kpi."):
                            deps.remove(dep)
                    binFilePath = binFilePath.replace(" ", "\\ ")
                    return binFilePath, idbFilePathWOSuffix, CFBundleIdentifier, deps
    return None

def traverseKEXTDir(kextDirPath="/System/Library/Extensions", idbDirPath=None, inDepsOrder=False):
    allKexts = {}
    for root, dirs, files in os.walk(kextDirPath):
        for dirName in dirs:
            dirPath = os.path.join(root, dirName)
            kextInfo = getInfoFromKEXT(dirPath, idbDirPath)
            if not None is kextInfo:
                if not inDepsOrder:
                    yield kextInfo
                allKexts[kextInfo[2]] = kextInfo

    allKextBundleIds = set(allKexts.keys())
    kextBundleIds = list(allKexts.keys())
    depsQueue = []
    if inDepsOrder:
        allKextsInDepsOrder = []
        while len(kextBundleIds) > 0:
            bundleid = kextBundleIds.pop(0)
            kextInfo = allKexts[bundleid]
            deps = kextInfo[3]
            
            if len(deps) == 0 or (set(deps) - set(depsQueue)).isdisjoint(allKextBundleIds):
                yield kextInfo
                depsQueue.append(bundleid)
            else:
                kextBundleIds.append(bundleid)

def getDepsOfKEXT(fp):
    dp = os.path.dirname(fp)
    if dp.endswith("/Contents/MacOS"):
        kextPath = dp[:-len("/Contents/MacOS")]
    else:
        kextPath = fp
    kextInfo = getInfoFromKEXT(kextPath)
    if not None is kextInfo:
        return kextInfo[3]

    return [] 
    


def buildDependencyTreeOfKEXTs(kextDirPath):
    dependencyTree = {}
    for root, dirs, files in os.walk(kextDirPath):
        for dirName in dirs:
            dirPath = os.path.join(root, dirName)
            kextInfo = getInfoFromKEXT(dirPath)
            if not None is kextInfo:
                OSBundleLibraries = kextInfo[3]
                CFBundleIdentifier = kextInfo[2]
                if not CFBundleIdentifier in dependencyTree:
                    dependencyTree[CFBundleIdentifier] = []
                dependencyTree[CFBundleIdentifier].extend(OSBundleLibraries.keys())
    return dependencyTree

import os

def notifyInSystem(title, text):
    os.system("""
              osascript -e 'display notification "{}" with title "{}"'
              """.format(text, title))


def demangle(names):
    demangledNames = []
    step = 50
    for i in range(0, len(names), step):
        args = ['c++filt']
        args.extend(names[i:(i+step if i+step<len(names) else len(names))])
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.split("\n")

        # Each line ends with a newline, so the final entry of the split output
        # will always be ''.
        demangledNames.extend(demangled[:-1])
    #print demangledNames
    #print len(demangledNames), len(names)
    assert len(demangledNames) == len(names)
    return demangledNames

#idaCommandPath = "/Applications/IDA Pro 6.8/IDA binaries/idal64"
#idaCommandPath = "/Applications/IDA Pro 7.0/idabin/idat64"
idaCommandPath = "/Applications/IDA\ Pro\ 7.0/idabin/idat64"

def processMacKEXTByIDAFromScratch(kextMachoFilePath, idbFilePath, logFilePath, scriptFilePath, *args):
    #cmd = [idaCommandPath, "-a-", "-P+", "-L"+logFilePath, "-o" + idbFilePath + '.dummy', "-A", "-S" + '"' + scriptFilePath + '"', kextMachoFilePath]
    #subprocess.call(cmd)
    skipAnalysis = (None is scriptFilePath)
    scriptArgsStr = " "
    if not skipAnalysis:
        for arg in args:
            scriptArgsStr += arg + " "
    kextMachoFilePath = kextMachoFilePath.replace(" ", "\ ")
    script = '-S"{}{}"'.format(scriptFilePath, scriptArgsStr) if not skipAnalysis else "-B"
    cmd = '{} -a- -P+ -L{} -o{} -A {} {}'.format(idaCommandPath, logFilePath, idbFilePath + '.dummy',  script, kextMachoFilePath)
    subprocess.call(cmd, shell=True)

def processMacKEXTByIDAWithExistence(idbFilePath, logFilePath, scriptFilePath, *args):
    #cmd = [idaCommandPath, "-a-", "-P+", "-L"+logFilePath, "-A", "-S" + '"' + scriptFilePath  + '"', idbFilePath + '.dummy']
    #subprocess.call(cmd)
    skipAnalysis = (None is scriptFilePath)
    scriptArgsStr = " "
    if not skipAnalysis:
        for arg in args:
            scriptArgsStr += arg + " "
    script = '-S"{}{}"'.format(scriptFilePath, scriptArgsStr) if not skipAnalysis else "-B"
    cmd = '{} -a- -P+ -L{} -A {} {}'.format(idaCommandPath, logFilePath, script, idbFilePath + '.dummy')
    subprocess.call(cmd, shell=True)

def processMacKEXTByIDAWithI64(idbFilePath, logFilePath, scriptFilePath, *args):
    #cmd = [idaCommandPath, "-a-", "-P+", "-L"+logFilePath, "-A", "-S" + '"' + scriptFilePath  + '"', idbFilePath + '.dummy']
    #subprocess.call(cmd)
    skipAnalysis = (None is scriptFilePath)
    scriptArgsStr = " "
    if not skipAnalysis:
        for arg in args:
            print arg
            scriptArgsStr += str(arg) + " "
    logOption = ""
    if not None is logFilePath:
        logOption = "-L{}".format(logFilePath)
    script = '-S\"{}{}\"'.format(scriptFilePath, scriptArgsStr) if not skipAnalysis else "-B"
    print script
    cmd = '{} -a- -P+ {} -A {} {}'.format(idaCommandPath, logOption, script, idbFilePath)
    subprocess.call(cmd, shell=True)
    if (not os.path.isfile(idbFilePath)) or (os.path.isfile(idbFilePath[:-4] + ".id0")):
        alertStr = "[!] Failed {}, Log at {}".format(idbFilePath, logFilePath)
        print alertStr
        notifyInSystem("batchProcessMacKEXTS", alertStr)
        raise Exception(alertStr)
        #exit(1)
    else:
        print "[+] Done {}".format(idbFilePath)

def exportTilForI64File(idbFilePath):
    XNU_6153_EXPORT_HDRS_DIRPATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "exportTil.py")
    processMacKEXTByIDAWithI64(idbFilePath, None, sfp)
