#!/usr/bin/python

# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
idaapi.require("X64Utils")
from macOSUtils import *

idaapi.require("HelperUtils")
from HelperUtils import *

idaapi.require("AnalysisUtils")
import AnalysisUtils

idaapi.require("PolicyChecker")
import PolicyChecker


def markPreparePhases():
    markPhaseDone("importNecessaryHeaders")
    markPhaseDone("preparePredefinedStructNameToIdMap")
    markPhaseDone("parseModInitFuncSeg")
    markPhaseDone("parseVTables")
    markPhaseDone("processAllFuncArgs")

def rebuildDataStructures():
    parseModInitFuncSeg()
    rebuildAllInternalDataWOParseModInitFunc(True)



def analyze_with_checker(checkerIdx, checkerResultFileName=None):
    if not checkPhaseDone("ReadyForChecker"):
        print "[!] Not Suitable For Checker"
        analyze_with_all_checkers()
    else:
        rebuildDataStructures()
    #PolicyChecker.launchAllCheckers()

    PolicyChecker.launchCheckerAtIndex(checkerIdx)


def test_userentries(outputFilePath=None):
    if not containsUserClient():
        return 
    rebuildAllInternalDataWOParseModInitFunc(True)
    AnalysisUtils.forward_analysis_intra_defined_funcs()
    binPath = getOriginalBinaryPath()
    outputFile = None
    if not None is outputFilePath:
        outputFile = open(outputFilePath, "a")
    foundEntryPoints = findEntryPoints()
    if len(foundEntryPoints) == 0:
        if not None is outputFile:
            outputFile.write("\n\n************\nNo Entry Points in {}:\n".format(binPath))
    else:
        if not None is outputFile:
            outputFile.write("\n\n============\nEntry Points in {}:\n".format(binPath) )
        for entryType in foundEntryPoints:
            entries = foundEntryPoints[entryType]
            for entry in entries:
                outputStr = "[{}] 0x{:016X}: {}".format(entryType, entry, getName(entry))
                print outputStr 
                if not None is outputFile:
                    outputFile.write(outputStr + "\n")
    if not None is outputFile:
        outputFile.close()


def importDepsTils():
    deps = batchUtils.getDepsOfKEXT(GetInputFilePath())
    print "[+] deps {}".format(deps)
    for bundleid in deps:
        depI64FilePath = os.path.join(os.path.dirname(idbFilePath), bundleid + ".i64")
        if os.path.isfile(depI64FilePath):
            tilFilePath = os.path.join(os.path.dirname(idbFilePath), "tils", bundleid + ".til")
            #if not os.path.isfile(tilFilePath):
            #    batchUtils.exportTilForI64File(depI64FilePath)
            if os.path.isfile(tilFilePath):
                iDEALoadTilFile(tilFilePath)



def test_indirectcalls(outputFilePath=None, listAll=False):
    #importDepsTils()
    modInitFuncs = getAllModInitFuncs()
    if len(modInitFuncs) == 0:
        return
    parseGOTNames()
    #if not haveSymbol():
    #    return
    commonSeg = getSegByName("__common")
    if not None is commonSeg:
        for ea in Heads(commonSeg.start_ea, commonSeg.end_ea):
            deName = getDeNameAtEA(ea)
            if None is deName:
                continue
            if deName.endswith("::gMetaClass"):
                SetType(ea, deName[:-len("::gMetaClass")] + "::MetaClass")

    parseKernelHeadersAndSetType()

    rebuildAllInternalDataWOParseModInitFunc(True)
    AnalysisUtils.forward_analysis_intra_defined_funcs()
    solvedIndirectCalls, unsolvedIndirectCalls, allIndirectCalls, solveRate = AnalysisUtils.checkResolutionRate()
    result = {"solvedIndirectCalls": {x: list(solvedIndirectCalls[x]) for x in solvedIndirectCalls}, "unsolvedIndirectCalls":list(unsolvedIndirectCalls), "allIndirectCalls": list(allIndirectCalls)}
    if not None is outputFilePath:
        with open(outputFilePath, "w") as f:
            json.dump(result, f)
    print "solved {}, unsolved {}, rate {}".format(len(solvedIndirectCalls), len(unsolvedIndirectCalls), solveRate)
    if listAll:
        print ", ".join(["0x{:X}".format(x) for x in unsolvedIndirectCalls])
    return solvedIndirectCalls, unsolvedIndirectCalls



RESULT_DIRPATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../results")


def test_class_recover_and_output(outputFilePath=None):
    correctClasses, failedClasses, falsePositives, vtSymbolAllClasses, vtSymbolMetaClasses = test_class_recover()
    outputFile = None
    if not None is outputFilePath:
        outputFile = open(outputFilePath, "a")
        outputFile.write("In File {}\n".format(idbFilePath))
        for className in falsePositives:
            outputStr = "[???] {}'s vtable {:016X} does not exist".format(className, className)
            outputFile.write(outputStr + "\n")

        for className in failedClasses:
            outputStr = "[!!!] {}'s vtable not found".format(className)
            outputFile.write(outputStr + "\n")

        for className in correctClasses:
            outputStr = "[+++] {}'s vtable found correct".format(className)
            outputFile.write(outputStr + "\n")

        outputFile.close()

def test_class_recover():
    #if not containsUserClient():
    #    return
    foundVTables, foundClassInhiertance = recoverClass()
    if None is foundVTables:
        return
    
    vtablesBySymbol = getVTablesBySymbol()

    correctClasses = set()
    failedClasses = set()
    falsePositives = set()
    metaClasses = set()

    for className in foundVTables:
        if not className in vtablesBySymbol:
            falsePositives.add(className)


    for className in vtablesBySymbol:
        #if className.endswith("::MetaClass"):
        #    continue
        outputStr = ""
        if className.endswith("::MetaClass"):
            metaClasses.add(className)
        if not className in foundVTables:
            failedClasses.add(className)
        elif vtablesBySymbol[className] + 0x10 != foundVTables[className]:
            failedClasses.add(className)
        else:
            correctClasses.add(className)

    return correctClasses, failedClasses, falsePositives, vtablesBySymbol.keys(), metaClasses

kernelClassNames = ["OSObject", "IOService", "IOUserClient", "OSMetaClass"]

def importKernelKnowledge(isKernel):
    importNecessaryHeaders(isKernel)
    parseGOTNames()

isKernel = False

def analyze_stage0():
    ''' preparations, e.g., import kernel knowledge '''
    global isKernel
    isKernel = isX64BinaryKernel()
    importKernelKnowledge(isKernel)

def analyze_stage1():
    ''' recover classes, either by parsing mod_init_func seg or load existing information '''
    global isKernel
    parseModInitFuncSeg()
    phase = "parseVTables"
    if not checkPhaseDone(phase):
        parseVTables()
        markPhaseDone(phase)
    else:
        rebuildAllInternalDataWOParseModInitFunc(True)

    ''' Useless recover class to calculate performance '''
    foundVTables, foundClassInhiertance = recoverClass()

    if isKernel:
        changeVTSAbstractFuncNamesForAll()

def analyze_stage2():
    ''' find userclients and user-entries (Type-I and Type-II) '''
    ucinfos = getAllUCInfos()

def analyze_stage3():
    ''' solve variable types '''
    parseKernelHeadersAndSetType()

    setTypesForGlobalObjs()

    wait_for_analysis_to_finish()
    processAllFuncArgs()
    wait_for_analysis_to_finish()


def analyze_stage4():
    ''' resolve indirect calls '''
    global isKernel
    if not isKernel:
        AnalysisUtils.forward_analysis_intra_defined_funcs()
        AnalysisUtils.forward_analysis_intra_defined_funcs()
    keepAllConsistency()

def analyze_stage5():
    PolicyChecker.launchAllCheckers()

analyze_stages_macos = [
    (analyze_stage0, "s0_prepare"),
    (analyze_stage1, "s1_recoverclass"),
    (analyze_stage2, "s2_finduserclients"),
    (analyze_stage3, "s3_identifyobjs"),
    (analyze_stage4, "s4_resolvcalls"),
    (analyze_stage5, "s5_checkers"),
        ]

def analyze_with_all_checkers():
    collect = getResultDBCollect()
    qret = collect.find_one({"kext": {"$eq": modulename}})
    if qret:
        return
    analysis_stages_go(analyze_stages_macos, None)
    markPhaseDone("ReadyForChecker")


def test_class_recover_and_export():
    if not check_mod_init_segs_have_metaclass_init_funcs():
        return
    collect = getResultDBCollect()
    correctClasses, failedClasses, falsePositives, vtSymbolAllClasses, vtSymbolMetaClasses = test_class_recover()
    result_record = {}
    result_record["correctClasses"] = len(correctClasses)
    result_record["failedClasses"] = len(failedClasses)
    result_record["falsePosClasses"] = len(falsePositives)
    result_record["vtSymbolClasses"] = len(vtSymbolAllClasses)
    result_record["vtSymbolMetaClasses"] = len(vtSymbolMetaClasses)
    noconstructor = set(correctClasses).union(set(falsePositives))
    for funcea in Functions():
        deFuncName = getDeFuncNameAtEA(funcea)
        for classname in set(noconstructor):
            if deFuncName == "{}::{}".format(classname, classname):
                noconstructor.discard(classname)
    result_record["noconstructor"] = len(noconstructor)
    result_record["noconstructor_classes"] = list(noconstructor)
    collect.update_one({"kext": str(modulename)}, {"$set": result_record}, upsert=True)

def recordSegSizes():
    kext = modulename
    kextSize, segSizes = getSizeOfKEXT(kext)

    perf_record = {"size_total": kextSize}

    for segname in segSizes:
        perf_record["segsize_{}".format(segname)] = segSizes[segname]
    collect = getPerfDBCollect()
    collect.update_one({"kext": str(kext)}, {"$set": perf_record}, upsert=True)

    None

def main_internal(checkerIdx, outputFileName=None):
    print "[+] Process %s with args %s"%(get_input_file_path(), ", ".join(idc.ARGV))
    print "[+] checker: {}, outputFileName: {}".format(checkerIdx, outputFileName)
    print "[+] Initialize HexRays Plugin"
    initHexRaysPlugin()

    wait_for_analysis_to_finish()

    if checkerIdx == 9:
        outputFilePath = PolicyChecker.getCheckerResultFilePath("test_class_recover", outputFileName)
        test_class_recover_and_output(outputFilePath)
    elif checkerIdx == 8:
        outputFilePath = PolicyChecker.getCheckerResultFilePath("test_userentries", outputFileName)
        test_userentries(outputFilePath)
    elif checkerIdx == 7:
        outputFilePath = PolicyChecker.getCheckerResultFilePath("test_indirectcalls", outputFileName, True)
        test_indirectcalls(outputFilePath)
    elif checkerIdx == 11:
        recordSegSizes()
    elif checkerIdx == 17:
        test_class_recover_and_export()
    elif checkerIdx == -1:
        analyze_with_all_checkers()
    elif not None is checkerIdx:
        analyze_with_checker(checkerIdx, outputFileName)
        #analyze_with_checker(checkerIdx, checkerResultFileName)

    wait_for_analysis_to_finish()


#isFromCMD = len(idc.ARGV) > 0
import time
import datetime
        
def main():
    startTime = datetime.datetime.now()
    print "start at: {}".format(startTime)
    checkerIdx, checkerResultFileName = getCheckerIdx()
    arg = None
    try:
        main_internal(checkerIdx, checkerResultFileName)
    except Exception as e:
        traceback.print_exc()
        endTime = datetime.datetime.now()
        print "end at: {}".format(endTime)
        exit(-1)

    endTime = datetime.datetime.now()
    print "end at: {}".format(endTime)

    if len(idc.ARGV)>0:
        idc.Exit(0) 



if __name__ == "__main__":
    main()
