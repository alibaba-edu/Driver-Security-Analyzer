#!/usr/bin/python

# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
idaapi.require("Arm64Utils")
from Arm64Utils import *

from HelperUtils import *
import Arm64Preprocessor
import Arm64TypeAnalyzer
import Arm64SymbolFinder
import Arm64ClassAndVTableFinder
import AnalysisUtils
import PolicyChecker

idaapi.require("HelperUtils")
idaapi.require("Arm64Preprocessor")
idaapi.require("Arm64TypeAnalyzer")
idaapi.require("Arm64SymbolFinder")
idaapi.require("Arm64ClassAndVTableFinder")

idaapi.require("AnalysisUtils")
idaapi.require("PolicyChecker")

needsPreparation = True
needsPreprocess = True
needsBuildStructs = False
needsAnalysis = True


def prepareForMergedUnnamedKC():
    ''' 
    preparation for merged kernelcache, e.g., tvOS
    name functions/classes according to exported symbols from iOS/iPadOS kernels
    you can export function/classes from iOS/iPadOS through exportNamedKernelFunctions/exportNamedKernelClasses in Arm64Utils
    '''
    Arm64Preprocessor.untagAllPointers()
    modinitfunc_seg =  get_segm_by_name("__mod_init_func")

    classInfoList = Arm64ClassAndVTableFinder.parseModInitFuncSeg(modinitfunc_seg) 
    importNamedKernelClasses(filepath=os.path.join(dataDirPath, "NamedClasses_iPad7_13_4_1.json"))

    filepath = os.path.join(dataDirPath, "NamedFuncs_iPad7_13_4_1.json")
    importNamedKernelFunctions(filepath)

    Arm64SymbolFinder.namePatternFuncsForKEXT("kernel", True)

    importNecessaryHeaders(True)
    parseKernelHeadersAndSetType()


def prepareForKernel():
    print "[+] prepareForKernel"
    Arm64Preprocessor.fixIDAProMistakes()
    if kernelcache_status.isMerged and not kernelcache_status.isKernelSymbolic:
        return prepareForMergedUnnamedKC()

    importNecessaryHeaders(True)
    #processWithDoxygenXMLs()
    parseKernelHeadersAndSetType()
    ''' parseAllKnownVTablesByName() parse all kernel vtables that already have symbols.
        parseModInitsForKEXT("__DATA_CONST") parse all kernel vtables that do already have symbols
        Both are very important
    '''
    Arm64ClassAndVTableFinder.parseAllKnownVTablesByName() 
    if not None is get_segm_by_name("__DATA_CONST:__mod_init_func"):
        Arm64ClassAndVTableFinder.parseModInitsForKEXT("__DATA_CONST") 
    elif not None is get_segm_by_name("__DATA:__mod_init_func"):
        Arm64ClassAndVTableFinder.parseModInitsForKEXT("__DATA") 


def prepareForAllKEXTs():
    print "[+] prepareForAllKEXTs"
    Arm64Utils.processAllGOTSegs()
    Arm64Preprocessor.renameAllKnownFuncs()

def prepareForKEXT(kextPrefix):
    print "[+] prepareFor {}".format(kextPrefix)
    Arm64Utils.processGOTSegForKEXT(kextPrefix)
    Arm64Preprocessor.renameKnownFuncsForKEXT(kextPrefix)


def prepareForAll():
    print "[+] prepareForAll"
    prepareForKernel()
    prepareForAllKEXTs()
    wait_for_analysis_to_finish() # Necessary ?

def preprocessForAll():
    print "[+] preprocessForAll" 
    processAllVTableConst()
    Arm64Preprocessor.createAllFunctions()
    wait_for_analysis_to_finish() # Necessary ?

def preprocessForKEXT(kextPrefix):
    print "[+] preprocessFor {}".format(kextPrefix) 
    processVTableConstForKEXT(kextPrefix)
    Arm64Preprocessor.createFunctionsForKEXT(kextPrefix)
    wait_for_analysis_to_finish() # Necessary ?

import ImportExportUtils
require("ImportExportUtils")

def measure_parseModInitsForKEXT(kextPrefix):
    s = time.time()
    Arm64ClassAndVTableFinder.parseModInitsForKEXT(kextPrefix)
    e = time.time()
    print "measure_parseModInitsForKEXT:", e-s

def analyze_stage0(kextPrefix=None):
    ''' preparations, e.g., import kernel knowledge '''
    if kextPrefix:
        prepareForKEXT(kextPrefix)
        preprocessForKEXT(kextPrefix)
    else:
        prepareForAll()
        preprocessForAll()

def analyze_stage1(kextPrefix=None):
    ''' recover classes, by parsing mod_init_func seg'''
    if kextPrefix:
        return Arm64ClassAndVTableFinder.parseModInitsForKEXT(kextPrefix)
    else:
        if kernelcache_status.isMerged :
            kmodinit_seg = get_segm_by_name("__kmod_init")
            return Arm64ClassAndVTableFinder.parseModInitFuncSeg(kmodinit_seg) 
        else:
            return Arm64ClassAndVTableFinder.parseModInitsForAll()

def analyze_stage2(kextPrefix=None):
    ''' find userclients and user-entries (Type-I and Type-II) '''
    if kextPrefix:
        Arm64SymbolFinder.findSymbolsForKEXT(kextPrefix)
        getUCInfosForKEXT(kextPrefix)
    else:
        Arm64SymbolFinder.findSymbolsForAll()
        getAllUCInfos()

def analyze_stage3(kextPrefix=None):
    ''' solve variable types '''
    if kextPrefix:
        Arm64TypeAnalyzer.analyzeTypesForKEXT(kextPrefix)
    else:
        Arm64TypeAnalyzer.analyzeTypesForAll()
        None

def analyze_stage4(kextPrefix=None):
    ''' resolve indirect calls '''
    if kextPrefix:
        Arm64TypeAnalyzer.solveVarTypesByPropInKEXT(kextPrefix)
        test_indirectcalls(kextPrefix)
    else:
        Arm64TypeAnalyzer.solveVarTypesByPropInAll()
        test_indirectcalls()

def analyze_stage5(kextPrefix=None):
    ''' launch checker '''
    PolicyChecker.launchAllCheckers(kextPrefix)

analyze_stages_ios = [
    (analyze_stage0, "s0_prepare"),
    (analyze_stage1, "s1_recoverclass"),
    (analyze_stage2, "s2_finduserclients"),
    (analyze_stage3, "s3_identifyobjs"),
    (analyze_stage4, "s4_resolvcalls"),
    (analyze_stage5, "s5_checkers"),
        ]


from pymongo import MongoClient

def perform_checker_on_kext(kextname, checker_id):
    if not kextname in getAllKEXTPrefixes():
        return
    AnalysisUtils.forward_analysis_intra_defined_funcs(kextname)
    PolicyChecker.launchCheckerAtIndex(checker_id, kextname)


def analyze_kext(kextPrefix, stage_ids=[1,2,3,4,5], kernelPrepared=False):
    if None is kextPrefix:
        return
    if not kernelPrepared:
        prepareForKernel()
    stages = []
    for stage_id in stage_ids:
        if stage_id < len(analyze_stages_ios):
            stages.append(analyze_stages_ios[stage_id])
    analysis_stages_go(stages, kextPrefix)

def only_stage4():
    loadNecessaryDataFromPersistNode()
    stage4 = [(analyze_stage4, "s4_resolvcalls")]
    for kextPrefix in getAllKEXTPrefixes():
        analysis_stages_go(stage4, kextPrefix)

def analyze_allkexts_separately(stage_ids=[1,2,3,4,5]):
    prepareForKernel()
    stages = []
    for stage_id in stage_ids:
        if stage_id < len(analyze_stages_ios):
            stages.append(analyze_stages_ios[stage_id])
    for kextPrefix in getAllKEXTPrefixes():
        print "[+] analysis_stages_go on {}".format(kextPrefix)
        analysis_stages_go(stages, kextPrefix)

def analyze_allkexts():
    print "analyze_allkexts begin"
    loadNecessaryDataFromPersistNode()
    analysis_stages_go(analyze_stages_ios, None)


def test_class_recover():
    loadNecessaryDataFromPersistNode()
    classInfoList = []
    failedClasses = set()
    for kextPrefix in getAllKEXTPrefixes():
        ret = analyze_stage1(kextPrefix)
        if not None is ret:
            c,f = ret
            classInfoList.extend(c)
            failedClasses.update(f)
    return classInfoList, failedClasses

def test_indirectcalls(kextPrefix=None, outputFilePath=None, listAll=False):
    loadNecessaryDataFromPersistNode()
    AnalysisUtils.forward_analysis_intra_defined_funcs(kextPrefix)
    solvedIndirectCalls, unsolvedIndirectCalls, allIndirectCalls, solveRate = AnalysisUtils.checkResolutionRate(kextPrefix)
    result = {"solvedIndirectCalls": {x: list(solvedIndirectCalls[x]) for x in solvedIndirectCalls}, "unsolvedIndirectCalls":list(unsolvedIndirectCalls), "allIndirectCalls": allIndirectCalls}
    if not None is outputFilePath:
        with open(outputFilePath, "w") as f:
            json.dump(result, f)
    print "solved {}, unsolved {}, rate {}".format(len(solvedIndirectCalls), len(unsolvedIndirectCalls), solveRate)
    if listAll:
        print ", ".join(["0x{:X}".format(x) for x in sorted(unsolvedIndirectCalls)])

    return solvedIndirectCalls, unsolvedIndirectCalls

    

def test2():
    #processAllGOTSegs()
    processAllVTableConst()
    Arm64Preprocessor.createAllFunctions()
    Arm64Preprocessor.checkIfAllFuncsCreateCorrect()


def main_internal(checkerIdx, checkerResultFileName):
    if not checkerIdx:
        None
    elif checkerIdx == 7:
        test_indirectcalls()
    elif checkerIdx == 9:
        test_class_recover()
    elif checkerIdx == 11:
        only_stage4()
    elif checkerIdx == -1:
        analyze_allkexts()
    elif checkerIdx == -2:
        analyze_allkexts_separately()
    elif checkerIdx == -3:
        analyze_allkexts_separately([1,2,3,4])
    elif checkerIdx == 12:
        kext_and_stages = ask_str("", 0, "kext:1,2,3,4,5")
        if ":" in kext_and_stages:
            split_parts = kext_and_stages.split(":")
            kext = split_parts[0]
            stage_ids_str = split_parts[1]
            stage_ids_str_splits = stage_ids_str.split(",")  
            stage_ids = []
            for i in range(0, len(stage_ids_str_splits)):
                stage_ids.append(int(stage_ids_str_splits[i]))
            analyze_kext(kext, stage_ids, True)
    else:
        kext = ask_str("", 0, "kextname")
        if kext:
            perform_checker_on_kext(kext, checkerIdx)


def main():
    startTime = datetime.datetime.now()
    print "[+] start at: {}".format(startTime)
    checkerIdx, checkerResultFileName = getCheckerIdx()
    arg = None
    try:
        main_internal(checkerIdx, checkerResultFileName)
    except Exception as e:
        traceback.print_exc()
    endTime = datetime.datetime.now()
    print "[+] end at: {}".format(endTime)
    duration = endTime-startTime
    print "[+] duration: {}".format(duration)
    ensureAllNecessaryDataPreparedAndStored()

    if len(idc.ARGV)>0:
        idc.Exit(0) 

if __name__ == "__main__":
    main()
