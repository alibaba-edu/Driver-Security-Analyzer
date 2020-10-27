# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
from idaapi import *
require("HelperUtils")
from HelperUtils import *
require("AnalysisUtils")
import AnalysisUtils


class CheckerResults:
    def __init__(self, checker_name, className, startFuncEA, out_file=None):
        self.resultStorageDict = {}
        self.startFuncEA = startFuncEA
        self.checker_name = checker_name
        self.out_file = out_file
        self.className = className

    def putResultAtEA(self, ea, result):
        self.resultStorageDict[ea] = result

    def isEmpty(self):
        return len(self.resultStorageDict) == 0

    def __str__(self):
        outString = ""
        for ea in self.resultStorageDict:
            outString += "{:016X}: {}\n".format(ea, self.resultStorageDict[ea])
        return outString

    def outputResults(self):
        if not self.isEmpty():
            orignalBinaryPath = getOriginalBinaryPath()
            out_str = str(self)
            out_file.write("\n[+] In {}:\n[+] {} Result of {} at {:016X}:\n{}".format(orignalBinaryPath, self.checker_name, getName(self.startFuncEA), self.startFuncEA, out_str))
        

def checker_racedemo_pre(currentEA, funcBasics, varStorages, analysisStatus, **kwargs):
    checkerResults = kwargs["checkerResults"]
    q_ea_and_lockretain = kwargs["q_ea_and_lockretain"]
    isUsingObj = False
    isNullingObj = False
    mnem = GetMnem(currentEA)
    if isCallAtEA(currentEA):
        calledTargets = getTargetsOfCallAtEA(currentEA)
        if isIndirectCallAtEA(currentEA):
            isUsingObj = True
            if None is calledTargets:
                ''' in case we haven't resolve the blr, 
                    we still want to create calledTargets 
                    if it is retain (at off 32) or release (at off 40) 
                '''
                opnd_type = get_operand_type(currentEA, 0)
                if opnd_type == 1:
                    call_reg = GetOpnd(currentEA, 0)
                    varDataTuple = varStorages.memberStorage_fromEntry.getRegInfo(call_reg)
                    if not None is varDataTuple:
                        varDataOpString = varDataTuple[1]
                        varDataOps = varDataOpString.split("_")[:-1]
                        if varDataOps[-1] == "[32":
                            calledTargets = [get_name_ea(0, "__ZNK8OSObject6retainEv")]
                        elif varDataOps[-1] == "[40":
                            calledTargets = [get_name_ea(0, "__ZNK8OSObject7releaseEv")]
                elif opnd_type in [3,4]:
                    baseReg, imm, _ = getBaseRegAndImmOfIndirectMemoryOperand(currentEA, 0)
                    if imm == 32:
                        calledTargets = [get_name_ea(0, "__ZNK8OSObject6retainEv")]
                    elif imm == 40:
                        calledTargets = [get_name_ea(0, "__ZNK8OSObject7releaseEv")]
        if None is calledTargets:
            print "[!] Still unsolved call at {:016X}".format(currentEA)
        else:
            for calledFuncEA in calledTargets:
                calledFuncName = getName(calledFuncEA)
                if None is calledFuncName:
                    continue
                if isFuncNameGate(calledFuncName):
                    q_ea_and_lockretain.append((currentEA, ("gate", varStorages.memberStorage_fromEntry.getRegInfo(convertArgIdxToRegName(0)))))
                elif isFuncNameLock(calledFuncName):
                    q_ea_and_lockretain.append((currentEA, ("lock", varStorages.memberStorage_fromEntry.getRegInfo(convertArgIdxToRegName(0)))))
                elif isFuncNameUnlock(calledFuncName):
                    q_ea_and_lockretain.append((currentEA, ("unlock", varStorages.memberStorage_fromEntry.getRegInfo(convertArgIdxToRegName(0)))))
                elif calledFuncName.endswith("6retainEv"):
                    q_ea_and_lockretain.append((currentEA, ("retain", varStorages.memberStorage_fromEntry.getRegInfo(convertArgIdxToRegName(0)))))
                elif calledFuncName.endswith("7releaseEv"):
                    released_obj = varStorages.memberStorage_fromEntry.getRegInfo(convertArgIdxToRegName(0))
                    # DO NOT PLACE BELOW append HERE
                    check_lock_and_set_results(currentEA, q_ea_and_lockretain, varStorages, checkerResults, released_obj, "release")
                    q_ea_and_lockretain.append((currentEA, ("release", varStorages.memberStorage_fromEntry.getRegInfo(0))))
                elif isUsingObj:
                    inuse_obj = varStorages.memberStorage_fromEntry.getRegInfo(convertArgIdxToRegName(0))
                    check_lock_and_set_results(currentEA, q_ea_and_lockretain, varStorages, checkerResults, inuse_obj, "use")
                    None

    elif isStoreAtEA(currentEA):
        result = getStoreSrcAndDstAtEA(currentEA)
        if not None is result:
            for (storeSrc, storeDst, storeDstImm) in result:
                if None is storeDst:
                    continue
                storeDstMemberInfo = varStorages.memberStorage_fromEntry.getRegInfo(storeDst)
                storeDstTinfo = varStorages.tinfoStorage.getRegInfo(storeDst)
                #print "0x{:016X} storeDstMemberInfo: {} storeDstTinfo: {}".format(currentEA, storeDstMemberInfo, storeDstTinfo)
                if (not None is storeDstMemberInfo) and (not storeDstMemberInfo[0].startswith("retof_")) and (not None is storeDstTinfo):
                    storeDstMemberInfo =(storeDstMemberInfo[0], storeDstMemberInfo[1] + "[{}_".format(storeDstImm))
                    result = getMemberInfoFromHostInfoAndOff(None, storeDstTinfo, storeDstImm)
                    if (None is result) or (None is result[1]):
                        # if the store destination's type is unknown, just skip
                        # this may import false negative
                        continue

                    storeSrcValue = None
                    if not None is storeSrc:
                        if isinstance(storeSrc, (int, long)):
                            storeSrcValue = storeSrc
                        else:
                            storeSrcValueInfo = varStorages.valueStorage.getRegInfo(storeSrc)
                            if (not None is storeSrcValueInfo) and (None is storeSrcValueInfo[0]):
                                storeSrcValue = storeSrcValueInfo[1]
                    if (not None is storeSrcValue) and (storeSrcValue == 0):
                        print "storeSrcValue == 0 at {:016X}".format(currentEA)
                        isNulling = True
                        check_lock_and_set_results(currentEA, q_ea_and_lockretain, varStorages, checkerResults, storeDstMemberInfo, "null")
                        q_ea_and_lockretain.append((currentEA, ("null", storeDstMemberInfo)))
                        


def check_lock_and_set_results(currentEA, q_ea_and_lockretain, varStorages, checkerResults, inuse_obj, obj_checking_type):
    lock_obj_stack = []
    retain_cnt = 0
    is_gated = False
    retain_cnt = 0
    for i in range(0, len(q_ea_and_lockretain)):
        ea_and_lockretain_tuple = q_ea_and_lockretain[i]
        ea = ea_and_lockretain_tuple[0]
        op_type = ea_and_lockretain_tuple[1][0]
        op_obj = ea_and_lockretain_tuple[1][1]
        if op_type == "gate":
            is_gated = True
            break
        elif op_type == "lock":
            lock_obj_stack.append(op_obj)
        elif op_type == "unlock":
            if len(lock_obj_stack) == 0:
                print "[?] Missed lock for unlock at {:016X}".format(ea)
            else:
                if (not None is lock_obj_stack[-1]) and (not None is op_obj) and (lock_obj_stack[-1] == op_obj):
                    lock_obj_stack.pop(-1)
                else:
                    checkerResults.putResultAtEA(ea, "Incorrect lock/unlock pair: {} and {}".format(lock_obj_stack[-1], op_obj))
        elif op_type == "retain" and op_obj == inuse_obj:
            retain_cnt += 1
        elif op_type == "release" and op_obj == inuse_obj:
            retain_cnt -= 1
    #print "{} {:016X} {}".format(obj_checking_type, currentEA, inuse_obj)
    if isObjMemberInfoPotentialVulnerable(inuse_obj):
        if (retain_cnt <= 0) and (not is_gated) and (len(lock_obj_stack) == 0):
            checkerResults.putResultAtEA(currentEA, {"check_type": obj_checking_type, "obj": inuse_obj, "retain_cnt": retain_cnt, "is_inlock": False})
            ''' retof is not reliable, for example IOMemoryDescriptor::withAddressRange '''
            #checkerResults.putResultAtEA(currentEA, "Thread unsafe {} of {}".format(obj_checking_type, inuse_obj))
        elif (retain_cnt <= 0):
            checkerResults.putResultAtEA(currentEA, {"check_type": obj_checking_type, "obj": inuse_obj, "retain_cnt": retain_cnt, "is_inlock": True})

def isObjMemberInfoPotentialVulnerable(objMemberInfo):
    return (not None is objMemberInfo) and (not objMemberInfo[1] == "") and (objMemberInfo[0] == "this")
    #return (not inuse_obj[0].startswith("retof_")) and (not inuse_obj[1] == "") and (inuse_obj[0] == "this")


def getCheckerResultDirPath(resultIdPart =""):
    resultsDirPath = os.path.abspath(os.path.join(os.path.dirname(thisScriptFilePath), "../results"))
    platformPart = ""
    if isBinaryArm64():
        platformPart = "arm64"
    elif isBinaryX86_64():
        platformPart = "x86_64"
    return os.path.join(resultsDirPath, platformPart, resultIdPart)

def getCheckerResultFilePath(checkerName, checkerResultFileName, separateModule=False):
    if not separateModule:
        crDirPath = getCheckerResultDirPath()
        crFileName = "{}_{}".format(checkerName, checkerResultFileName) 
        return os.path.join(crDirPath, crFileName)
    else:
        resultIdPart = "{}_{}".format(checkerName, checkerResultFileName)
        dirPath = getCheckerResultDirPath(resultIdPart)
        if not os.path.isdir(dirPath):
            os.makedirs(dirPath)
        return os.path.join(dirPath, modulename + ".txt")


def getCheckerResultFile(checkerName, resultFileName):
    resultFile = sys.stdout
    if not None is resultFileName:
        resultFilePath = getCheckerResultFilePath(checkerName, resultFileName)
        resultFile = open(resultFilePath, "a")
    return resultFile



#def launchChecker(checkerName, checkerResultFileName, preCheckers, postCheckers, resultHandler, onlyUserClients, **kwargs):
def launchChecker(checkerArgs, kext, **kwargs):
    print "[+] launchChecker {} ".format(checkerArgs.checkerName)
    resultFile = getCheckerResultFile(checkerArgs.checkerName, checkerArgs.checkerResultFileName)

    if checkerArgs.onlyUserClients:
        #foundEntryPoints = findEntryPoints()
        gen = DefinedUserEntries(kext)
    else:
        gen = DefinedFunctions(kext)

    for item in gen:
        if checkerArgs.onlyUserClients:
            className, funcEA, entryType = item
            checkerArgs.entryType = entryType
        else:
            funcEA = item
            deFuncName = getDeFuncNameAtEA(funcEA)
            if deFuncName is None:
                className = ""
            else:
                className = deFuncName[:deFuncName.rfind("::")]

        launchCheckerInFunc(funcEA, className, resultFile, checkerArgs, **kwargs)
        

    if resultFile != sys.stdout:
        resultFile.close()

def launchCheckerInFunc(funcEA, className, resultFile, checkerArgs, **kwargs):
    if None is resultFile:
        resultFile = sys.stdout

    print "\n[+] Launch {} in func {} at {:016X}".format(checkerArgs.checkerName, getName(funcEA), funcEA)

    checkerResults = CheckerResults(checkerArgs.checkerName, className, funcEA, resultFile)
        
    AnalysisUtils.forward_analysis_in_func(funcEA, \
        isPureChecker=True, \
        isInterProc=checkerArgs.isInterProc, \
        crossKEXT = checkerArgs.crossKEXT, \
        preCheckers=checkerArgs.preCheckers, \
        postCheckers=checkerArgs.postCheckers, \
        checkerResults = checkerResults, \
        checkerArgs=checkerArgs, \
        **kwargs)

    if not None is checkerArgs.resultHandler:
        checkerArgs.resultHandler(checkerResults, resultFile)



def checkerRacedemoResultHandler(checkerResults, resultFile):
    orignalBinaryPath = getOriginalBinaryPath()
    outputStrLines = []
    safeReleaseObjToEAMap = {}
    safeUseObjToEAMap = {}
    safeNullObjToEAMap = {}
    unsafeReleaseObjToEAMap = {}
    unsafeUseObjToEAMap = {}
    unsafeNullObjToEAMap = {}
    # !!! Notice: this function collects the unsafe nullify/release !!!
    # !!! You can further decide whether there is a vulnerability according to the collected nullify/release !!!
    for ea in checkerResults.resultStorageDict:
        result = checkerResults.resultStorageDict[ea]
        if isinstance(result, str):
            outputStrLines.append("{:016X}: {}\n".format(ea, result))
            continue
        #print "{:016X} {}".format(ea, result)
        is_inlock = result["is_inlock"]
        check_type = result["check_type"]
        retain_cnt = result["retain_cnt"]
        obj = result["obj"]
        if (not is_inlock):
            if check_type == "use":
                unsafeUseObjToEAMap[obj] = ea
            elif check_type == "release" and (retain_cnt <= 0):
                unsafeReleaseObjToEAMap[obj] = ea
            elif check_type == "null":
                unsafeNullObjToEAMap[obj] = ea
        else:
            if check_type == "use":
                safeUseObjToEAMap[obj] = ea
            elif check_type == "release" and (retain_cnt <= 0):
                safeReleaseObjToEAMap[obj] = ea
            elif check_type == "null":
                safeNullObjToEAMap[obj] = ea

def launchCheckerRacedemo(checkerResultFileName, kext):
    checkerArgs = AnalysisUtils.CheckerArgs(\
        checkerName="checker_racedemo", \
        checkerResultFileName=checkerResultFileName, \
        preCheckers=[checker_racedemo_pre], \
        resultHandler=checkerRacedemoResultHandler, \
        crossKEXT = False, \
        onlyUserClients=True)
    launchChecker(checkerArgs, kext, q_ea_and_lockretain=[])


def launchCheckerAtIndex(checkerIdx, kext=None):
    if checkerIdx >= len(Checkers):
        print "checkerIdx {} out of {}".format(checkerIdx, len(Checkers))
        return
    checker = Checkers[checkerIdx]
    if not None is checker:
        checker_name = checker["name"]
        checker_launcher = checker["launcher"]

        allUCInfos = getAllUCInfos()
        if checker["requireUC"] and len(allUCInfos) == 0:
            print "[!] {} requires accessible userclient, but kext does not have".format(checker_name)
            return
        AnalysisUtils.forward_analysis_intra_defined_funcs(kext)

        print "[+] Launching checker {}".format(checker_name)
        checker_launcher("abc", kext)

def launchAllCheckers(kext=None):
    for checkerIdx in range(0, len(Checkers)):
        launchCheckerAtIndex(checkerIdx, kext)



Checkers = [
        None,
        {"name": "checker_racedemo", "launcher": launchCheckerRacedemo, "requireUC": True},
        ]
