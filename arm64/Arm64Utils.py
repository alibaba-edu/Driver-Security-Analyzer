# Copyright (C) 2020 Alibaba Group Holding Limited

from idc import *
from ida_funcs import *

import idaapi
from idaapi import *

import os
thisScriptFilePath = os.path.realpath(__file__)
utilsPath = os.path.join(os.path.dirname(thisScriptFilePath), "../utils")
import sys
sys.path.insert(0, utilsPath)
idaapi.require("HelperUtils")
from HelperUtils import *
import kernel
import subprocess

DEBUG=False


def getCallInstructionListInFunc(func):
    result = []
    if not (None is func):
        funcStartEA = func.startEA
        funcEndEA = func.endEA
        heads = list(Heads(funcStartEA, funcEndEA))
        for insnEA in heads:
            opnd0 = GetOpnd(insnEA, 0)
            opertor = GetMnem(insnEA)
            if opertor == "BL" or opertor == "BLR":
                result.append(insnEA)
    return result

def getPrevCallInstruction(startEA):
    result = None
    func = get_func(startEA)
    if not (None is func):
        funcStartEA = func.startEA
        funcEndEA = func.endEA
        heads = list(funcStartEA, startEA)
        count = len(heads) - 1
        while count >= 0:
            insnEA = heads[count]
            opnd0 = GetOpnd(insnEA, 0)
            opertor = GetMnem(insnEA)
            if opertor == "BL":
                result = insnEA
                break
            count -= 1
    return result

def getNextCallInstruction(startEA):
    result = None
    func = get_func(startEA)
    if not (None is func):
        funcStartEA = func.startEA
        funcEndEA = func.endEA
        heads = list(Heads(startEA, funcEndEA))
        for head in heads:
            insnEA = head
            opnd0 = GetOpnd(insnEA, 0)
            opertor = GetMnem(insnEA)
            if opertor == "BL":
                result = insnEA
                break
    return result


def isStringHex(string):
    try:
        int(string, 16)
        return True
    except:
        return False

def getAllSegsOfText():
    return getAllSegsOf("__text")

def getAllSegsOfGOT():
    return getAllSegsOf("__got")

def getAllSegsOfSTUBS():
    return getAllSegsOf("__stubs")

def getAllSegsOfMODINITFUNC():
    return getAllSegsOf("__mod_init_func")

def getAllSegsOfKMODINIT():
    return getAllSegsOf("__kmod_init")

def getAllSegsOf(name):
    prefixes = getAllKEXTPrefixes()
    segs = []
    if len(prefixes) == 0:
        for segStartEA in Segments():
            segName = get_segm_name(segStartEA)
            if segName == name:
                segs.append(getseg(segStartEA))
    else:
        for pre in prefixes:
            seg = get_segm_by_name(pre + ":" + name)
            if seg:
                segs.append(seg)
    return segs

def getAllKEXTPrefixes(inDepsOrder=True):
    if not inDepsOrder:
        if len(allKextPrefixSet) != 0:
            return list(allKextPrefixSet)
        if not kernelcache_status.isMerged:
            for n in xrange(get_segm_qty()):
                seg = getnseg(n)
                segname = get_segm_name(seg.startEA)
                if ":" in segname:
                    segnamePrefix = segname[:segname.find(":")]
                    if not segnamePrefix.startswith("__"):
                        allKextPrefixSet.add(segnamePrefix)
            return list(allKextPrefixSet)
        else:
            kext_areas = findKEXTTextAreasForMergedKC()
            return kext_areas.keys()
    else:
        global allKextPrefixInDeps
        if len(allKextPrefixInDeps) != 0:
            return allKextPrefixInDeps
        else:
            allKextPrefixInDeps = list(traverseKEXTsByDeps())
            return allKextPrefixInDeps



capstoneMode = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
capstoneMode.detail = True

def guessArgNumberForAllFuncs():
    phase = "guessArgNumberForAllFuncs"
    if checkPhaseDone(phase):
        return
    print "[+] Guess Number of Arguments for All Functions "
    for funcStartEA in Functions():
        funcSegName = get_segm_name(funcStartEA)
        if funcSegName.endswith("__text"):
            guessArgNumberForFuncAtEA_arm64(funcStartEA)
    markPhaseDone(phase)

def setNameAndRelatedGOT(ea, name):
    set_name(ea, name)
    xref = get_first_dref_to(funcEA)
    while xref != None and xref != BADADDR:
        xrefSegName = get_segm_name(xref)
        if xrefSegName.endswith(":__got"):
            xrefSegNum = get_segm_num(xref)
            xref_name = name + "_ptr_" + str(xrefSegNum)
        xref = get_next_dref_to(funcEA, xref)

def processGOTSeg(segStartEA):
    gotSegEA = segStartEA
    gotSegStartEA = gotSegEA
    gotSegEndEA = SegEnd(gotSegEA)
    gotSegName = SegName(gotSegStartEA)
    currentEA = gotSegStartEA
    seg_num = get_segm_num(segStartEA)
    while currentEA < gotSegEndEA:
        value = Qword(currentEA)
        if value != 0:
            op_plain_offset(currentEA, 0, 0)
            keepCon_ItemAndGOTItem(value, currentEA, True, True)
        else:
            None
        currentEA += 0x8

def processGOTSegForKEXT(kextPrefix):
    segs = getSegsByName(kextPrefix+":__got")
    for seg in segs:
        processGOTSeg(seg.startEA)
    wait_for_analysis_to_finish()


def processAllGOTSegs():
    #phase = "processAllGOTSegs"
    #if checkPhaseDone(phase):
    #    return
    print "[+] Process All GOT Segments"
    for segStartEA in Segments():
        segName = get_segm_name(segStartEA)
        if segName.endswith("__got"):
            #print segName
            processGOTSeg(segStartEA)
    #markPhaseDone(phase)
    wait_for_analysis_to_finish()


def findNearestAncestorHaveVT(className):
    parentClassName = className
    parentVTableStartEA = BADADDR
    parentVTableEndEA = BADADDR
    while parentVTableStartEA == BADADDR:
        ''' If we can not find the class's parent's vtable
            We plan to go back the hierarchy chain to find its ancestors
        '''
        parentClassName = getParentClassNameOfClass(parentClassName)
        parentVTableStartEA, parentVTableEndEA = getVTableAddrOfClass(parentClassName)
        if parentClassName is None:
            break

    if parentClassName == className:
        parentClassName = None
        parentVTableStartEA = BADADDR
        parentVTableEndEA = BADADDR
    return parentClassName, parentVTableStartEA, parentVTableEndEA

def findCallExprInCInsnForEA(cinsn, ea):
    if not None is cinsn.creturn:
        return findCallExprInCExprForEA(cinsn.creturn.expr, ea)
    elif not None is cinsn.cif:
        return findCallExprInCExprForEA(cinsn.cif.expr, ea)
    elif not None is cinsn.cfor:
        ret = findCallExprInCExprForEA(cinsn.cfor.expr, ea)
        if not None is ret:
            return ret
        ret = findCallExprInCExprForEA(cinsn.cfor.init, ea)
        if not None is ret:
            return ret
        return findCallExprInCExprForEA(cinsn.cfor.step, ea)
    elif not None is cinsn.cwhile:
        return findCallExprInCExprForEA(cinsn.cwhile.expr, ea)
    elif not None is cinsn.cexpr:
        return findCallExprInCExprForEA(cinsn.cexpr, ea)

    
def findCallExprInCExprForEA(cexpr, ea):
    callexpr = None
    if cexpr.op == 57:
        if cexpr.ea == ea:
            callexpr = cexpr.to_specific_type
            return callexpr
        else:
            if not None is cexpr.x:
                callexpr = findCallExprInCExprForEA(cexpr.x, ea)
                if not None is callexpr:
                    return callexpr
            if not None is cexpr.a:
                args = cexpr.a
                for arg in args:
                    callexpr = findCallExprInCExprForEA(arg, ea)
                    if not None is callexpr:
                        return callexpr
    if not None is cexpr.y:
        callexpr = findCallExprInCExprForEA(cexpr.y, ea)
        if not None is callexpr:
            return callexpr
    if not None is cexpr.x:
        callexpr = findCallExprInCExprForEA(cexpr.x, ea)
        if not None is callexpr:
            return callexpr
    if not None is cexpr.z:
        callexpr = findCallExprInCExprForEA(cexpr.z, ea)
        if not None is callexpr:
            return callexpr
    return callexpr


def getTransferRegsOfLDRAndSTRInsn(insnEA):
    transferReg0 = None
    transferReg1 = None
    mnem = GetMnem(insnEA)
    if mnem.startswith("ST") or mnem.startswith("LD"):
        transferReg0 = GetOpnd(insnEA, 0)
        if get_operand_type(insnEA, 2) != 0:
            transferReg1 = GetOpnd(insnEA, 1)
    return transferReg0, transferReg1

def isInsnLoad(insnEA):
    mnem = GetMnem(insnEA)
    result = None
    if mnem == "LDR" or mnem == "LDUR" or mnem == "LDP":
        srcReg, offset, src_shift = getBaseRegAndImmOfLDRAndSTRInsn(insnEA)
        dstReg0 = GetOpnd(insnEA, 0)
        if mnem == "LDP":
            dstReg1 = GetOpnd(insnEA, 1)
            return (srcReg, offset, dstReg0, dstReg1)
        else:
            return (srcReg, offset, dstReg0, None)
    return result

def isInsnStore(insnEA):
    mnem = GetMnem(insnEA)
    result = None
    if mnem == "STR" or mnem == "STUR" or mnem == "STP":
        dstReg, offset, dst_shift = getBaseRegAndImmOfLDRAndSTRInsn(insnEA)
        srcReg0 = GetOpnd(insnEA, 0)
        if mnem == "STP":
            srcReg1 = GetOpnd(insnEA, 1)
            return (dstReg, offset, dstReg0, dstReg1)
        else:
            return (dstReg, offset, dstReg0, None)
    return result


import xml.dom.minidom
import codecs
import re

ProviderRels = {}

def getProviderRelationship(kext):
    global ProviderRels
    if kext in ProviderRels:
        return ProviderRels[kext]
    kextInfos = getPreLinkInfoDict()
    if not kext in kextInfos:
        return None
    info = kextInfos[kext]
    rel = getProviderRelFromInfo(info)
    if not None is rel:
        ProviderRels[kext] = rel
    return rel



kextInfos = {}

def getPreLinkInfoDict():
    global kextInfos
    if len(kextInfos) != 0:
        return kextInfos
    prelink_info = kernel.parse_prelink_info()
    prelink_info_dict = prelink_info["_PrelinkInfoDictionary"]
    for item in prelink_info_dict:
        if "CFBundleIdentifier" in item:
            bundleid = item["CFBundleIdentifier"]
            if not bundleid.startswith("com.apple.kpi."):
                kextInfos[bundleid] = item
    return kextInfos

def traverseKEXTsByDeps():
    allKextPrefix = getAllKEXTPrefixes(False)
    kextInfos = getPreLinkInfoDict()
    kextBundleIds = kextInfos.keys()
    depsQueue = []
    while len(kextBundleIds) > 0:
        bundleid = kextBundleIds.pop(0)
        if not bundleid in allKextPrefix:
            continue
        kextInfo = kextInfos[bundleid]
        deps = kextInfo.get("OSBundleLibraries", None)
        if not None is deps:
            deps = deps.keys()
            deps = filter(lambda x:(not x.startswith("com.apple.kpi.")), deps)
            if len(deps) == 0 or (set(deps) - set(depsQueue)).isdisjoint(kextBundleIds):
                yield bundleid
                depsQueue.append(bundleid)
            else:
                kextBundleIds.append(bundleid)
        else:
            yield bundleid

    for kextPrefix in allKextPrefix:
        if not kextPrefix in kextInfos:
            yield kextPrefix

    
def processVTableConst(vtStartEA, vtEndEA):
    currentEA = vtStartEA
    while currentEA < vtEndEA:
        value = Qword(currentEA)
        if value != 0:
            op_plain_offset(currentEA, 0, 0)
        currentEA += 8


def processAllVTableConst(afterVTFound=False):
    #phase = "processAllVTableConst"
    #if checkPhaseDone(phase):
    #    return

    if kernelcache_status.isMerged:
        ''' Has been processed by Arm64Preprocessor.untagAllPointers() '''
        return 

    print "[+] Process All Data in VTable Const Segments"
    if not afterVTFound:
        for segStartEA in Segments():
            segName = get_segm_name(segStartEA)
            if kernelcache_status.isMerged:
                if segName.endswith("__const"):
                    processVTableConstSeg(segStartEA)

            elif segName.endswith("__mod_term_func"):
                moduleName = segName[:-len("__mod_term_func")]
                nextSegName = segName
                nextSegStartEA = segStartEA
                while nextSegName.startswith(moduleName):
                    if nextSegName[len(moduleName):] == "__const":
                        #print nextSegName 
                        processVTableConstSeg(nextSegStartEA)
                        break
                    nextSeg = ida_segment.get_next_seg(nextSegStartEA)
                    if None is nextSeg:
                        break
                    nextSegStartEA = nextSeg.startEA
                    nextSegName = get_segm_name(nextSegStartEA)
    else:
        for className in classNameToVTableAddrMap:
            vtStartEA, vtEndEA = classNameToVTableAddrMap[className]
            processVTableConst(vtStartEA, vtEndEA)
    #markPhaseDone(phase)


class RecordListStorage():
    def __init__(self, oldRecordStorage=None):
        if None is oldRecordStorage:
            self.records_list = []
        else:
            self.records_list = list(oldRecordStorage.records_list)
    def enqueue(self, record):
        self.records_list.append(record)
    def dequeue(self):
        return self.records_list.pop(0)
    def push(self, record):
        self.records_list.append(record)
    def pop(self):
        return self.records_list.pop(-1)
    def compute_hash(self):
        result = ""
        for record in self.records_list:
            result += str(record)
        return hash(result)


def findAllNameKnownFuncs():
    result = []
    allTextSegs = getAllSegsOfText()
    for textSeg in allTextSegs():
        for funcEA in Functions(textSeg.startEA, textSeg.endEA):
            funcName = getName(funcEA)
            if funcName.startswith("__"):
                result.append((funcEA, funcName))
    return result

def findAllTypeKnownFuncs():
    result0 = []
    result1 = []
    totalfunc = 0
    allTextSegs = getAllSegsOfText()
    for textSeg in allTextSegs():
        for funcEA in Functions(textSeg.startEA, textSeg.endEA):
            totalfunc += 1
            funcTinfo = getTinfoOfFuncAtEA(funcEA)
            if not None is funcTinfo:
                nargs = funcTinfo.get_nargs()
                for i in range(0, nargs):
                    argTinfo = funcTinfo.get_nth_arg(i)
                    if isTinfoInterested(argTinfo):
                        result0.append(funcEA)
                        break
                rettinfo = funcTinfo.get_rettype()
                if isTinfoInterested(rettinfo):
                    result1.append(funcEA)
    return totalfunc, result0, result1

def findTypedMember():
    result = []
    for className in classNameToModuleNameMap:
        sid = GetStrucIdByName(className)
        struct = get_struc(sid)
        structSize = get_struc_size(sid)
        for offset in range(0, structSize, 8):
            member = ida_struct.get_member(struct, offset)
            mid = member.id
            memberName = ida_struct.get_member_name(member.id)
            if offset == 0:
                continue
            elif offset > 0x8000:
                break
            else:
                member = ida_struct.get_member(struct, offset)
                memberTinfo = tinfo_t()
                ret = ida_struct.get_member_tinfo(memberTinfo, member)
                if isTinfoInterested(memberTinfo):
                    result.append(mid)
    return result


from pymongo import MongoClient
import json

def getInsnInfoForFuncAtEA(funcEA):
    insns = []
    funcName = getName(funcEA)
    func = get_func(funcEA)
    funchash = ""
    for insnEA in Heads(func.startEA, func.endEA):
        mnem = GetMnem(insnEA)
        opnum = get_op_num(insnEA)
        optypes = []
        ops = []

        for i in range(0, opnum):
            optypes.append(get_operand_type(insnEA, i))
            ops.append(GetOpnd(insnEA, i))

        insns.append({"mnem": mnem, "opnum": opnum, "optypes": optypes, "ops": ops})

    exportFuncInfo = {"name": funcName, "size": func.endEA - func.startEA, "insns": insns }
    return exportFuncInfo

def exportNamedKernelFunctions():
    kernelTextSegs = getSegsByName("__TEXT_EXEC:__text")
    if None is kernelTextSegs:
        print "__TEXT_EXEC:__text not found" 
    
    osname = idbFilePath.split(os.sep)[-2].replace(".", "_")
    exportFuncs = []
    for kernelTextSeg in kernelTextSegs:
        for funcEA in Functions(kernelTextSeg.startEA, kernelTextSeg.endEA):
            funcName = getName(funcEA)
            if funcName.startswith("_"):
                exportFuncInfo = getInsnInfoForFuncAtEA(funcEA)
                exportFuncs.append(exportFuncInfo)

    exportFilePath = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../data", "NamedFuncs_{}.json".format(osname))
    with open(exportFilePath, "w") as fp:
        json.dump(exportFuncs, fp)

def compareInsnInfos(currentInfo, exportInfo):
    if currentInfo["size"] != exportInfo["size"] :
        return False
    funcName = exportInfo["name"]
    if "InitFunc" in funcName:
        return False
    insns = currentInfo["insns"]
    exportInsns = exportInfo["insns"]
    if len(insns) != len(exportInsns):
        return False
    diffInsnCnt = 0
    diffInsns = []
    i = 0
    while i < len(insns):
        exportInsn = exportInsns[i]
        insn = insns[i]
        optypes = []
        ops = []
        if (insn["mnem"] == "ADR" and exportInsn["mnem"] == "ADRP") or (insn["mnem"] == "ADRP" and exportInsn["mnem"] == "ADR"): 
            if (insn["ops"][1].startswith("#__") or exportInsn["ops"][1].startswith("#__")) or (insn["ops"][1].startswith("#a") or exportInsn["ops"][1].startswith("#a")):
                op = insn["ops"][1]
                export_op = exportInsn["ops"][1]
                if op[0] == "#":
                    op = op[1:]
                if export_op == "#":
                    export_op = export_op[1:]
                if (not export_op.startswith(op)) and (not op.startswith(export_op)):
                    return False
            i += 2
            continue


        if insn["opnum"] != exportInsn["opnum"] or insn["mnem"] != exportInsn["mnem"]:
            return False
        for j in range(0, insn["opnum"]):
            if insn["optypes"][j] != exportInsn["optypes"][j]:
                #diffInsns.append((insn, exportInsn))
                return False
            if insn["optypes"][j] == 5 and ((insn["ops"][j].startswith("#__") or exportInsn["ops"][j].startswith("#__")) or (insn["ops"][j].startswith("#a") or exportInsn["ops"][j].startswith("#a"))) \
                and insn["ops"][j] != exportInsn["ops"][j]: 
                # For named constant operands, they should be equal
                    return False
        i += 1

    return True
    #unsimilar_rate = len(diffInsns)*1.0/len(insns)
    #return unsimilar_rate, diffInsns

def compareFuncWithExportFuncInfo(funcEA, exportFuncInfo):
    func = get_func(funcEA)
    if None is func:
        return False
    if (func.endEA - func.startEA) != exportFuncInfo["size"] :
        return False
    funcName = exportFuncInfo["name"]
    if "InitFunc" in funcName:
        return False
    insns = list(Heads(func.startEA, func.endEA))
    exportInsns = exportFuncInfo["insns"]
    if len(insns) != len(exportInsns):
        return False
    diffInsnCnt = 0
    for i in range(0, len(insns)):
        exportInsn = exportInsns[i]
        insnEA = insns[i]
        mnem = GetMnem(insnEA)
        opnum = get_op_num(insnEA)
        optypes = []
        ops = []
        if opnum != exportInsn["opnum"] or mnem != exportInsn["mnem"]:
            return False
        for j in range(0, opnum):
            optype = get_operand_type(insnEA, j)
            if optype != exportInsn["optypes"][j]:
                diffInsnCnt += 1
                #return False

    unsimilar_rate = diffInsnCnt*1.0/len(insns)
    return unsimilar_rate == 0 
    #return unsimilar_rate <= 0.1

    #return True

def importNamedKernelFunctions(filepath):
    if not os.path.isfile(filepath):
        return
    exportFuncs = None
    kernel_textseg_start, kernel_textseg_end = findKernelTextAreaForMergedKC()
    with open(filepath, "r") as fp:
        exportFuncs = json.load(fp)
    funcEAs = list(Functions(kernel_textseg_start, kernel_textseg_end))
    func_equals = []
    for func_idx in range(0, len(funcEAs)):
        funcEA = funcEAs[func_idx]
        func = get_func(funcEA)
        insns = list(Heads(func.startEA, func.endEA))
        if len(insns) <= 4:
            # Too small function, could be false
            continue
        currentFuncInfo = getInsnInfoForFuncAtEA(funcEA)
        for i in range(0, len(exportFuncs)):
            exportFuncInfo = exportFuncs[i]
            #if compareFuncWithExportFuncInfo(funcEA, exportFuncInfo):
            if compareInsnInfos(currentFuncInfo, exportFuncInfo):
                funcName = exportFuncInfo["name"]
                print "[+] Found {} at {:016X}".format(funcName, funcEA)
                #setName(funcEA, str(funcName), SN_NOWARN)
                #setName(funcEA, str(funcName), SN_FORCE)
                setNameOverride(funcEA, str(funcName))
                exportFuncs.pop(i)
                #exportFuncs = exportFuncs[i+1:]
                break
    print "[+] Unmapped export funcs:"
    for exportFuncInfo in exportFuncs:
        name = exportFuncInfo["name"]
        if BADADDR == get_name_ea(0, str(name)):
            print name

def exportNamedKernelClasses():
    exportClasses = {}
    classnames = kernelClassNameSet.copy()
    for name in kernelClassNameSet:
        classnames.add(name + "::MetaClass")
    for classname in classnames:
        vtstart, vtend = getVTableAddrOfClass(classname)
        if vtstart == BADADDR:
            continue
        funcnames = []
        for ea in range(vtstart, vtend, 8):
            funcea = Qword(ea)
            funcname = getName(funcea)
            funcnames.append(funcname)
        exportClasses[classname] = funcnames

    osname = idbFilePath.split(os.sep)[-2].replace(".", "_")
    exportFilePath = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../data", "NamedClasses_{}.json".format(osname))
    with open(exportFilePath, "w") as fp:
        json.dump(exportClasses, fp)

    None

def importNamedKernelClasses(filepath):
    if not os.path.isfile(filepath):
        return
    importclasses = None
    with open(filepath, "r") as fp:
        importclasses = json.load(fp)
    for classname in importclasses:
        classname = str(classname)
        vtstart, vtend = getVTableAddrOfClass(classname)
        funcnames = importclasses[classname]
        if (vtend-vtstart)/8 != len(funcnames):
            print "[!] {}'s vt size {} != import vt size {}".format(\
                    classname, (vtend-vtstart)/8, len(funcnames))
            continue
        for ea in range(vtstart, vtend, 8):
            funcea = Qword(ea)
            name = str(funcnames[(ea-vtstart)/8])
            if name.startswith("_"):
                setName(funcea, name, SN_FORCE)
        keepCon_VTAndVTS_ForClass(classname)

def getDuplicateSegNames():
    segname_eas_map = {}
    for segea in Segments():
        segname = getSegName(segea)
        if not segname in segname_eas_map:
            segname_eas_map[segname] = []
        segname_eas_map[segname].append(segea)
    for segname in segname_eas_map:
        if segname.startswith("_"):
            continue
        if (segname.endswith("__const") and \
            len(segname_eas_map[segname]) > 2) or \
            (not segname.endswith("__const") and \
            len(segname_eas_map[segname]) > 1) :

            print "{}: {}".format(segname, ", ".join([hex(ea)[:-1] for ea in segname_eas_map[segname]]))

def findPotentialVTablesForKEXT(kext):
    vtables = []
    for segea in Segments():
        segName = getSegName(segea)
        if segName == kext + ":__const":
            vtables.extend(findPotentialVTablesInSeg(segea))
    return vtables

def findPotentialVTablesInSeg(seg):
    print "findPotentialVTablesInSeg", seg
    if isinstance(seg, (str, unicode)):
        seg = get_segm_by_name(seg)
    elif isinstance(seg, long):
        seg = getseg(seg)
    if None is seg:
        return []
    if not getSegName(seg).endswith("__const"):
        return []
    vtables = []
    invt = False
    vt = []
    for ea in range(seg.startEA, seg.endEA, 8):
        item = Qword(ea)
        if item != 0:
            segname = getSegName(item)
            if (not None is segname) and \
                (segname.endswith("__text") or \
                segname.endswith("__got") or \
                segname.endswith("__stubs")):
                if not invt:
                    vt = []
                    vt.append(ea)
                    invt = True
                else:
                    vt.append(ea)
                continue
        if len(vt) > 1:
            refedByText = False
            xrefs = getXRefsTo(vt[0])
            for xref in xrefs:
                xrefsegname = getSegName(xref)
                if xrefsegname.endswith("__text"):
                    #print "xref: {:016X}".format(xref)
                    refedByText = True
                    break
            if refedByText:
                vtables.append(vt[0])
            vt = []
        invt = False
    return vtables


print "[+] Arm64Utils loaded"
