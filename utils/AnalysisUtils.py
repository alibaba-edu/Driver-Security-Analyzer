
# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
from idaapi import *
import os
thisScriptFilePath = os.path.realpath(__file__)
utilsPath = os.path.join(os.path.dirname(thisScriptFilePath), "../utils")
import sys
sys.path.insert(0, utilsPath)
idaapi.require("HelperUtils")
from HelperUtils import *
from enum import Enum

class AnalysisStatus():
    def __init__(self, visitedFuncs, isPureChecker, isInterProc, startFuncEA, crossKEXT, enableTriton=False, isDebug=False):
        assert not None is visitedFuncs
        self.visitedFuncs = visitedFuncs
        self.isPureChecker = isPureChecker
        self.isInterProc = isInterProc
        self.startFuncEA = startFuncEA
        self.crossKEXT = crossKEXT
        self.enableTriton = enableTriton
        self.callGraph = {}
        self.isDebug= isDebug

class FuncBasics():
    def __init__(self, func):
        self.func = func
        self.funcStartEA = func.startEA
        self.funcEndEA = func.endEA
        # funcHeadEndEA is the start of function ignoring stack operations
        self.bp_sp_distance, self.funcHeadEndEA = getBPSPDistanceOfFunc(func)
        self.capDisasmInsnsList, self.capDisasmInsnsMap = getCapDisasmInsnsOfFuncAtEA(self.funcStartEA)
        fc = FlowChart(func)
        self.firstBB = fc[0]
        self.funcName = getName(self.funcStartEA)
        self.deFuncName = getDeFuncNameOfName(self.funcName)


class VarInfoStorage():
    def __init__(self, oldStorage=None, isInterProc=False):
        self.is_inter_proc = isInterProc
        if None is oldStorage:
            self.regs = [None for _ in range(32)] 
            #self.regs = {}
            self.local_vars = {}
        else:
            self.regs = list(oldStorage.regs) 
            self.local_vars = dict(oldStorage.local_vars)
            self.is_inter_proc = oldStorage.isInterProc()

    def __str__(self):
        s_reg = ""
        s_local = ""
        for idx in range(0, 32):
            reg = self.regs[idx]
            if reg:
                s_reg += "R" + str(idx) + "->" + str(reg) + ", "
        #for idx in self.regs:
        #    reg = self.regs[idx]
        #    if reg:
        #        s_reg += "R" + str(idx) + "->" + str(reg) + ", "
        for off in self.local_vars:
            s_reg += "SP_" + str(off) + "->" + str(self.local_vars[off]) + ", "

        return "Regs: " + str(s_reg) + "  Local Vars: " + str(s_local)

    def __eq__(self, other):
        if None is other or (not isinstance(other, VarInfoStorage)):
            return False
        for i in range(0, len(self.regs)):
            if (None is self.regs[i] and not None is other.regs[i]) or (None is other.regs[i] and not None is self.regs[i]): 
                return False
            if str(self.regs[i]) != str(other.regs[i]):
                return False

        return self.local_vars == other.local_vars

    def __hash__(self):
        return hash(str(self))

    def isInterProc(self):
        return self.is_inter_proc

    def setRegInfo(self, reg, info):
        #self.regs[reg] = info
        regIdx = convertRegToRegIdx(reg)
        if not None is regIdx and regIdx < 32:
            if isinstance(info, tinfo_t) and "const " in str(info):
                info = getTinfoForTypeStr(str(info).replace("const ", ""))
                
            self.regs[regIdx] = info

    def getRegInfo(self, reg):
        #if reg in self.regs:
        #    return self.regs[reg]
        #else:
        #    return None
        regIdx = convertRegToRegIdx(reg)
        if not None is regIdx and regIdx < 32:
            return self.regs[regIdx]
        return None

    def clearRegInfo(self, reg):
        #if reg in self.regs:
        #    self.regs.pop(reg)
        regIdx = convertRegToRegIdx(reg)
        if not None is regIdx and regIdx < 32:
            self.regs[regIdx] = None

    def clearAllRegInfos(self):
        #self.regs = {}
        self.regs = [None for _ in range(32)] 

    def setLocalVarInfo(self, localVarOff, localVarInfo):
        self.local_vars[localVarOff] = localVarInfo

    def getLocalVarInfo(self, localVarOff):
        if localVarOff in self.local_vars:
            return self.local_vars[localVarOff]
        else:
            return None

    def clearLocalVarInfo(self, localVarOff):
        self.local_vars.pop(localVarOff)

    def clearAllLocalVarInfos(self):
        self.local_vars = {}

    def updateRegInfos(self, refStorage):
        #for i in refStorage.regs:
        for i in range(0, 32):
            refRegInfo = refStorage.getRegInfo(i)
            if not refRegInfo:
                self.setRegInfo(i, refRegInfo)

    def copyInfo(self, src, dst, isSrcReg, isDstReg):
        if isSrcReg:
            if isDstReg:
                self.setRegInfo(dst, self.getRegInfo(src))
            else:
                self.setLocalVarInfo(dst, self.getRegInfo(src))
        else:
            if isDstReg:
                self.setRegInfo(dst, self.getLocalVarInfo(src))
            else:
                self.setLocalVarInfo(dst, self.getLocalVarInfo(src))




class StateStorages():
    '''
        Basically varStorages has three keys as: varStorages.tinfoStorage, varStorages.valueStorage, varStorages.memberStorage_fromEntry
        varStorages.tinfoStorage stores the tinfo of the vars (regs and locals)
        varStorages.valueStorage stores the value (represented as (None, value) tuple) or structure offset (represented as (struct_ptr_tinfo, offset) tuple)
        varStorages.memberStorage_fromEntry stores the relationship between current var and the originally analzed function's arguments, which is inter-procedure
    '''
    def __init__(self, tinfoStorage=None, valueStorage=None, memberStorage_fromEntry=None, extraStorages=None, newTritonContextArgs=None, checkerRecords=None):
        self.tinfoStorage = tinfoStorage
        self.valueStorage = valueStorage
        self.memberStorage_fromEntry = memberStorage_fromEntry
        self.extraStorages = extraStorages
        self.tritonContext = newTritonContext(newTritonContextArgs)
        self.checkerRecords = None

    def __eq__(self, other):
        if None is other or (not isinstance(other, StateStorages)):
            return False
        return (self.tinfoStorage == other.tinfoStorage) and (self.valueStorage == other.valueStorage )
        #return self.tinfoStorage == other.tinfoStorage and self.valueStorage == other.valueStorage and self.memberStorage_fromEntry == other.memberStorage_fromEntry
    def __hash__(self):
        return hash(hash(self.tinfoStorage) + hash(self.valueStorage))

    def clearAllLocalVarInfos(self):
        self.tinfoStorage.clearAllLocalVarInfos()
        self.valueStorage.clearAllLocalVarInfos()
        self.memberStorage_fromEntry.clearAllLocalVarInfos()
        for storage in self.extraStorages.values():
            # Local var info is not propagated for now
            storage.clearAllLocalVarInfos()

    def getAllStorageList(self):
        result = []
        result.append(self.tinfoStorage)
        result.append(self.valueStorage)
        result.append(self.memberStorage_fromEntry)
        for storage in self.extraStorages.values():
            result.append(storage)
        return result

    def createStoragesByCopy(oldStorages):
        ''' For tinfo and value, update. For member, replace '''
        newStorages = StateStorages()
        newStorages.tinfoStorage = VarInfoStorage(oldStorages.tinfoStorage)
        newStorages.valueStorage = VarInfoStorage(oldStorages.valueStorage)
        newStorages.memberStorage_fromEntry = VarInfoStorage(oldStorages.memberStorage_fromEntry)
        copyTritonContext(newStorages.tritonContext, oldStorages.tritonContext)
        newStorages.extraStorages = {}
        for key in oldStorages.extraStorages:
            newStorages.extraStorages[key] = VarInfoStorage(oldStorages.extraStorages[key])
        if not None is oldStorages.checkerRecords:
            newStorages.checkerRecords = copy.deepcopy(oldStorages.checkerRecords)
        return newStorages

    createStoragesByCopy = staticmethod(createStoragesByCopy)

    def createStoragesForFunc(funcBasics, oldStorages=None):
        tinfoStorage = getTinfoStorageOfFuncArgAtEA(funcBasics.funcStartEA)
        memberStorage_fromEntry = getDataStorageOfFuncArgAtEA(funcBasics.funcStartEA)
        valueStorage = VarInfoStorage()
        if not None is oldStorages:
            ''' For tinfo and value, update. For member, replace '''
            if oldStorages.tinfoStorage.isInterProc():
                tinfoStorage.updateRegInfos(oldStorages.tinfoStorage)
            if oldStorages.valueStorage.isInterProc():
                valueStorage.updateRegInfos(oldStorages.valueStorage)
            if oldStorages.memberStorage_fromEntry.isInterProc():
                memberStorage_fromEntry = VarInfoStorage(oldStorages.memberStorage_fromEntry)

        extraStorages = {}
        if not None is oldStorages:
            for key in oldStorages.extraStorages:
                if oldStorages.extraStorages[key].isInterProc():
                    extraStorages[key] = VarInfoStorage(oldStorages.extraStorages[key])
        newStorages = StateStorages(tinfoStorage, valueStorage, memberStorage_fromEntry, extraStorages)
        newStorages.clearAllLocalVarInfos()
        return newStorages
    createStoragesForFunc = staticmethod(createStoragesForFunc)

import copy

class CopiableObj():
    def copyself(self):
        return copy.deepcopy(self)

def isFuncSuitableForAnalysis(funcStartEA):
    ''' We do not propagate type in funcs like below '''
    deFuncName = getDeFuncNameAtEA(funcStartEA)
    if deFuncName:
        className = deFuncName[:deFuncName.rfind("::")]
        if className in kernelClassNameSet:
            return False
    if isBinaryArm64() and isFuncInKernel(funcStartEA):
        #print "[?] Kern func"
        return False
    segName = get_segm_name(funcStartEA)
    if not segName.endswith("__text"):
        #print "[?] Not text func"
        return False
    funcName = getName(funcStartEA)
    if funcName.startswith("__GLOBAL__") or "_InitFunc_" in funcName or "_TermFunc_" in funcName:
        #print "[?] ModInit or ModTerm func"
        return False
    if not None is deFuncName:
        deFuncNameParts = deFuncName.split("::")
        if len(deFuncNameParts) == 3 and deFuncName[1] == "MetaClass":
            return False
    return True
    # for kernel C functions, no need to propagate
    if len(funcName) < 2:
        return False
    if funcName[0] == "_" and funcName[1] != "_":
        return False
    elif funcName[0] == "_" and funcName[1] == "_" and not deFuncName:
        return False
    elif deFuncName:
        if not "::" in deFuncName:
            return False
        classNameInFuncName = deFuncName[:deFuncName.rfind("::")]
        if classNameInFuncName in kernelClassNameSet or classNameInFuncName.endswith("::MetaClass"):
            return False
        deFuncNameParts = deFuncName.split("::")
        if deFuncNameParts[0] == deFuncNameParts[1] or deFuncNameParts[1][0] == "~":
            return False
    '''
    if kernel.kernelcache_format == kernel.KC_12_MERGED and get_name_ea(0, "assemble_identifier_and_version") != BADADDR:
        # This is a special condition check for symboled iPhone 6 iOS 12 kernelcache
        if not deFuncName:
            return False
        if funcName == "___cxa_pure_virtual":
            return False
    '''
    return True

def handleSpecialVFuncCallDuringProp(callEA, calledFuncEA, varTinfoStorage, varValueStorage, isPureChecker):
    calledFuncName = getName(calledFuncEA)
    if calledFuncName in ["__ZN13IOCommandGate9runActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_", "__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_"]:
        Arg1ValueTuple = varValueStorage.getRegInfo(convertArgIdxToRegName(1))
        #print "runAction {:016X} {}".format(callEA, Arg1ValueTuple)
        if (not None is Arg1ValueTuple) and (None is Arg1ValueTuple[0]):
            gatedFuncEA = Arg1ValueTuple[1]
            callGraphEdgeFound(callEA, gatedFuncEA)
            funcStartEA = get_fchunk_attr(callEA, FUNCATTR_START)
            className = getClassNameOfFuncAtEA(funcStartEA)
            if None is className:
                funcTinfo = getTinfoOfFuncAtEA(funcStartEA)
                firstArgTinfo = funcTinfo.get_nth_arg(0)
                if firstArgTinfo.is_ptr():
                    className = str(firstArgTinfo.get_pointed_object())

            if not None is className:
                gatedFuncName = getName(gatedFuncEA)
                if (not isPureChecker) and (not None is gatedFuncName) and (not gatedFuncName.startswith("__")):
                    arg0Tinfo = varTinfoStorage.getRegInfo(convertArgIdxToRegName(2))
                    arg1Tinfo = varTinfoStorage.getRegInfo(convertArgIdxToRegName(3))
                    arg2Tinfo = varTinfoStorage.getRegInfo(convertArgIdxToRegName(4))
                    arg3Tinfo = varTinfoStorage.getRegInfo(convertArgIdxToRegName(5))
                    arg0Type = "void *" if None is arg0Tinfo else str(arg0Tinfo) 
                    arg1Type = "void *" if None is arg1Tinfo else str(arg1Tinfo) 
                    arg2Type = "void *" if None is arg2Tinfo else str(arg2Tinfo)
                    arg3Type = "void *" if None is arg3Tinfo else str(arg3Tinfo) 
                    gatedFuncName = "{}::GatedFunc_{:08X}".format(className, gatedFuncEA%0x100000000)
                    gatedFuncType = "IOReturn {}({} * this, {}, {}, {}, {})".format(gatedFuncName, className, arg0Type, arg1Type, arg2Type, arg3Type) 
                    setTypeForFuncAtEA(gatedFuncEA, gatedFuncType)
                    setFuncName(gatedFuncEA, gatedFuncName)
                    #print "[+] Action {:016X} of CommandGate::runAction at {:016X} is found".format(gatedFuncEA, callEA)
            else:
                #print "[!] Class is not found for CommandGate::runAction at {:016X}".format(callEA)
                None
        else:
            #print "[?] CommandGate::runAction is not using a func addr at {:016X}".format(callEA)
            None

def findCallTargetsInRegDuringProp(currentEA, varStorages, funcStartEA, isPureChecker):
    calledFuncEA = None
    calledTargets = set()
    calledReg = GetOpnd(currentEA, 0)
    valueTuple = None
    if "[" in calledReg and "]" in calledReg: 
        # This is for x86_64, for example call [rax+0x10], 
        # This is like load, need an extra parse
        baseReg, imm, _ = getBaseRegAndImmOfIndirectMemoryOperand(currentEA, 0)
        baseRegTinfo = varStorages.tinfoStorage.getRegInfo(baseReg)
        #print baseReg, imm, baseRegTinfo, varStorages.tinfoStorage
        if (not None is baseReg) and (not None is baseRegTinfo):
            valueTuple = (baseRegTinfo.get_pointed_object(), imm)
    else:
        valueTuple = varStorages.valueStorage.getRegInfo(calledReg)
    #print "valueTuple at 0x{:016X}: {}".format(currentEA, valueTuple[0])
    if None is valueTuple:
        return calledTargets
    elif type(valueTuple) == tuple:
        #print "Indirect Call @ {:016X} : [{} + {}]".format(currentEA, valueTuple[0], valueTuple[1])
        vtsTinfo = valueTuple[0]
        if None is vtsTinfo:
            calledFuncEA = valueTuple[1]
            #callGraphEdgeFound(currentEA, calledFuncEA, funcStartEA)
            # TODO more complete solution should check whether the funciton is virtual and add children vfuncs to calledTargets
            calledTargets.add(calledFuncEA)
        else:
            vtsOffset = valueTuple[1]
            vtsTypeStr = str(vtsTinfo)
            vtsName = vtsTypeStr.strip()
            if vtsName.startswith("struct "):
                vtsName = vtsName[7:].strip()
            if vtsName.startswith("vtable_") or vtsName.startswith("whole_vtable_"):
                if vtsName.startswith("vtable_"):
                    className = vtsName[7:]
                else:
                    className = vtsName[13:]
                    vtsOffset -= 0x10
                vtsStructId = GetStrucIdByName("vtable_" + className)
                calledFuncEA = None
                isCallingExternalFunc = False
                vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
                if vtableStartEA == BADADDR and (vtsStructId != BADADDR):
                    calledFuncEA = GetMemberId(vtsStructId, vtsOffset)
                    #print "[+] {:016X} resolving indirect call to external vtable {:016X} {:016X} -> {:016X}".format(currentEA, vtsStructId, vtsOffset, calledFuncEA)

                    isCallingExternalFunc = True
                elif vtableStartEA != BADADDR and vtsOffset != BADADDR and vtableStartEA + vtsOffset < vtableEndEA:
                    calledFuncEA = Qword(vtableStartEA + vtsOffset)

                if not None is calledFuncEA:
                    handleSpecialVFuncCallDuringProp(currentEA, calledFuncEA, varStorages.tinfoStorage, varStorages.valueStorage, isPureChecker)
                    #callGraphEdgeFound(currentEA, calledFuncEA, funcStartEA)
                    calledTargets.add(calledFuncEA)
                    if not isCallingExternalFunc:
                        if (not isFuncInKernel(calledFuncEA)) and isFuncVirtual(calledFuncEA):
                            childFuncEASet = getChildFuncEAsForClassAtVTOff(className, vtsOffset)
                            for childFuncEA in childFuncEASet:
                                #callGraphEdgeFound(currentEA, childFuncEA, funcStartEA)
                                calledTargets.add(childFuncEA)
    calledTargets.discard(BADADDR)
    calledTargets.discard(-1)
    calledTargets.discard(0)
    for ea in set(calledTargets):
        if None is getName(ea) :
            calledTargets.discard(ea)
    if len(calledTargets) == 0:
        return None
    else:
        return calledTargets


def processFuncArgByVarTinfos(funcEA, varStorages):
    # This is only useful for iOS
    if not isBinaryArm64():
        return
    funcName = getName(funcEA)
    segName = get_segm_name(funcEA)
    if (not None is funcName) and not (funcName.startswith("__") or isFuncInKernel(funcEA)):
        if segName.endswith("__stubs"):
            targetFuncEA, gotItemEA = getTargetAndGOTOfStubsFuncAtEA_arm64(funcEA)
            processFuncArgByVarTinfos(targetFuncEA, varStorages)
            keepCon_ItemAndGOTItem(targetFuncEA, gotItemEA)
        elif segName.endswith("__text"):
            ''' I ignore function with mangled name and kernel function
                AArch64 uses X0-X7 to pass arguments
                I should consider args passed by sp, but not implemented currently
                I ignore virtual funtion's first argument, since it should be set in processVFuncArgsForClass()
            ''' 
            argTypes = {}
            for regIdx in range(0, 8):
                if isFuncVirtual(funcEA) and regIdx == 0:
                    continue
                tinfo = varStorages.tinfoStorage.getRegInfo(regIdx)
                if not None is tinfo and isTinfoInterested(tinfo):
                    argTypes[regIdx] = tinfo
            if len(argTypes) > 0:
                funcArgsTypesFound(funcEA, argTypes)

TypeCastFuncs = {}
ClassInstFuncs = {}


class IndicatorKind(Enum):
    OSSYMBOL=1
    OSSTRING=2
    CHARSTR=3
    METACLASS=4
    INDNAME=5


class TypeIndicatorInfo:
    def __init__(self, funcName, indicatorArgIdx, indicatorKind, indicatedArgs, isRetIndicated):
        ''' A type indicatorArgIdx can only indicate 1 var type at once '''
        self.indicatorArgIdx = indicatorArgIdx
        self.indicatorKind = indicatorKind
        self.indicatedArgs = indicatedArgs
        self.isRetIndicated = isRetIndicated 
        self.funcName = funcName

    def getIndicatorRegName(self):
        return convertArgIdxToRegName(self.indicatorArgIdx)
        None

class TypeCastFuncInfo(TypeIndicatorInfo):
    #def __init__(self, funcName, indicatorArgIdx, indicatorKind, indicatedArgs, isRetIndicated):
    #    super().__init__(funcName, indicatorArgIdx, indicatorKind, indicatedArgs, isRetIndicated)
    def __str__(self):
        return "Type Cast Func {} indicated by {} of kind {}".format(self.funcName, str(self.indicatorArgIdx), str(self.indicatorKind))

class ClassInstFuncInfo(TypeIndicatorInfo):
    #def __init__(self, funcName, typeIndicatorReg, typeIndicatorKind, indicatedArgs, isRetIndicated):
    #    super().__init__(funcName, indicatorArgIdx, indicatorKind, indicatedArgs, isRetIndicated)
    def __str__(self):
        return "Class Inst Func {} indicated by {} of kind {}".format(self.funcName, str(self.indicatorArgIdx), str(self.indicatorKind))

def initTypeCastFuncs():
    funcName = "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass"
    TypeCastFuncInfo_safeMetaCast = TypeCastFuncInfo(funcName, 1, IndicatorKind.METACLASS, [0], True)
    TypeCastFuncs[funcName] = TypeCastFuncInfo_safeMetaCast
    funcName = "__ZNK15OSMetaClassBase8metaCastEPKc"
    TypeCastFuncInfo_metaCast = TypeCastFuncInfo(funcName, 1, IndicatorKind.CHARSTR, [0], True)
    TypeCastFuncs[funcName] = TypeCastFuncInfo_metaCast

def initClassInstFuncs():
    ''' __ZN11OSMetaClass18allocClassWithNameEPK8OSSymbol is not used in any driver, no need to process it
    funcName = "__ZN11OSMetaClass18allocClassWithNameEPK8OSSymbol"
    ClassInstFuncInfo_allocClassWithNameOSSymbol = ClassInstFuncInfo(funcName, 0, IndicatorKind.OSSYMBOL, [], True)
    ClassInstFuncs[funcName] = ClassInstFuncInfo_allocClassWithNameOSSymbol
    '''
    ''' __ZN11OSMetaClass18allocClassWithNameEPK8OSString is mostly called after getProperty, can not parse
    funcName = "__ZN11OSMetaClass18allocClassWithNameEPK8OSString"
    ClassInstFuncInfo_allocClassWithNameOSString = ClassInstFuncInfo(funcName, 0, IndicatorKind.OSSTRING, [], True)
    ClassInstFuncs[funcName] = ClassInstFuncInfo_allocClassWithNameOSString
    '''
    funcName = "__ZN11OSMetaClass18allocClassWithNameEPKc"
    ClassInstFuncInfo_allocClassWithNameCharStr = ClassInstFuncInfo(funcName, 0, IndicatorKind.CHARSTR, [], True)
    ClassInstFuncs[funcName] = ClassInstFuncInfo_allocClassWithNameCharStr


def getTypeCastFuncs():
    if len(TypeCastFuncs) == 0:
        initTypeCastFuncs()
    return TypeCastFuncs

def getClassInstFuncs():
    if len(ClassInstFuncs) == 0:
        initClassInstFuncs()
    return ClassInstFuncs



def checkIfSpecialTypeCallAtEA(currentEA, varStorages):
    specialTypeCallFuncs = getTypeCastFuncs()
    specialTypeCallFuncs.update(getClassInstFuncs())
    foundTypeCallFuncName = None
    foundFuncInfo = None
    mnem = GetMnem(currentEA)
    if isDirectCallAtEA(currentEA):
        calledFuncEA = GetOperandValue(currentEA, 0)
        calledFuncName = getName(calledFuncEA)
        if None is calledFuncName:
            #print "checkIfSpecialTypeCallAtEA called func {:016X} none at {:016X}".format(calledFuncEA, currentEA)
            return None, None
        for typeCallFuncName in specialTypeCallFuncs:
            if calledFuncName.startswith(typeCallFuncName):
                foundTypeCallFuncName = typeCallFuncName
                foundFuncInfo = specialTypeCallFuncs[foundTypeCallFuncName]
                break
    if not None is foundFuncInfo:
        indicatorKind = foundFuncInfo.indicatorKind
        indicatorReg = foundFuncInfo.getIndicatorRegName()
        indicatedType = None

        if indicatorKind == IndicatorKind.CHARSTR:
            valueTuple = varStorages.valueStorage.getRegInfo(indicatorReg)
            charStrAddr = None
            if None is valueTuple:
                charStrAddr = backwardResolveAtEA(currentEA, indicatorReg)
            else:
                charStrAddr = valueTuple[1]
            if not None is charStrAddr:
                charStr = getStringAtAddr(charStrAddr)
                if not None is charStr:
                    indicatedType = charStr + "*"
        elif indicatorKind == IndicatorKind.METACLASS:
            varTinfo = varStorages.tinfoStorage.getRegInfo(indicatorReg)
            valueTuple = varStorages.valueStorage.getRegInfo(indicatorReg)
            className = None
            if not None is varTinfo:
                varType = str(varTinfo)
                if varType.startswith("struct vtable_") and varType.endswith("::MetaClass *"):
                    className = varType[14:-13]
                else:
                    if varType.startswith("struct "):
                        varType = varType[len("struct "):]
                    if "::MetaClass" in varType:
                        className = varType[:varType.find("::MetaClass")]
                #print varType, className
            else:
                gMetaClassAddr = None
                if None is valueTuple:
                    gMetaClassAddr = backwardResolveAtEA(currentEA, indicatorReg)
                else:
                    gMetaClassAddr = valueTuple[1]

                if not None is gMetaClassAddr:
                    gMetaClassName = getName(gMetaClassAddr)
                    if gMetaClassName.endswith("_0"):
                        gMetaClassName = gMetaClassName[:-2]
                    if not None is gMetaClassName:
                        className = None
                        if gMetaClassName.endswith("10gMetaClassE"):
                            className = getDeNameOfName(gMetaClassName)[:-12]
                        elif gMetaClassName.endswith("9metaClassE"):
                            className = getDeNameOfName(gMetaClassName)[:-11]
            #print "typecast toMeta", "0x{:X}".format(currentEA), className
            if not None is className:
                indicatedType = className + "*"
                #print "MetaClass Indicator at 0x{:016X} {} {} {} {}".format(currentEA, indicatorReg, valueTuple, gMetaClassName, indicatedType)
        elif indicatorKind == IndicatorKind.INDNAME:
            ''' These two are seldomly used and hard to parse. They are always from dynamic source, like getProperty 
            elif indicatorKind == IndicatorKind.OSSTRING:
                None
            elif indicatorKind == IndicatorKind.OSSYMBOL:
                None
                '''
            None
        
        if None is indicatedType:
            # TODO Please do not comment out, it's for test_object check
            #print "[!!!] Unknown indicatedType for SpecialTypeCall at {:016X}".format(currentEA)
            recordFoundObjType(currentEA, foundTypeCallFuncName, None, ObjTypeSrcType.FAILED)
            return None, None
        else:
            # Please do not comment out if you want to calculate object resolving rate !!! 
            #print "[+++] Know indicatedType for SpecialTypeCall at {:016X}".format(currentEA)
            None

        typedRegs = list(foundFuncInfo.indicatedArgs)
        indicatedTinfo = getTinfoForTypeStr(indicatedType)
        recordFoundObjType(currentEA, foundTypeCallFuncName, indicatedTinfo, foundTypeCallFuncName )
        return typedRegs,indicatedTinfo 

    return None, None


def handlePropInCall(currentEA, targetInReg, funcBasics, varStorages, analysisStatus, **kwargs):
    calledTargets = None
    is_ret_tinfo_interested = False
    typedRegs = None
    returnTinfo = None
    ret_is_set = False
    if targetInReg:
        calledTargets = findCallTargetsInRegDuringProp(currentEA, varStorages, funcBasics.funcStartEA, analysisStatus.isPureChecker)
        if not None is calledTargets:
            for calledFuncEA in calledTargets:
                callGraphEdgeFound(currentEA, calledFuncEA, funcBasics.funcStartEA)

        
        #print "handlePropInCall {:016X} {}".format(currentEA, calledTargets)
        if not None is calledTargets and len(calledTargets) > 0:
            #print "Found indirect call targets @ {:016X}: {}".format(currentEA, calledTargets)
            for calledTargetEA in calledTargets:
                returnTinfo = getRetTinfoOfFuncAtEA(calledTargetEA)
                if not None is returnTinfo and isTinfoInterested(returnTinfo):
                    break
    else:
        calledTargetEA = GetOperandValue(currentEA, 0)
        typedRegs, returnTinfo = checkIfSpecialTypeCallAtEA(currentEA, varStorages)

        if None is returnTinfo:
            returnTinfo = getRetTinfoOfFuncAtEA(calledTargetEA)
        #print "returnTinfo at 0x{:016X} {}".format(currentEA, returnTinfo)

        calledTargets = [calledTargetEA]

    if not None is calledTargets:
        if BADADDR in calledTargets or -1 in calledTargets :
            print "BAD find target of call at 0x{:016X} {}".format(currentEA, calledTargets)
            raise Exception
        for calledTargetEA in calledTargets:
            calledFuncName = getName(calledTargetEA)
            if isFuncInKernel(calledTargetEA) and \
                not calledFuncName.startswith("__ZN11OSMetaClass18allocClassWithNameEPKc") and \
                not calledFuncName.startswith("__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass") and \
                not calledFuncName.startswith("__ZNK15OSMetaClassBase8metaCastEPKc"):
                
                kernelret_tinfo = getRetTinfoOfFuncAtEA(calledTargetEA)
                if isTinfoInterested(kernelret_tinfo):
                    recordFoundObjType(currentEA, "kernelret_{}".format(calledFuncName), kernelret_tinfo, ObjTypeSrcType.KERNEL_RET)
            if not analysisStatus.isPureChecker:
                processFuncArgByVarTinfos(calledTargetEA, varStorages)
                # Maybe the return result is not used here, but it may be used in other place, so below is not correct
                #if checkIfX0IsNotReadAfterCapInsnIdx(capInsnIndex+1, capDisasmInsnsOfFunc):
                #    changeRetTypeOfFuncAtAddr(calledTargetEA, "void")

            if not None is calledFuncName and calledFuncName.startswith("__ZN15OSMetaClassBase9_ptmf2ptf"):
                arg1ValueTuple = varStorages.valueStorage.getRegInfo(convertArgIdxToRegName(1))
                #print "{} at {:016X} arg1: {}".format(calledFuncName, currentEA, arg1ValueTuple)
                if not None is arg1ValueTuple:
                    func_ea = arg1ValueTuple[1]
                    varStorages.valueStorage.setRegInfo(0, (None, func_ea))
                    returnTinfo = None
                    ret_is_set = True

            if not None is analysisStatus.visitedFuncs:
                calledFuncName = getName(calledTargetEA)
                if None is calledFuncName and len(calledTargets) == 1:
                    #print calledTargetEA
                    print "None target funcname at 0x{:016X} for call at 0x{:016X} {}".format(calledTargetEA, currentEA, calledTargets)
                    continue
                if analysisStatus.isInterProc and (analysisStatus.isPureChecker or not calledFuncName.startswith("__")):
                    shouldEnter = False
                    if analysisStatus.isPureChecker:
                        # All pure checkers should do inter_proc analysis
                        shouldEnter = True
                    else:
                        #if "isPropTypeInStrippediOS" in kwargs and kwargs["isPropTypeInStrippediOS"]:
                        #   shouldEnter = False

                        for i in range(0, 8):
                            # if there was no tinfo recognized 
                            # no need to interproc analysis
                            if not None is varStorages.tinfoStorage.getRegInfo(convertArgIdxToRegName(i)):
                                shouldEnter = True
                                break
                        if isBinaryArm64():
                            if (not analysisStatus.crossKEXT) and \
                                    (not isInSameKEXT(calledTargetEA, currentEA)):
                                shouldEnter = False

                    if shouldEnter and \
                        is_func(GetFlags(calledTargetEA)) and \
                        getSegName(calledTargetEA) != "UNDEF" and \
                        not isFuncInKernel(calledTargetEA):
                        #print "[+] Call at {:016X} {} should enter {:016X} {}".format(currentEA, funcBasics.funcName, calledTargetEA, calledFuncName)
                        forward_analysis_in_func(calledTargetEA, varStorages, analysisStatus.visitedFuncs, analysisStatus.isPureChecker, analysisStatus.isInterProc, analysisStatus.crossKEXT, **kwargs)

    if not None is returnTinfo and isTinfoInterested(returnTinfo):
        #print returnTinfo

        if not None is typedRegs:
            for reg in typedRegs:
                varStorages.tinfoStorage.setRegInfo(reg, returnTinfo)
                varStorages.valueStorage.clearRegInfo(reg)

        varStorages.tinfoStorage.setRegInfo(0, returnTinfo)
        varStorages.valueStorage.clearRegInfo(0)

        varStorages.memberStorage_fromEntry.setRegInfo(0, ("retof_{:016X}@{:016X}".format(calledTargetEA, currentEA), ""))
    elif not ret_is_set :
        varStorages.tinfoStorage.clearRegInfo(0)
        varStorages.valueStorage.clearRegInfo(0)
        varStorages.memberStorage_fromEntry.setRegInfo(0, ("retof_unsolvedCall@{:016X}".format(currentEA), ""))


def handlePropInAdd(currentEA, src, dst, imm, varStorages, bp_sp_distance):
    isSRCStackReg = isStackReg(src)
    if not isSRCStackReg:
        if imm != -1:
            ''' I can not handle add Rd, Rn, Rx'''
            srcTinfo = varStorages.tinfoStorage.getRegInfo(src)
            if not None is srcTinfo:
                if srcTinfo.is_ptr():
                    if str(srcTinfo).startswith("whole_vtable_") and imm == 0x10:
                        ''' A special case for whole_vtable_ add 0x10 as vtable * '''
                        varStorages.tinfoStorage.setRegInfo(dst, getTinfoForTypeStr("vtable_" + str(srcTinfo)[13:-1] + "*"))
                    else:
                        valueTuple = (srcTinfo, imm)
                        varStorages.valueStorage.setRegInfo(dst, valueTuple)
                else:
                    print "[?] ADD src tinfo {} not ptr @{:016X}".format(str(srcTinfo), currentEA) 
            srcValue = varStorages.valueStorage.getRegInfo(src)
            if not None is srcValue:
                valueTuple = (srcValue[0], srcValue[1] + imm)
                varStorages.valueStorage.setRegInfo(dst, valueTuple)

            srcDataTuple = varStorages.memberStorage_fromEntry.getRegInfo(src)
            if not None is srcDataTuple:
                varStorages.memberStorage_fromEntry.setRegInfo(dst, (srcDataTuple[0], srcDataTuple[1] + "+{}_".format(imm)))
    else:
        sp_off = calculateSPOff(imm, bp_sp_distance, isSRCStackReg=="BP")
        varStorages.valueStorage.setRegInfo(dst, ("SP", sp_off))

def isStackReg(reg):
    regIdx = convertRegToRegIdx(reg)
    if isBinaryArm64():
        if regIdx == 13:
            return "SP"
        elif regIdx == 29:
            return "BP"
    elif isBinaryX86_64():
        if regIdx == 4:
            return "SP"
        elif regIdx == 5:
            return "BP"
    return None


def handlePropForLEADst(adrEA, dst, varStorages):
    if not getSegName(adrEA).endswith("__text"):
        # Do not get tinfo for functions
        adrTinfo = getTinfoAtEA(adrEA)
        if not None is adrTinfo:
            adrPtrTinfo = tinfo_t()
            adrPtrTinfo.create_ptr(adrTinfo)
            varStorages.tinfoStorage.setRegInfo(dst, adrPtrTinfo)
    varStorages.valueStorage.setRegInfo(dst, (None, adrEA))
    varStorages.memberStorage_fromEntry.setRegInfo(dst, ("ea@{:016X}".format(adrEA),""))



def handlePropInLoad(currentEA, src, imm, src_shift, dst, varStorages, bp_sp_distance):
    if None is dst:
        return
    if None is src:
        if imm >= 0:
            srcTinfo = getTinfoAtEA(imm)
            if not None is srcTinfo:
                varStorages.tinfoStorage.setRegInfo(dst, srcTinfo)
        return

    isSRCStackReg = isStackReg(src)

    if not isSRCStackReg:
        # The source is not stack reg
        #if imm != -1:
        if imm >= 0:
            ''' I can not handle add Rd, Rn, Rx'''
            srcTinfo = varStorages.tinfoStorage.getRegInfo(src)
            #print "LDR:", hex(currentEA), src, dst, imm, src_shift, srcTinfo
            memberInfo = getMemberInfoFromHostInfoAndOff(currentEA, srcTinfo, imm)
            if not None is memberInfo:
                #print "[+] handlePropInLoad {:016X}: {}({})+{} ({})->{}".format(currentEA, src, srcTinfo, imm, memberInfo[1], dst)
                #print hex(currentEA), srcTinfo, memberInfo[0], str(memberInfo[1])
                isInVTS = memberInfo[0]
                if not isInVTS:
                    varStorages.tinfoStorage.setRegInfo(dst, memberInfo[1])
                else:
                    varStorages.valueStorage.setRegInfo(dst, (memberInfo[1], imm))
                    varStorages.tinfoStorage.setRegInfo(dst, memberInfo[2])
                    #varStorages.valueStorage.setRegInfo(dst, (None, memberInfo[1]))
            else:
                srcValue = varStorages.valueStorage.getRegInfo(src)
                #print "{:016X} srcTinfo: {} srcValue: {}".format(currentEA, srcTinfo, srcValue)
                if not None is srcValue:
                    originalTinfo = srcValue[0]
                    originalImm = srcValue[1]
                    if not None is originalTinfo:
                        if isinstance(originalTinfo, str) and originalTinfo == "SP":
                            varTinfo = varStorages.tinfoStorage.getLocalVarInfo(originalImm + imm)
                            if not None is varTinfo:
                                varStorages.tinfoStorage.setRegInfo(dst, varTinfo)
                        else:
                            memberInfo = getMemberInfoFromHostInfoAndOff(currentEA, originalTinfo, originalImm + imm)
                            if not None is memberInfo:
                                isInVTS = memberInfo[0]
                                if not isInVTS:
                                    varStorages.tinfoStorage.setRegInfo(dst, memberInfo[1])
                                else:
                                    varStorages.valueStorage.setRegInfo(dst, (memberInfo[1], originalImm + imm))
                                    #varStorages.valueStorage.setRegInfo(dst, (None, memberInfo[1]))
                    else:
                        #if (not type(originalImm) in [int, long]) or (not type(imm) in [int, long]):
                        #    print "originalImm", originalImm, "imm", imm
                        loadEA = originalImm + imm
                        if isEAValid(loadEA):
                            targetEA = Qword(loadEA)
                            #print "{:016X} loadEA:{:016X} targetEA:{:016X} ".format(currentEA, loadEA, targetEA)
                            targetTinfo = getTinfoAtEA(targetEA)
                            if None is targetTinfo:
                                loadEATinfo = getTinfoAtEA(loadEA)
                                if not None is loadEATinfo and loadEATinfo.is_struct():
                                    firstMemType = getMemberTypeAtOff(str(loadEATinfo), 0)
                                    if not None is firstMemType:
                                        targetTinfo = getTinfoForTypeStr(firstMemType)

                            varStorages.valueStorage.setRegInfo(dst, (None, targetEA))
                            if not None is targetTinfo:
                                varStorages.tinfoStorage.setRegInfo(dst, targetTinfo)

            srcDataTuple = varStorages.memberStorage_fromEntry.getRegInfo(src)
            if not None is srcDataTuple:
                varStorages.memberStorage_fromEntry.setRegInfo(dst, (srcDataTuple[0], srcDataTuple[1] + "[{}_".format(imm)))

    else:
        sp_off = calculateSPOff(imm, bp_sp_distance, isSRCStackReg=="BP")
        varTinfo = varStorages.tinfoStorage.getLocalVarInfo(sp_off)
        #print "[+] handlePropInLoad {:016X}: {}+{} ({})->{}".format(currentEA, src, imm, varTinfo, dst)
        if not None is varTinfo:
            varStorages.tinfoStorage.setRegInfo(dst, varTinfo)

        srcDataTuple = varStorages.memberStorage_fromEntry.getLocalVarInfo(sp_off)
        if not None is srcDataTuple:
            varStorages.memberStorage_fromEntry.setRegInfo(dst, (srcDataTuple[0], srcDataTuple[1]))

    if src_shift != 0:
        handlePropInAdd(currentEA, src, src, src_shift, varStorages, bp_sp_distance)

def handlePropInStore(currentEA, dst, imm, dst_shift, src, varStorages, bp_sp_distance, isPureChecker):
    #print "[-] handlePropInStore {:016X}: {}".format(currentEA, str(varStorages.tinfoStorage))
    if None is src or None is dst:
        return
    srcTinfo = varStorages.tinfoStorage.getRegInfo(src)
    #print "[-] handlePropInStore {:016X}: {}({})->{}+{}".format(currentEA, src, srcTinfo, dst, imm)
    if not None is srcTinfo:
        srcTypeStr = str(srcTinfo).strip()
        isDSTStackReg = isStackReg(dst)
        if not isDSTStackReg:
            # The dst is not stack reg
            if imm != -1:
                dstTinfo = varStorages.tinfoStorage.getRegInfo(dst)
                ''' I can not handle add Rd, Rn, Rx'''
                if not None is dstTinfo:
                    if (not isPureChecker):
                        setMemberTinfoForStoreDst(currentEA, dstTinfo, imm, srcTinfo)
                    if srcTypeStr.startswith("vtable_") and srcTypeStr[-1] == "*" and imm == 0:
                        varStorages.tinfoStorage.setRegInfo(dst, getTinfoForTypeStr(str(srcTinfo)[7:-1] + "*"))
                else:
                    dstValue = varStorages.valueStorage.getRegInfo(dst)
                    if not None is dstValue:
                        originalTinfo = dstValue[0]
                        originalImm = dstValue[1]
                        if not None is originalTinfo:
                            if isinstance(originalTinfo, str) and originalTinfo == "SP":
                                varStorages.tinfoStorage.setLocalVarInfo(originalImm + imm, srcTinfo)
                            else:
                                if not isPureChecker:
                                    setMemberTinfoForStoreDst(currentEA, originalTinfo, originalImm + imm, srcTinfo)
                                if srcTypeStr.startswith("vtable_") and srcTypeStr[-1] == "*" and originalImm + imm == 0:
                                    varStorages.tinfoStorage.setRegInfo(dst, getTinfoForTypeStr(str(srcTinfo)[7:-1] + "*"))
        else:
            #print "[-] handlePropInStore {:016X}: {}({})->{}+{}".format(currentEA, src, srcTinfo, dst, imm)
            sp_off = calculateSPOff(imm, bp_sp_distance, isDSTStackReg=="BP")
            varStorages.tinfoStorage.setLocalVarInfo(sp_off, srcTinfo)

            srcDataTuple = varStorages.memberStorage_fromEntry.getLocalVarInfo(src)
            if not None is srcDataTuple:
                varStorages.memberStorage_fromEntry.setLocalVarInfo(dst, (srcDataTuple[0], srcDataTuple[1]))
    else:
        ''' Even we known it's in srcValue, we do not know srcValue's type ''' 
        None
    if dst_shift != 0:
        handlePropInAdd(currentEA, dst, dst, dst_shift, varStorages, bp_sp_distance)


def forward_prop_basic_processor_x64(currentEA, funcBasics, varStorages, analysisStatus, **kwargs):
    mnem = GetMnem(currentEA)
    #print "Insn at 0x{:016X}: {}".format(currentEA, mnem)
    is_func_end = False
    if mnem == "mov":
        dst_operand_type = get_operand_type(currentEA, 0)
        src_operand_type = get_operand_type(currentEA, 1)
        dst = GetOpnd(currentEA, 0)
        src = GetOpnd(currentEA, 1)
        if src_operand_type == 1 and dst_operand_type == 1 : # the operands are regs
            for storage in varStorages.getAllStorageList():
                storage.copyInfo(src, dst, True, True)
        elif (dst_operand_type == 4 or dst_operand_type == 3) and src_operand_type == 1 : # src is reg, dst is indirect memory, store
            dstBaseReg, dstImm, _ = getBaseRegAndImmOfIndirectMemoryOperand(currentEA, 0)
            handlePropInStore(currentEA, dstBaseReg, dstImm, 0, src, varStorages, funcBasics.bp_sp_distance, analysisStatus.isPureChecker)
            None
        elif dst_operand_type == 1 and (src_operand_type == 4 or src_operand_type == 3) : # dst is reg, src is indirect memory, load
            srcBaseReg, srcImm, _ = getBaseRegAndImmOfIndirectMemoryOperand(currentEA, 1)
            handlePropInLoad(currentEA, srcBaseReg, srcImm, 0, dst, varStorages, funcBasics.bp_sp_distance)
        elif dst_operand_type == 1 and src_operand_type == 2 : # dst is reg, src is address
            # FIXME Be careful on mov got items
            srcEA = GetOperandValue(currentEA, 1)
            srcTinfo = getTinfoAtEA(srcEA)

            if not None is srcTinfo and srcTinfo.is_struct():
                firstMemType = getMemberTypeAtOff(str(srcTinfo), 0)
                if not None is firstMemType:
                    srcTinfo = getTinfoForTypeStr(firstMemType)
                else:
                    print "[!] firstMemType None {:016X} {:016X} {}".format(currentEA, srcEA, srcTinfo)

            if isTinfoInterested(srcTinfo):
                varStorages.tinfoStorage.setRegInfo(dst, srcTinfo)
            varStorages.valueStorage.setRegInfo(dst, (None, GetOperandValue(currentEA, 1)))
            # TODO no need to handle memberStorage_fromEntry ?
        elif dst_operand_type == 1 and src_operand_type == 5 : # dst is reg, src is imm
            dst = GetOpnd(currentEA, 0)
            srcValue = GetOperandValue(currentEA, 1)
            varStorages.valueStorage.setRegInfo(dst, (None, srcValue))
    elif mnem == "lea":
        dst = GetOpnd(currentEA, 0)
        if get_operand_type(currentEA, 0) == 1:
            if get_operand_type(currentEA, 1) == 2:
                # dst is reg, src is imm or addr
                adrEA = GetOperandValue(currentEA, 1)
                handlePropForLEADst(adrEA, dst, varStorages)
            elif get_operand_type(currentEA, 1) == 4:
                # TODO pointer to a member variable or local variable, do we need to handle?
                None
        else:
            print "[!] Unknown LEA dst at {:016X}".format(currentEA)
        
    elif mnem == "add":
        src = GetOpnd(currentEA, 0)
        dst = src
        immStr = GetOpnd(currentEA, 1)
        imm = isInt(immStr)
        if None is imm:
            imm = -1
        handlePropInAdd(currentEA, src, dst, imm, varStorages, funcBasics.bp_sp_distance)
    elif mnem == "retn" or mnem == "ret":
        is_func_end = True
    elif mnem == "xor":
        opnd0 = GetOpnd(currentEA, 0)
        opnd1 = GetOpnd(currentEA, 1)
        if opnd0 == opnd1:
            varStorages.valueStorage.setRegInfo(opnd0, (None, 0))
    #elif isCallAtEA(currentEA):
    elif mnem == "call" or (mnem == "jmp" and isFuncEnd(currentEA)):
        isIndirectCall = isIndirectCallAtEA(currentEA)
        handlePropInCall(currentEA, isIndirectCall, funcBasics, varStorages, analysisStatus, **kwargs)
        target_op_type = get_operand_type(currentEA, 0)
        if target_op_type == 7 and getName(GetOperandValue(currentEA, 0)).startswith("___stack_chk_fail"):
            is_func_end = True
    return currentEA, is_func_end


def forward_prop_basic_processor_arm64(currentEA, funcBasics, varStorages, analysisStatus, **kwargs):
    is_func_end = False
    mnem = GetMnem_wrapper(currentEA)
    if mnem == "MOV":
        if get_operand_type(currentEA, 0) == 1 and get_operand_type(currentEA, 1) == 1 : # the operands is a reg
            dst = GetOpnd(currentEA, 0)
            src = GetOpnd(currentEA, 1)
            for storage in varStorages.getAllStorageList():
                storage.copyInfo(src, dst, True, True)

            #print "MOV:", hex(currentEA), src, dst, varStorages.tinfoStorage.getRegInfo(src), varStorages.tinfoStorage.getRegInfo(dst)

            #if src in varStorages.tinfoStorage:
            #    varStorages.tinfoStorage[dst] = varStorages.tinfoStorage[src]
            #if src in varStorages.valueStorage:
            #    varStorages.valueStorage[dst] = varStorages.valueStorage[src]

    elif mnem == "BL" or mnem == "BLR" or isDirectCallForJumpAtEA(currentEA) or (mnem == "BR" and isFuncEnd(currentEA)): 
        ''' 
        Maybe we know the BR target in propagation.
        In this case, a known direct call is formed.
        '''
        #if DEBUG:
        #    arg_types_str = "[+] Args Types at 0x%lx: "%(currentEA)
        #    for i in range(0, 8):
        #        arg_types_str += "r%d: "%(i) + str(varStorages.tinfoStorage.getRegInfo(i)) + ", "
        #    print arg_types_str
        handlePropInCall(currentEA, mnem=="BLR" or mnem=="BR", funcBasics, varStorages, analysisStatus, **kwargs)
        if mnem != "BLR" and mnem != "BL":
            is_func_end = True

    elif mnem == "ADD":
        dst = GetOpnd(currentEA, 0)
        src = GetOpnd(currentEA, 1)
        imm = GetOperandValue(currentEA, 2)
        handlePropInAdd(currentEA, src, dst, imm, varStorages, funcBasics.bp_sp_distance)

    elif mnem == "LDR" or mnem == "LDUR":
        dst = GetOpnd(currentEA, 0)
        src, imm, src_shift = getBaseRegAndImmOfLDRAndSTRInsn(currentEA)
        handlePropInLoad(currentEA, src, imm, src_shift, dst, varStorages, funcBasics.bp_sp_distance)

    elif mnem == "LDP":
        dst0 = GetOpnd(currentEA, 0)
        dst1 = GetOpnd(currentEA, 1)
        src, imm, src_shift = getBaseRegAndImmOfLDRAndSTRInsn(currentEA)
        handlePropInLoad(currentEA, src, imm, 0, dst0, varStorages, funcBasics.bp_sp_distance)
        handlePropInLoad(currentEA, src, imm+8, src_shift, dst1, varStorages, funcBasics.bp_sp_distance)

    elif mnem == "STR" or mnem == "STUR":
        src = GetOpnd(currentEA, 0)
        dst, imm, dst_shift = getBaseRegAndImmOfLDRAndSTRInsn(currentEA)
        handlePropInStore(currentEA, dst, imm, dst_shift, src, varStorages, funcBasics.bp_sp_distance, analysisStatus.isPureChecker)

    elif mnem == "STP":
        src0 = GetOpnd(currentEA, 0)
        src1 = GetOpnd(currentEA, 1)
        dst, imm, dst_shift = getBaseRegAndImmOfLDRAndSTRInsn(currentEA)
        handlePropInStore(currentEA, dst, imm, 0, src0, varStorages, funcBasics.bp_sp_distance, analysisStatus.isPureChecker)
        handlePropInStore(currentEA, dst, imm+8, dst_shift, src1, varStorages, funcBasics.bp_sp_distance, analysisStatus.isPureChecker)

    elif mnem == "RET":
        is_func_end = True

    elif mnem == "ADR" or mnem == "ADRP":
        dst = GetOpnd(currentEA, 0)
        adrEA = GetOperandValue(currentEA, 1)
        handlePropForLEADst(adrEA, dst, varStorages)
    '''
    elif mnem == "ADR" or (mnem == "ADRP" and GetMnem_wrapper(currentEA+4) == "ADD"):
        dst = GetOpnd(currentEA, 0)
        has_2_insns = False
        if mnem == "ADR":
            adrEA = GetOperandValue(currentEA, 1)
        else:
            adrEA = GetOperandValue(currentEA, 1) + GetOperandValue(currentEA+4, 2)
            has_2_insns = True
        handlePropForLEADst(adrEA, dst, varStorages)
        if has_2_insns:
            currentEA = next_head(currentEA)
    '''

    return currentEA, is_func_end 


import pyvex
import archinfo

def forward_prop_basic_processor(currentEA, funcBasics, varStorages, analysisStatus, **kwargs):
    if analysisStatus.isDebug:
        dbg_state = check_bpt(currentEA)
        if dbg_state != -1:
            print "[DEBUG] pre 0x{:X} tinfo: {}, value: {}".format(currentEA, varStorages.tinfoStorage, varStorages.valueStorage)
    is_func_end = False
    ea = currentEA

    if isBinaryArm64():
        currentEA, is_func_end = forward_prop_basic_processor_arm64(currentEA, funcBasics, varStorages, analysisStatus, **kwargs)
    elif isBinaryX86_64():
        currentEA, is_func_end = forward_prop_basic_processor_x64(currentEA, funcBasics, varStorages, analysisStatus, **kwargs )

    if analysisStatus.isDebug:
        dbg_state = check_bpt(currentEA)
        if dbg_state != -1:
            print "[DEBUG] post 0x{:X} tinfo: {}, value: {}".format(ea, varStorages.tinfoStorage, varStorages.valueStorage)
    return currentEA, is_func_end

def forward_analysis_in_bb(bb, funcBasics, varStorages, analysisStatus, **kwargs):

    preCheckers = None
    postCheckers = None

    if "preCheckers" in kwargs:
        preCheckers = kwargs["preCheckers"]
    if "postCheckers" in kwargs:
        postCheckers = kwargs["postCheckers"]

    ''' Start iteration '''

    is_func_end = False
    currentEA = bb.startEA
    while currentEA < bb.endEA and currentEA >= bb.startEA:
        tritonInsn = getTritonInsnAtEA(currentEA)

        if not None is preCheckers:
            for checker in preCheckers:
                checker(currentEA, funcBasics, varStorages, analysisStatus, tritonInsn=tritonInsn, **kwargs)

        if currentEA < funcBasics.funcHeadEndEA:
            currentEA = funcBasics.funcHeadEndEA
            continue
        if currentEA >= funcBasics.funcEndEA:
            break

        if analysisStatus.enableTriton:
            try:
                varStorages.tritonContext.processing(tritonInsn)
            except Exception as e:
                print "[!] TritonContext Processing {} Failed at {:016X}".format(tritonInsn, currentEA)

        capDisasmInsn = None
        capInsnIndex = -1
        if not None is funcBasics.capDisasmInsnsMap and currentEA in funcBasics.capDisasmInsnsMap :
            capDisasmInsn = funcBasics.capDisasmInsnsMap[currentEA]
            #print hex(currentEA), capDisasmInsn.op_str, capDisasmInsn.regs_access()
        if not None is capDisasmInsn:
            regs_read, regs_write = capDisasmInsn.regs_access()
            for reg in regs_write:
                if not reg in regs_read:
                    ''' 
                        if the reg is both read and write, like ADD X8, X8, #0x10, we leave it to further analysis 
                        capstone do not think that x0 is written for BL/BLR !!!  
                    '''
                    regName = str(capDisasmInsn.reg_name(reg).upper().strip())
                    #print "clear at {:016X} of {} {}".format(currentEA, regName, str(varStorages.tinfoStorage.getRegInfo(regName)))
                    for storage in varStorages.getAllStorageList(): 
                        storage.clearRegInfo(regName)

                    #print "{:016X} X1 {}".format(currentEA, str(varStorages.tinfoStorage.getRegInfo(regName)))
        #print "{:016X} X1 {}".format(currentEA, str(varStorages.tinfoStorage.getRegInfo("X1")))

        currentEA, is_func_end = forward_prop_basic_processor(currentEA, funcBasics, varStorages, analysisStatus, **kwargs )


        if not None is postCheckers:
            for checker in postCheckers:
                checker(currentEA, funcBasics, varStorages, analysisStatus, tritonInsn=tritonInsn, **kwargs)

        if is_func_end:
            break

        currentEA = next_head(currentEA)
        if currentEA >= bb.endEA:
            break

    if not analysisStatus.isPureChecker:
        if currentEA == funcBasics.funcEndEA or is_func_end:
            retInfo = varStorages.tinfoStorage.getRegInfo(0)
            #print "retInfo {}".format(varStorages.tinfoStorage)
            oldRetInfo = getRetTinfoOfFuncAtEA(funcBasics.funcStartEA)
            if ((None is oldRetInfo) or (oldRetInfo.is_uint64())) and isTinfoInterested(retInfo):
                changeRetTypeOfFuncAtAddr(funcBasics.funcStartEA, str(retInfo))

def getTinfoStorageOfFuncArgAtEA(funcStartEA):
    funcTinfo = getTinfoOfFuncAtEA(funcStartEA)
    tinfoStorage = VarInfoStorage()
    if not None is funcTinfo:
        func_nargs = funcTinfo.get_nargs()
        if func_nargs > 8:
            func_nargs = 8
        for arg_idx in range(0, func_nargs):
            regName = convertArgIdxToRegName(arg_idx)
            arg_tinfo = funcTinfo.get_nth_arg(arg_idx)
            if isTinfoInterested(arg_tinfo):
                tinfoStorage.setRegInfo(regName, arg_tinfo)
    return tinfoStorage

def getDataStorageOfFuncArgAtEA(funcStartEA):
    memberStorage_fromEntry = VarInfoStorage(isInterProc=True)
    funcTinfo = getTinfoOfFuncAtEA(funcStartEA)
    #tinfoStorage = VarInfoStorage()
    if not None is funcTinfo:
        func_nargs = funcTinfo.get_nargs()
        if func_nargs > 8:
            func_nargs = 8
        for arg_idx in range(0, func_nargs):
            arg_tinfo = funcTinfo.get_nth_arg(arg_idx)
            arg_reg_name = convertArgIdxToRegName(arg_idx)
            if arg_idx == 0:
                memberInfo = ("this", "")
            else:
                memberInfo = ("arg{}({})@{:016X}".format(arg_idx, str(arg_tinfo), funcStartEA), "")
            memberStorage_fromEntry.setRegInfo(arg_reg_name, memberInfo)

    return memberStorage_fromEntry

import copy

def forward_analysis_in_bb_recur(bb, funcBasics, oldStorages, visitedBBs=None, analysisStatus=None, **kwargs):
    assert (not None is oldStorages) and (not None is bb) and (not None is funcBasics)
    #print "[+] forward_analysis_in_bb_recur {:016X} {}".format(bb.startEA, visitedBBs)
    if None is visitedBBs:
        visitedBBs = {}
        #visitedBBs = []
    #if bb.startEA in visitedBBs:
    if bb.startEA in visitedBBs:
        if visitedBBs[bb.startEA][0] > 3:
            # Thredshold of while loop
            return
        for ss in visitedBBs[bb.startEA]:
            if ss == oldStorages:
                return
    #if bb.startEA in visitedBBs:
    #    for ss in visitedBBs[bb.startEA]:
    #        if ss != oldStorages:
    #            print "{:016X}\n{}\n{}".format(bb.startEA, ss.tinfoStorage, oldStorages.tinfoStorage)
    #visitedBBs.append(bb.startEA)
    storages = StateStorages.createStoragesByCopy(oldStorages)
    if not bb.startEA in visitedBBs:
        visitedBBs[bb.startEA] = [0]

    visitedBBs[bb.startEA][0] = visitedBBs[bb.startEA][0] + 1
    oldStoragesCopy = StateStorages.createStoragesByCopy(oldStorages)
    visitedBBs[bb.startEA].append(oldStoragesCopy)
    #print hex(bb.startEA), oldStoragesCopy.tinfoStorage
    #print "{:016X} {}".format(bb.startEA, storages)

    #if bb.startEA == 0x471F or bb.startEA == 0x5CB4:
    #    print storages.tinfoStorage, storages.valueStorage
        #print storages.tinfoStorage.getRegInfo(0)
    #if 0x0000000000005CCF > bb.startEA and 0x0000000000005CCF < bb.endEA:
    #    print visitedBBs

    for k in kwargs:
        v = kwargs[k]
        if isinstance(v, VarInfoStorage):
            nv = VarInfoStorage(v)
            kwargs[k] = nv
        elif isinstance(v, CopiableObj):
            kwargs[k] = v.copyself()
        elif isinstance(v, list):
            nv = list(v)
            kwargs[k] = nv
        elif isinstance(v, dict):
            nv = dict(v)
            kwargs[k] = nv

    forward_analysis_in_bb(bb, funcBasics, storages, analysisStatus, **kwargs)
    for bb_succ in set(bb.succs()):
        forward_analysis_in_bb_recur(bb_succ, funcBasics, storages, visitedBBs, analysisStatus, **kwargs)
    #visitedBBs.remove(bb.startEA)


def forward_analysis_in_func(funcStartEA, oldStorages=None, \
        visitedFuncs=None, isPureChecker=False, \
        isInterProc=True, crossKEXT=True, \
        checkerArgs = None, isDebug = False,\
        **kwargs):

    #if DEBUG and not None is oldStorages:
    #    recordStatesAtEA(funcStartEA, oldStorages)

    func = get_func(funcStartEA)
    if (None is func):
        return
    funcStartEA = func.startEA

    isFirstTime = (None is visitedFuncs)
    if not None is visitedFuncs:
        if funcStartEA in visitedFuncs:
            return
    else:
        #visitedFuncs = set()
        visitedFuncs = []

    '''
    if isFirstTime and DEBUG:
        inspect_addrs = ask_str("", None, 'Addrs to inspect states, seperate by ","')
        global DEBUG_ADDRS
        if not None is inspect_addrs:
            addrs = inspect_addrs.split(",")
            for addr in addrs:
                try:
                    addr = int(addr, 16)
                    DEBUG_ADDRS.add(addr)
                except Exception:
                    None
    '''


    #visitedFuncs.add(funcStartEA)
    visitedFuncs.append(funcStartEA)

    if not isFuncSuitableForAnalysis(funcStartEA):
        ''' DO NOT ANALYZE TYPES IN KERNEL FUNCTIONS '''
        #print "[!] Func at {:016X} is not suitable for analysis".format(funcStartEA)
        return
    
    funcBasics = FuncBasics(func)
    
    status = AnalysisStatus(visitedFuncs, isPureChecker, isInterProc, funcStartEA, crossKEXT, isDebug=isDebug)
    storages = StateStorages.createStoragesForFunc(funcBasics, oldStorages)

    if isFirstTime and \
        not None is checkerArgs and \
        not None is checkerArgs.checkerInitHandler:
        checkerArgs.checkerInitHandler(funcBasics, status, storages, checkerArgs)

    #print "[-] Propagate type in func {:016X} {} {}".format(funcBasics.funcStartEA, funcBasics.deFuncName if funcBasics.deFuncName else funcBasics.funcName, visitedFuncs)
    #print "[-] Propagate type in func {:016X} {}".format(funcBasics.funcStartEA, funcBasics.deFuncName if funcBasics.deFuncName else funcBasics.funcName)
    try:
        forward_analysis_in_bb_recur(funcBasics.firstBB, funcBasics, storages, None, status, **kwargs)
    except Exception as e:
        print "[!] Error during forward analysis in 0x{:016X} {}".format(funcStartEA, e.message)
        traceback.print_exc()

    #visitedFuncs.remove(funcStartEA)

def extractCFGPathsInBB_recur(bb, visitedBBs, result):
    None

def extractCFGPathsInFunc(func):
    result = []
    extractCFGPathsInBB_recur(FlowChart(func)[0], result=[])
    None

def collectIndirectCallInFuncAtEA(funcEA):
    IndirectCall2FuncEA = {}
    func = get_func(funcEA)
    for currentEA in Heads(func.startEA, func.endEA):
        if isIndirectCallAtEA(currentEA):
            IndirectCall2FuncEA[currentEA] = func.startEA
    return IndirectCall2FuncEA


def collectIndirectCallsInText(textStart, textEnd, onlyCPP=True):
    incalls = set()
    
    for funcEA in Functions(textStart, textEnd):
        func = get_func(funcEA)
        if None is func:
            continue
        if isBinaryX86_64() and onlyCPP:
            deName = getDeNameAtEA(funcEA)
            if None is deName:
                continue
        for ea in Heads(func.startEA, func.endEA):
            if isIndirectCallAtEA(ea):
                incalls.add(ea)
    return incalls

global kernelcache_status
def collectIndirectCalls(kextPrefix=None):
    #IndirectCall2FuncEA_all = {}
    incalls = set()
    textSegs = []
    if None is kextPrefix:
        if (not isBinaryArm64()) or \
            (isBinaryArm64() and \
            not kernelcache_status.isMerged):

            for segStartEA in Segments():
                segName = getSegName(segStartEA)
                if segName.endswith("__text"):
                    if isBinaryArm64() :
                        if segName in ["__TEXT_EXEC.__text", "__TEXT_EXEC:__text", "__PLK_TEXT_EXEC:__text"] : # kernel seg for iOS
                            continue
                        if len(segName) > len("__text") + 1:
                            kextPrefix = segName[:-len("__text")-1]
                            if None is get_mod_init_seg_of_kext(kextPrefix): 
                                # Do not count for no mod_init kexts
                                continue
                    seg = getseg(segStartEA)
                    textSegs.append((seg.startEA, seg.endEA))
        else:
            kextTextAreas = findKEXTTextAreasForMergedKC()
            for kmodname in kextTextAreas:
                start,end = kextTextAreas[kmodname]
                textSegs.append((start,end))

    else:
        startea, endea = getTextAreaForKEXT(kextPrefix)
        if (startea != BADADDR):
            if (not kernelcache_status.isMerged) and \
                (not None is get_mod_init_seg_of_kext(kextPrefix)):
                textSegs.append((startea, endea))

            elif kernelcache_status.isMerged:
                textSegs.append((startea, endea))

    for (segStart, segEnd) in textSegs:
        #IndirectCall2FuncEA_kext = collectIndirectCallInKextTEXTFuncs(seg)
        #IndirectCall2FuncEA_all.update(IndirectCall2FuncEA_kext)
        incalls.update(collectIndirectCallsInText(segStart, segEnd))
    #return IndirectCall2FuncEA_all
    return incalls


def checkResolutionRate(kextPrefix=None):
    #IndirectCall2FuncEA_all = collectIndirectCalls()
    incalls = collectIndirectCalls(kextPrefix)
    solvedIndirectCalls = {}
    unsolvedIndirectCalls = []
    #for IndirectCallEA in IndirectCall2FuncEA_all:
    for IndirectCallEA in incalls:
        targets = getTargetsOfCallAtEA(IndirectCallEA)
        if not None is targets and len(targets) > 0:
            solvedIndirectCalls[IndirectCallEA] = targets
        else:
            unsolvedIndirectCalls.append(IndirectCallEA)
    #rate = 0 if len(IndirectCall2FuncEA_all) == 0 else len(solvedIndirectCalls)*1.0/len(IndirectCall2FuncEA_all)
    rate = 0 if len(incalls) == 0 else len(solvedIndirectCalls)*1.0/len(incalls)
    return solvedIndirectCalls, unsolvedIndirectCalls, incalls, rate
    #return solvedIndirectCalls, unsolvedIndirectCalls, IndirectCall2FuncEA_all, rate


def forward_analysis_intra_defined_funcs(kextPrefix=None):
    for funcEA in DefinedFunctions(kextPrefix):
        forward_analysis_in_func(funcEA, isInterProc=False)


class CheckerArgs():
    def __init__(self, checkerName="", \
        checkerResultFileName=None, \
        preCheckers=None, postCheckers=None, \
        checkerInitHandler=None, resultHandler=None, \
        onlyUserClients=False, isInterProc=True, \
        checkerRecords=None, entryType=None,
        crossKEXT=True):

        self.preCheckers = preCheckers
        self.postCheckers = postCheckers
        self.checkerInitHandler = checkerInitHandler
        self.resultHandler = resultHandler
        self.checkerName = checkerName
        self.checkerResultFileName = checkerResultFileName
        self.isInterProc = isInterProc
        self.checkerRecords = checkerRecords 
        self.onlyUserClients = onlyUserClients
        self.entryType = entryType
        self.crossKEXT = crossKEXT

