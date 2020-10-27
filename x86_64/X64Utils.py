# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
from idaapi import *
from idautils import *
from idc import *
import os
thisScriptFilePath = os.path.realpath(__file__)
utilsPath = os.path.join(os.path.dirname(thisScriptFilePath), "../utils")
import sys
sys.path.insert(0, utilsPath)
idaapi.require("HelperUtils")
from HelperUtils import *

idaapi.require("AnalysisUtils")
import AnalysisUtils

idaapi.require("PolicyChecker")
import PolicyChecker


def getFuncTypeByArgList(arglist):
    funcType = "__int64 ("
    if len(arglist) == 0 :
        funcType = funcType + "void"
    elif len(arglist) == 1:
        funcType = funcType + arglist[0]
    else:
        funcType = funcType + arglist[0]
        for i in range(1, len(arglist)):
            funcType = funcType + ", " + arglist[i]
    funcType = funcType + ")"
    return funcType

def parseVTable(vtableStartEA, demangledClassName):
    alreadyExist = False
    vtableEAList = []

    vtableEndEA = vtableStartEA

    vtableStructName = "vtable_" + demangledClassName
    #classStrucName = "class_" + demangledClassName
    classStrucName = demangledClassName

    vtableStructId = GetStrucIdByName(vtableStructName)
    if vtableStructId == BADADDR:
        vtableStructId = AddStrucEx(-1, vtableStructName, 0)

    set_struc_hidden(get_struc(vtableStructId), 1)

    classStrucId = GetStrucIdByName(classStrucName)
    if classStrucId == BADADDR:
        classStrucId = AddStrucEx(-1, classStrucName, 0)
        set_struc_hidden(get_struc(classStrucId), 1)
    if GetStrucSize(classStrucId) == 0:
        AddStrucMember(classStrucId, "vtable", 0, qwrdflag(), -1, 8)
    SetMemberType(classStrucId, 0, qwrdflag(), -1, 1)
    SetOrAddMemberName(classStrucId, 0, "vtable")
        
    vtableStructSize = GetStrucSize(vtableStructId)
    if vtableStructSize > 0:
        alreadyExist = True
        #return

    ret = SetType(GetMemberId(classStrucId, 0), "struct " + vtableStructName + " *")
    #print "SetClassMemberType: " + str(ret)

    classNameToVTableStructIdMap[demangledClassName] = vtableStructId

    while True:
        if Qword(vtableEndEA) == 0:
            vtableEndEA = vtableEndEA - 0x8   
            break
        #print Name(Qword(vtableEndEA))
        funcEA = Qword(vtableEndEA)
        funcName = Name(funcEA) 
        funcFlags = GetFlags(funcEA)
        funcType = GetType(funcEA)
        demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
        memberOffset = vtableEndEA-vtableStartEA

        vtableEAList.append(funcEA)
        virtualFuncEASet.add(funcEA)

        # TODO
        if not alreadyExist:
            # in case two members have the same name, e.g., ___cxa_pure_virtual
            AddStrucMember(vtableStructId, "member" + str(memberOffset/8), memberOffset, qwrdflag(), -1, 8)
            SetOrAddMemberName(vtableStructId, memberOffset, funcName)
        SetMemberComment(vtableStructId, memberOffset, hex(funcEA), 1)
        memberId = GetMemberId(vtableStructId, memberOffset)
        addXref(memberId, funcEA, 1)
        addXref(funcEA, memberId, 1)
        if funcType == None:
            funcType = GuessType(funcEA)
            if funcType == None and demangledFuncName != None:
                nouse, nouse2, arglist = parseFuncProtoWORet(demangledFuncName, True)            
                funcType = getFuncTypeByArgList(arglist)
                #if demangledFuncName != None:
                #    log("Parse Type: " + demangledFuncName)
            
        if funcType != None:
            funcTypeArgStartLoc = funcType.find("(")
            funcPTRType = funcType[:funcTypeArgStartLoc] + "(*)" +  funcType[funcTypeArgStartLoc:]
            SetType(memberId, funcPTRType)

        #print "funcFlags: " + hex(funcFlags), "funcType: " + str(GetType(funcEA)), "funcDemangledName: " + Demangle(funcName, GetLongPrm(INF_LONG_DN)) , "guessType: " + str(GuessType(funcEA)), "memberId: " + hex(GetMemberId(vtableStructId, vtableEndEA-vtableStartEA))
        if GetType(memberId) == None:
            if demangledFuncName != None:
                print("SetType Failed: " + demangledFuncName + " " + funcType if funcType else "")
            else:
                print("SetType Failed: " + funcName + " " + funcType if funcType else "")

        vtableEndEA = vtableEndEA + 0x8 

    classNameToVTableEAListMap[demangledClassName] = vtableEAList

def getVTablesBySymbol():
    names = Names()
    vtables = {}
    for nameTuple in names:
        ea = nameTuple[0]
        name = nameTuple[1]
        demangledName = Demangle(nameTuple[1], INF_SHORT_DN)
        if demangledName != None and demangledName.startswith("`vtable for'"):
            demangledClassName = demangledName[len("`vtable for'"):]
            segName = get_segm_name(ea)
            xrefs = getXRefsTo(ea+0x10)
            hasTextRef = True
            #for xref in xrefs:
            #    if getSegName(xref).endswith("__text"):
            #        hasTextRef = True
            #if (segName == "__const" or segName == "__data" or segName == "__constdata"): 
            if (segName == "__const") and hasTextRef: 
                vtables[demangledClassName] = ea
    return vtables

def parseVTables():
    print "[+] Parse VTables"
    vtables = getVTablesBySymbol()
    for demangledClassName in vtables:
        ea = vtables[demangledClassName]
        #if not demangledClassName.endswith("::MetaClass"): 
        #print hex(nameTuple[0]), nameTuple[1], Demangle(nameTuple[1], INF_SHORT_DN)
        vtableStartEA = ea + 16
        parseVTable(vtableStartEA, demangledClassName)
        createWholeVTableStructForClass(demangledClassName)
        SetType(ea, "whole_vtable_" + demangledClassName)
        SetType(ea-16, demangledClassName + "::MetaClass *")
        SetType(Qword(ea-16), demangledClassName + "::MetaClass")

def findVTableAddrInMetaClassAlloc(func):
    vtableAddr = findVTableAddrInMetaClassAlloc_NoReEnter(func)
    if vtableAddr == BADADDR:
        directCalls = findDirectCallsInFunc(func)
        for (callEA, calledEA) in directCalls:
            if getSegName(calledEA).endswith("__text"):
                vtableAddr = findVTableAddrInMetaClassAlloc(get_func(calledEA))
                if vtableAddr != BADADDR:
                    break
    return vtableAddr

def findVTableAddrInMetaClassAlloc_NoReEnter(func):
    vtableAddr = BADADDR
    calledFuncEAs = []
    if not None is func:
        for insnEA in Heads(func.startEA, func.endEA):
            nInsnEA = next_head(insnEA)
            if nInsnEA >= func.endEA:
                break
            elif GetMnem(insnEA) == "lea" and GetMnem(nInsnEA) == "mov" and get_operand_type(nInsnEA, 0) == 3 and GetOpnd(insnEA, 0) == GetOpnd(nInsnEA, 1):
                vtableAddr = GetOperandValue(insnEA, 1)
                break
            elif GetMnem(insnEA) == "lea":
                leaTarget = GetOpnd(insnEA, 0)
                nnInsnEA = next_head(nInsnEA)
                nnnInsnEA = next_head(nnInsnEA)
                if GetMnem(nInsnEA) == "add" and GetMnem(nnInsnEA) == "mov" and GetMnem(nnnInsnEA) == "mov" and GetOpnd(nInsnEA, 0) == leaTarget and GetOperandValue(nInsnEA, 1) == 0x10 and GetOpnd(nnnInsnEA, 1) == leaTarget:
                    vtableAddr = GetOperandValue(insnEA, 1) + 0x10
                    break
    return vtableAddr

def findVTableAddrByFindGetMetaClassFunction(gMetaClassAddr):
    xrefs = getXRefsTo(gMetaClassAddr)
    getMetaClassFuncEA = None
    for xref in xrefs:
        segName = getSegName(xref)
        if segName.endswith("__text"):
            xrefFunc = get_func(xref)
            if (not None is xrefFunc):
                lea_ea = None
                if (xrefFunc.size() == 13):
                    lea_ea = xrefFunc.startEA + 4
                elif (xrefFunc.size() == 22):
                    lea_ea = xrefFunc.startEA + 9
                if None is lea_ea:
                    continue
                mnem = GetMnem(lea_ea)
                if mnem == "lea" :
                    if GetOperandValue(lea_ea, 1) == gMetaClassAddr:
                        getMetaClassFuncEA = xrefFunc.startEA
                        break
    if not None is getMetaClassFuncEA:
        getMetaClassFuncEARefs = getXRefsTo(getMetaClassFuncEA)
        for ea in list(getMetaClassFuncEARefs):
            if (not isEAValid(ea)) or (not getSegName(ea).endswith("__const")):
                getMetaClassFuncEARefs.remove(ea)
        if len(getMetaClassFuncEARefs) > 1 or len(getMetaClassFuncEARefs) == 0:
            print "{:016X} getMetaClass has {} refs".format(getMetaClassFuncEA, len(getMetaClassFuncEARefs))
            return BADADDR
        vtableItemEA = getMetaClassFuncEARefs[0]
        
        currentEA = vtableItemEA
        if Qword(currentEA) == 0 and Qword(currentEA+8) == 0:
            return currentEA + 0x10
        else:
            while True:
                if Qword(currentEA) == 0:
                    break
                currentEA -= 8
            #print "0x{:016X}: {}".format(currentEA+8, Qword(currentEA+8)) 
            return (currentEA + 0x8)
    return BADADDR

def getAllModInitFuncs():
    modInitFuncSegSelector = SegByName("__mod_init_func")
    if modInitFuncSegSelector == BADADDR:
        print "[!] No mod init func seg, no need for analysis"
        return []
    modInitFuncSegEA = SegByBase(modInitFuncSegSelector)
    modInitFuncSegStartEA = SegStart(modInitFuncSegEA)
    modInitFuncSegEndEA = SegEnd(modInitFuncSegEA)
    currentEA = modInitFuncSegStartEA
    modInitFuncs = []
    for currentEA in range(modInitFuncSegStartEA, modInitFuncSegEndEA, 8):
        modInitFuncEA = Qword(currentEA)
        modInitFuncs.append(modInitFuncEA)
    return modInitFuncs

                
def parseModInitFuncSeg(reanalysis=False):
    ''' Necessary every time to get defined classes' information ?'''
    phase = "parseModInitFuncSeg"
    if not reanalysis and checkPhaseDone(phase):
        return True
    print "[+] Parse ModInitFunc Segments"
    modInitFuncs =  getAllModInitFuncs()
    if len(modInitFuncs) == 0:
        return False
    for modInitFuncEA in modInitFuncs:
        modInitFuncName = Name(modInitFuncEA)
        className = None
        classSize = 0
        classParentMetaClass = None
        classParentClass = None
        classGMetaClass = None

        #print "modInitFuncName: " + str(modInitFuncName)
        for (startea, endea) in Chunks(modInitFuncEA):
            heads = list(Heads(startea, endea))
            for i in range(0, len(heads)):
                insnEA = heads[i]
                opnd0 = GetOpnd(insnEA, 0)
                opertor = GetMnem(insnEA)
                if opertor == "call" and (opnd0 == "__ZN11OSMetaClassC2EPKcPKS_j" or opnd0 == "OSMetaClass::OSMetaClass(char const*,OSMetaClass const*,uint)"):
                    value, _ = backwardResolveInHeads(heads, i, "rsi")
                    if value != None:
                        className = GetString(value)
                    value, _ = backwardResolveInHeads(heads, i, "ecx")
                    if value != None:
                        classSize = value 
                    value, _ = backwardResolveInHeads(heads, i, "rdx")
                    if value != None:
                        valueName = Name(value)
                        if valueName == None or valueName.startswith("off_"):
                            classParentMetaClass =  Demangle(Name(Qword(value)), GetLongPrm(INF_SHORT_DN))
                            classParentClass = classParentMetaClass[:classParentMetaClass.rfind("::")]
                        else:
                            classParentMetaClass =  Demangle(valueName, GetLongPrm(INF_SHORT_DN))
                            classParentClass = classParentMetaClass[:classParentMetaClass.rfind("::")]
                    value, _ = backwardResolveInHeads(heads, i, "rdi")
                    if value != None:
                        valueName = Name(value)
                        classGMetaClassDemangledName = Demangle(valueName, GetLongPrm(INF_SHORT_DN))
                        if classGMetaClassDemangledName is None:
                            set_name(value, "__ZN" + str(len(className)) + className + "10gMetaClassE")
                    print className, classParentClass, classSize

                    # Add class struct or fulfill existing class struct
                    classNameToParentClassNameMap[className] = classParentClass
                    #classStrucName = "class_" + className
                    classStrucName = className
                    #classStrucId = GetStrucIdByName(classStrucName)
                    #if classStrucId == BADADDR:
                    #    classStrucId = AddStrucEx(-1, classStrucName, 0)
                    #currentClassSize = GetStrucSize(classStrucId)

                    #for memberOffset in range(currentClassSize, classSize, 8):
                    #    AddStrucMember(classStrucId, "member" + str(memberOffset/8), memberOffset, qwrdflag(), -1, 8)

                    createClassStruct(classStrucName, classSize, True)
                    #createClassStruct(classStrucName, classSize, False)
    markPhaseDone(phase)
    return True

def processAllFuncArgs(reanalysis=True):
    #phase = "processAllFuncArgs"
    #if not reanalysis and checkPhaseDone(phase):
    #    return
    #print "[+] Process All Function Args"

    textSegSelector = SegByName("__text")
    textSegEA = SegByBase(textSegSelector)
    textSegStartEA = SegStart(textSegEA)
    textSegEndEA = SegEnd(textSegEA)
    for funcStartEA in Functions(textSegStartEA, textSegEndEA):
        processFuncArgs(funcStartEA, not False, None, None)

    #markPhaseDone(phase)

            
def parseGOTNames():
    ''' assign types to vtable names in got seg''' 
    #phase = "parseGOTNames"
    #if checkPhaseDone(phase):
    #    return
    print "[+] Parse GOT Names"
    gotSegSelector = SegByName("__got")
    gotSegEA = SegByBase(gotSegSelector)
    if gotSegEA != BADADDR:
        parseNamesInGOTSeg(gotSegEA)
    #markPhaseDone(phase)

def findEntryPoints():
    foundEntry1 = []
    foundEntry2 = []
    foundEntryPoints = {}
    for ea, name in Names():
        segName = getSegName(ea)
        if not segName.endswith("__text"):
            continue
        deName = getDeFuncNameOfName(name)
        if None is deName:
            continue
        method_entry_names = ["externalMethod", "getTargetAndMethodForIndex", "getTargetAndTrapForIndex", "getAsyncTargetAndMethodForIndex"]
        entry_names = ["clientMemoryForType", "registerNotificationPort", "setProperty", "clientClose", "setProperties"]
        entry_names.extend(method_entry_names)
        for entry_name in entry_names:
            if deName.endswith("::" + entry_name):
                className = deName[:-(len(entry_name)+2)]
                outputStr = None
                if entry_name in method_entry_names:
                    #print "[+] Found {}".format(deName)
                    result = None
                    try:
                        result = sMethodAnalysisInMethodCB_byTriton(ea, entry_name != "externalMethod")
                    except Exception:
                        print "[!] sMethodAnalysisInMethodCB_byTriton failed at {:016X}".format(ea)
                        traceback.print_exc()
                    if (not None is result) and (not None is result[-1]) :
                        foundSMethodArrayEAs = result[-1]
                        if len(foundSMethodArrayEAs) > 0:
                            for arrayEA in foundSMethodArrayEAs:
                                sMethodEAs, funcPtrs = collectSMethodsFromArrayAt(arrayEA, -1, entry_name)
                                for funcPtr in funcPtrs:
                                    if isFuncStart(funcPtr):
                                        foundEntry2.append(funcPtr)
                                    else:
                                        vtStartEA, vtEndEA = getVTableAddrOfClass(className)
                                        realFuncPtr = Qword(vtStartEA+ funcPtr-1)
                                        foundEntry2.append(realFuncPtr)
                            #outputStr = "[+++] SMethod Array found for {}".format(deName)
                foundEntry1.append(ea)
                    #if None is outputStr:
                    #    outputStr = "[!!!] SMethod Array not found for {}".format(deName)
                #if None is outputStr:
                #    outputStr = "[+++] user entry {} found".format(entry_name)
    if len(foundEntry1) == 0 and len(foundEntry2) == 0:
        return {}
    foundEntryPoints["type1"] = foundEntry1
    foundEntryPoints["type2"] = foundEntry2
    return foundEntryPoints

def get_all_driver_class_names():
    classList = []
    modInitFuncs = getAllModInitFuncs()
    for modInitFuncEA in modInitFuncs:
        classList.extend(getClassListInModInitFunc(modInitFuncEA))
    return [item[1] for item in classList]

def isMetaClassAllocFunc(funcEA):
    func = get_func(funcEA)
    if not None is func:
        for insnEA in Heads(func.startEA, func.endEA):
            if GetMnem(insnEA) == "call" and GetOpnd(insnEA, 0).startswith("__ZN8OSObjectnwEm"):
                return True
    return False

def recoverClass():
    modInitFuncs = getAllModInitFuncs()
    foundVTables = {}
    if len(modInitFuncs) == 0:
        return None, None
    foundVTables = {}
    foundClassInhiertance = {}
    processVTableConstForKEXT()
    for modInitFuncEA in modInitFuncs:
        classList = getClassListInModInitFunc(modInitFuncEA)
        for (metaClassAddr, className, parentMetaClassAddr, parentClassName, classSize, metaClassVTableAddr) in classList:
            foundClassInhiertance[className] = parentClassName
            foundVTables[className + "::MetaClass"] = metaClassVTableAddr
            ea = metaClassVTableAddr
            funcEA = Qword(ea)
            while funcEA != 0:
                name = getName(funcEA)
                if name.endswith("9MetaClass5allocEv") or isMetaClassAllocFunc(funcEA):
                    vtableAddr = findVTableAddrInMetaClassAlloc(get_func(funcEA))
                    if vtableAddr == BADADDR:
                        #print "findVTableAddrInMetaClassAlloc for {} returned BADADDR".format(className)
                        vtableAddr = findVTableAddrByFindGetMetaClassFunction(metaClassAddr)
                    foundVTables[className] = vtableAddr
                    break
                ea += 8
                funcEA = Qword(ea)
    return foundVTables, foundClassInhiertance

def setTypesForGlobalObjs():
    print "[+] setTypesForGlobalObjs"
    commonSegSelector = SegByName("__common")
    commonSegEA = SegByBase(commonSegSelector)
    if commonSegEA == BADADDR:
        return
    commonSegStartEA = SegStart(commonSegEA)
    commonSegEndEA = SegEnd(commonSegEA)
    for ea in range(commonSegStartEA, commonSegEndEA, 8):
        deName = getDeNameAtEA(ea)
        if not None is deName and deName.endswith("::gMetaClass"):
            metaClassType = deName[:-len("::gMetaClass")] + "::MetaClass"
            SetType(ea, metaClassType)

def importTypesFromNeededKEXTs():
    binPath = get_input_file_path()
    macosPath = os.path.dirname()
    infoPlistPath = os.path.join(macosPath, "../Info.plist")


def exportParsedTypes():
    idbFileDirPath = os.path.dirname(idbFilePath)
    dumpTypesDirPath = os.path.join(idbFileDirPath)
    typeDumpFileName = idbFileName[:idbFileName.rfind(".")] + ".typedump.json"
    typeDumpfilePath = os.path.join(idbFileDirPath, typeDumpFileName)
    typesToDump = {"vtables": {}, "funcs": {}}
    vtablesToDump = {}
    for className in classNameToVTableAddrMap:
        vatbleStartEA, vtableEndEA = classNameToVTableAddrMap[className]
    testSeg = getSegByName("__text")
    funcsToDump = {}
    if not None is textSeg:
        for funcEA in Functions(textSeg.startEA, textSeg.endEA):
            funcTinfo = getTinfoOfFuncAtEA(funcEA)
            funcName = getName(funcEA)
            funcsToDump[funcName] = str(funcTinfo)


def haveSymbol():
    textSeg = getSegByName("__text")
    for f in Functions(textSeg.start_ea, textSeg.end_ea):
        if Name(f).startswith("_") and not None is getDeNameAtEA(f):
            return True
    return False

def exportCheckerResult(resultDirPath, result, includeDetailed=False):
    if not os.path.isdir(resultDirPath):
        os.mkdir(resultDirPath)
        
    resultFilePath = os.path.join(resultDirPath, modulename + ".json")
    with open(resultFilePath, "w") as f:
        json.dump(result, f)
   
    
def getProviderRelationship():
    import plistlib
    infoplist_fp = os.path.join(os.path.dirname(getOriginalBinaryPath()), "../Info.plist")
    if not os.path.isfile(infoplist_fp):
        return None
    plist = plistlib.readPlist(infoplist_fp)
    return getProviderRelFromInfo(plist)

