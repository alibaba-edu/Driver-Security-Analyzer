# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
idaapi.require("Arm64Utils")
from Arm64Utils import *

idaapi.require("AnalysisUtils")

def checkIfAllGotFuncIsInStubs():
    allGOTSegs = getAllSegsOfGOT()
    allStubsSegs = getAllSegsOfSTUBS()
    if len(allGOTSegs) == 0 and len(allStubsSegs) == 0:
        return
    for gotSeg in allGOTSegs:
        gotSegStartEA = gotSeg.startEA
        gotSegEndEA = gotSeg.endEA
        currentEA = gotSegStartEA
        while currentEA < gotSegEndEA:
            realItemEA = Qword(currentEA)
            if is_func(GetFlags(realItemEA)):
                xref = get_first_dref_to(currentEA)
                while xref != None and xref != BADADDR:
                    xrefSegName = get_segm_name(xref) 
                    if not xrefSegName.endswith(":__stubs"):
                        print "[!] GOT func item @{:016X} refer @{:016X} is not in stubs".format(currentEA, xref)
                    xref = get_next_dref_to(currentEA, xref)
            currentEA += 8

def getConstructorsInKextTEXT(kextPrefix):
    CTextEA2InfoMap = {}
    textSegStartEA, textSegEndEA = getTextAreaForKEXT(kextPrefix)
    for funcEA in Functions(textSegStartEA, textSegEndEA):
        funcName = getName(funcEA)
        if not None is funcName and isMangledFuncNameConstructor(funcName):
            realFuncDeName = getDeFuncNameOfName(funcName)
            className = realFuncDeName[:len(realFuncDeName)/2-1]
            ClassInstFuncInfo_C = ClassInstFuncInfo(funcName, className, IndicatorKind.INDNAME, [0], False)
            CTextEA2InfoMap[funcEA] = ClassInstFuncInfo_C
    return CTextEA2InfoMap


def getConstructorsInKextSTUBS(kextPrefix):
    stubsSegName = kextPrefix + ":__stubs"
    CStubEA2InfoMap = {}
    stubsSeg = get_segm_by_name(stubsSegName)
    if None is stubsSeg:
        return CStubEA2InfoMap
    stubsSegStartEA = stubsSeg.startEA
    stubsSegEndEA = stubsSeg.endEA
    currentEA = stubsSegStartEA
    while currentEA < stubsSegEndEA:
        stubFuncName = getName(currentEA)
        gotItemName = GetOpnd(currentEA, 1)[1:-5]
        realFuncName = gotItemName[:gotItemName.rfind("_ptr_")]
        if isMangledFuncNameConstructor(realFuncName):
            realFuncDeName = getDeFuncNameOfName(realFuncName)
            className = realFuncDeName[:len(realFuncDeName)/2-1]
            ClassInstFuncInfo_C = ClassInstFuncInfo(realFuncName, className, IndicatorKind.INDNAME, [0], False)
            CStubEA2InfoMap[currentEA] = ClassInstFuncInfo_C
        currentEA += 12
    return CStubEA2InfoMap

def isMangledFuncNameConstructor(mangledFuncName):
    if mangledFuncName.startswith("__ZN11OSMetaClassC2EPKcPKS_j"):
        return False
    deFuncName = getDeFuncNameOfName(mangledFuncName)
    return not None is deFuncName and deFuncName[:len(deFuncName)/2-1] == deFuncName[len(deFuncName)/2+1:]


def findUsageOfFuncEAs(usageSegName, funcEAs):
    usageOfSpecialFuncs = {}
    for funcEA in funcEAs:
        usageOfSpecialFuncs[funcEA] = set()
        xrefs = getXRefsTo(funcEA)
        for xref in xrefs:
            xrefSegName = get_segm_name(xref) 
            if xrefSegName == usageSegName:
                usageOfSpecialFuncs[funcEA].add(xref)
            elif xrefSegName.endswith(":__text"):
                print "[!] Stub In %s: %s refed in %s"%(kextPrefix, funcEA, xrefSegName)
    return usageOfSpecialFuncs

def findUsageOfStubFuncNames(stubsSegName, usageSegName, searchFuncNames):
    stubsSeg = get_segm_by_name(stubsSegName)
    if None is stubsSeg:
        return {}
    stubsSegStartEA = stubsSeg.startEA
    stubsSegEndEA = stubsSeg.endEA
    usageOfSpecialFuncs = {}
    for specialFuncName in searchFuncNames:
        usageOfSpecialFuncs[specialFuncName] = set()
    for funcEA in range(stubsSegStartEA, stubsSegEndEA, 12):
        funcName = getName(funcEA)
        for specialFuncName in searchFuncNames:
            if funcName.startswith(specialFuncName):
                #print "[+] Found ", funcName, specialFuncName 
                xrefs = getXRefsTo(funcEA)
                for xref in xrefs:
                    xrefSegName = get_segm_name(xref) 
                    if xrefSegName == usageSegName:
                        usageOfSpecialFuncs[specialFuncName].add(xref)
                    elif xrefSegName.endswith(":__text"):
                        print "[!] Stub In %s: %s refed in %s"%(kextPrefix, specialFuncName, xrefSegName)
    return usageOfSpecialFuncs

def shouldByPassSolveTypes(funcEA):
    funcName = getName(funcEA)
    if "_InitFunc_" in funcName:
        return True
    elif GetMnem(funcEA) == "B":
        return True
    return False

def solveVarTypesByPropInTextSeg(textSegStartEA, textSegEndEA, crossKEXT=False):
    for funcStartEA in Functions(textSegStartEA, textSegEndEA):
        if isFuncContainObjArg(funcStartEA):
            if not shouldByPassSolveTypes(funcStartEA):  
                AnalysisUtils.forward_analysis_in_func(funcStartEA, crossKEXT=crossKEXT)
        else:
            #print "[#] func at {:016X} does not have obj arg".format(funcStartEA)
            pass

def solveVarTypesByPropInAll():
    print "[+] solveVarTypesByPropInAll"
    for textSeg in getAllSegsOfText():
        solveVarTypesByPropInTextSeg(textSeg.startEA, textSeg.endEA)

def solveVarTypesByPropInKEXT(kextPrefix):
    startea, endea = getTextAreaForKEXT(kextPrefix)
    if startea == BADADDR:
        return
    solveVarTypesByPropInTextSeg(startea, endea, False)

def processVFuncArgsForClass(className):
    vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
    currentEA = vtableStartEA
    vtableStructId = getVTableStructIdOfClass(className)
    
    parentClassName, parentVTableStartEA, parentVTableEndEA = findNearestAncestorHaveVT(className)
    if parentVTableStartEA == BADADDR:
        print "[!] {}'s parent {}'s vtable is not found! Abort typing".format(className, parentClassName)
        return

    while currentEA != vtableEndEA:
        funcEA = Qword(currentEA)
        offset = currentEA-vtableStartEA
        shouldProcess = True
        if not None is parentClassName and parentVTableStartEA != BADADDR and parentVTableStartEA + offset < parentVTableEndEA:
            parentFuncEA = Qword(parentVTableStartEA + offset)
            if funcEA != parentFuncEA:
                funcName = getName(funcEA)
                if None is funcName:
                    currentEA += 8
                    continue
                if funcName.startswith("__"):
                    deFuncName = getDeFuncNameOfName(funcName)
                    if deFuncName:
                        funcClassName = deFuncName[:deFuncName.rfind("::")]
                        if funcClassName != className:
                            shouldProcess = False
                elif "::" in funcName:
                    funcClassName = funcName[:funcName.rfind("::")]
                    if funcClassName != className:
                        shouldProcess = False
                elif funcName == "___cxa_pure_virtual":
                    shouldProcess = False
                if shouldProcess:                    
                    processFuncArgs(funcEA, True, className, parentFuncEA)
        else:
            processFuncArgs(funcEA, True, className, None)
        keepCon_VFuncAndVTSMember(funcEA, vtableStructId, offset, False, True)
        currentEA += 8

def processVFuncArgsBFS(className):
    if not className in kernelClassNameSet:
        processVFuncArgsForClass(className)
    if className in classNameToChildClassNameSetMap:
        childClassNames = classNameToChildClassNameSetMap[className]
        for childClassName in childClassNames:
            processVFuncArgsBFS(childClassName)

def processVFuncArgsForKext(kextPrefix):
    #print moduleNameToClassNamesMap
    if not kextPrefix in moduleNameToClassNamesMap:
        return
    classNameSet = moduleNameToClassNamesMap[kextPrefix]
    for className in classNameSet:
        processVFuncArgsForClass(className)
        #if className in classNameToVTableFuncEAListMap:
        #    processVFuncArgsForClass(className)

def processNamedFuncArgsForKext(kextPrefix):
    #kextPrefix += ":__text"
    #textSeg = get_segm_by_name(kextPrefix)
    textSegStartEA, textSegEndEA = getTextAreaForKEXT(kextPrefix)
    processNamedFuncArgsForSeg(textSegStartEA, textSegEndEA)

def processNamedFuncArgsForSeg(textSegStartEA, textSegEndEA):
    for funcEA in Functions(textSegStartEA, textSegEndEA):
        funcName = getName(funcEA)
        if funcName.startswith("__"):
            funcDeName = getDeFuncNameOfName(funcName)
            if funcDeName and funcName != "___cxa_pure_virtual":
                if "::" in funcDeName:
                    className = funcDeName[:funcDeName.rfind("::")]
                    # This may incur error since not all functions are non-static
                    processFuncArgs(funcEA, True, className, None)
                else:
                    processFuncArgs(funcEA, False, None, None)


def processNamedFuncArgsForAll():
    print "[+] Process All Named Functions' Arguments"
    for seg in getAllSegsOfText():
        processNamedFuncArgsForSeg(seg.startEA, seg.endEA)


def processVFuncArgsForAll():
    print "[+] Process All Virtual Functions' Arguments"
    roots = kernelClassNameSet
    if len(roots) == 0:
        roots = findRootClasses()
    for className in roots:
        processVFuncArgsBFS(className)
    keepAllCon_VTAndVTS()



def setTypeForAllGlobalVars():
    for ea,name in Names():
        if None is name:
            continue
        if name.endswith("10gMetaClassE"):
            deName = getDeNameOfName(name)
            metaClassName = deName[:-12] + "::MetaClass"
            SetType(ea, metaClassName)
        elif name.endswith("9metaClassE"):
            deName = getDeNameOfName(name)
            metaClassName = deName[:-12] + "::MetaClass"
            SetType(ea, metaClassName + "*")
        elif name.startswith("__ZTV"):
            vtableDeName = getDeNameOfName(name)
            if not None is vtableDeName:
                className = vtableDeName[12:]
                wholeVTableStructId = GetStrucIdByName("whole_vtable_" + className)
                if wholeVTableStructId == BADADDR or GetStrucSize(wholeVTableStructId) != GetStrucSize(getVTableStructIdOfClass(className))+0x10:
                    wholeVTableStructId = createWholeVTableStructForClass(className)
                if wholeVTableStructId != BADADDR:
                    SetType(ea, "whole_vtable_" + className)

    ''' SetType(ea, "whole_vtable_" + className) will make the vtable const a chaos''' 
    processAllVTableConst(True)

def analyzeTypesForKEXT(kextPrefix):
    processNamedFuncArgsForKext(kextPrefix)
    processVFuncArgsForKext(kextPrefix)
    # I think this one is useless
    #setTypeForAllGlobalVars()

def analyzeTypesForAll():
    print "[+] Start Analyzing Types"
    processNamedFuncArgsForAll()
    processVFuncArgsForAll()
    # I think this one is useless
    #setTypeForAllGlobalVars()
    # Keep GOT consistency for type-analyzed funcs and vars
    processAllGOTSegs()

def findSMethodArrayForUCClass(ucClassName):
    vtableStartEA, vtableEndEA = getVTableAddrOfClass(ucClassName)
    if vtableStartEA != BADADDR:
        externMethodNamePrefix = "__ZN" + str(len(ucClassName)) + ucClassName + "14externalMethodE"
        getTargetNamePrefix = "__ZN" + str(len(ucClassName)) + ucClassName + "26getTargetAndMethodForIndexE"
        for vtEA in range(vtableStartEA, vtableEndEA, 4):
            funcEA = Qword(vtEA)
            funcName = getName(funcEA)
            if funcName.startswith(externMethodNamePrefix):
                None
            elif funcName.startswith(getTargetNamePrefix):
                None


def findSMethodArrayForKext(kextPrefix=None):
    externSMethods = []
    targetSMethods = []
    targetConstSegName = "__const"
    targetTextSegName = "__text"
    if kextPrefix:
        targetConstSegName = kextPrefix + ":__const"
        targetTextSegName = kextPrefix + ":__text"

    for segStartEA in Segments():
        seg = getseg(segStartEA)
        segName = get_segm_name(segStartEA)
        if segName != targetSegName:
            continue
        constSegStartEA = seg.startEA
        constSegEndEA = seg.endEA
        currentEA = constSegStartEA
        isInVT = False
        while currentEA < constSegEndEA:
            currentName = getName(currentEA)
            if currentName.startswith("__ZTV"):
                currentEA += 0x10
                isInVT = True
                continue
            if isInVT:
                if Qword(currentEA) == 0:
                    isInVT = False
                currentEA += 8
                continue

            xrefs = getXRefsTo(currentEA)
            if len(xrefs) == 0:
                currentEA += 8
                continue
            else:
                for xref in xrefs:
                    xrefSegName = SegName(xref)
                    if xrefSegName == targetTextSegName:
                        xrefFunc = get_func(xref)
                        if not None is xrefFunc:
                            xrefFuncName = getName(xrefFunc.startEA)
                            xrefDeFuncName = getDeFuncNameOfName(xrefFuncName)
                            className = None
                            if not None is xrefDeFuncName:
                                className = xrefDeFuncName[:xrefDeFuncName.rfind("::")]
                            elif "::" in xrefFuncName:
                                className = xrefFuncName[:xrefFuncName.rfind("::")]
                            sMethods_IOExternalMethodDispatch_cnt = 0
                            guessEA = currentEA
                            while True:
                                guessValue0 = Qword(guessEA)
                                guessValue1 = Qword(guessEA+8)
                                guessValue2 = Qword(guessEA+0x10)
                                guessValue3 = Qword(guessEA+0x18)
                                if isIOExternalMethodDispatchAtEA(guessEA) :
                                    guessEA += 0x18
                                    sMethods_IOExternalMethodDispatch_cnt += 1 
                                elif guessValue0 == 0 and guessValue1 == 0 and guessValue2 == 0 and \
                                       isIOExternalMethodDispatchAtEA(guessEA+0x18, True):
                                    guessEA += 0x18
                                    sMethods_IOExternalMethodDispatch_cnt += 1 
                                else:
                                    break
                            if sMethods_IOExternalMethodDispatch_cnt != 0:
                                externSMethods.append((currentEA, sMethods_IOExternalMethodDispatch_cnt+1, className))
                                if not None is className:
                                    parseSMethodArrayAtAddr(currentEA, sMethods_IOExternalMethodDispatch_cnt+1, className, True)
                                currentEA = guessEA + 0x18
                                continue
                            

            currentEA += 8

    return externSMethods, targetSMethods


def findSMethodArrayForAll():
    externSMethods = []
    targetSMethods = []
    for kextPrefix in getAllKEXTPrefixes():
        externSMethodsOfKext, targetSMethodsOfKext = findSMethodArrayForKext(kextPrefix)
        externSMethods.extend(externSMethodsOfKext)
        targetSMethods.extend(targetSMethodsOfKext)

    externSMethodsOfKext, targetSMethodsOfKext = findSMethodArrayForKext()
    externSMethods.extend(externSMethodsOfKext)
    targetSMethods.extend(targetSMethodsOfKext)

    print "[+] Found SMethods: EA, Size, ClassName"
    for sMethod in externSMethods:
        print "{:016X}, {}, {}".format(sMethod[0], sMethod[1], sMethod[2])


print "[+] Arm64TypeAnalyzer loaded"
