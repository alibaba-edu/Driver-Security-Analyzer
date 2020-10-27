# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
idaapi.require("Arm64Utils")
from Arm64Utils import *

def nameVFuncsForClass(className):
    ''' This function should be called in BFS/DFS order
    '''
    somethingChanged = False
    if className in kernelClassNameSet:
        return somethingChanged
    if not className in classNameToVTableAddrMap:
        return somethingChanged
    (vtableStartEA, vtableEndEA) = getVTableAddrOfClass(className)
    vtableStructId = getVTableStructIdOfClass(className)
    if not className in classNameToParentClassNameMap:
        return somethingChanged

    parentClassName, parentVTableStartEA, parentVTableEndEA = findNearestAncestorHaveVT(className)

    if parentVTableStartEA == BADADDR:
        print "[!] {}'s parent {}'s vtable is not found! Abort naming".format(className, parentClassName)
        return

    currentEA = vtableStartEA
    while currentEA < vtableEndEA:
        offset = currentEA - vtableStartEA
        funcEA = Qword(currentEA)
        funcName = getName(funcEA)
        if funcEA == BADADDR or None is funcName:
            print "[!] nameVFuncsForClass {} {:016X} vfunc name none at {:016X}".format(className, currentEA, funcEA)
            ida_utilities.force_function(funcEA)
            funcName = getName(funcEA)
        if (not is_func(GetFlags(funcEA))) or  (None is funcName) or (funcName.startswith("__")):
            currentEA += 8
            continue
        newFuncName = funcName
        demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
        if offset == 0:
            newFuncName = "__ZN" + getMangledNameOfName(className) + "D2Ev"
        elif parentVTableStartEA != BADADDR and parentVTableStartEA + offset < parentVTableEndEA:
            parentFuncEA = Qword(parentVTableStartEA + offset)
            parentFuncName = getName(parentFuncEA)
            #if funcEA != parentFuncEA and (not funcName.startswith("__")) and demangledFuncName == None:
            if funcEA != parentFuncEA:
                ''' We can not set func name if it is the same with its parent '''
                parentFuncDemangledName = Demangle(parentFuncName, GetLongPrm(INF_LONG_DN))
                
                if parentFuncDemangledName != None:
                    #print parentFuncDemangledName
                    newFuncName = replaceClassInMangledName(parentFuncName, className)
                        #print "setFuncName " + newFuncName + " at " + hex(funcEA)
                        #SetMemberName(vtableStructId, offset, newFuncName)
                        #memberId = GetMemberId(vtableStructId, offset)
                        #funcPTRType = tryToGetFuncPTRTypeForVirtualFunc(funcEA, className)
                        #if funcPTRType != None:
                        #    SetType(memberId, funcPTRType)
                else:
                    # The parent name is not found, maybe a kext class
                    newFuncName = className + "::vfunc_" + hex(funcEA & 0xFFFFFFFF)
        elif not funcName.startswith("__") and funcName != "___cxa_pure_virtual":
            ''' Sometimes, we can not find the func's parent, but the original func name may be kernel func '''
            newFuncName = className + "::vfunc_" + hex(funcEA & 0xFFFFFFFF)
        if funcName.startswith("sub_") and not funcName.startswith("__") and funcName != newFuncName and funcName != "___cxa_pure_virtual":
            if setFuncName(funcEA, newFuncName, SN_FORCE):
                somethingChanged = True
        if somethingChanged:
            keepCon_VFuncAndVTSMember(funcEA, vtableStructId, offset, True, False)
        currentEA += 0x8
    return somethingChanged

def nameVFuncsBFS(className):
    if not className in kernelClassNameSet:
        nameVFuncsForClass(className)
    if className in classNameToChildClassNameSetMap:
        childClassNames = classNameToChildClassNameSetMap[className]
        for childClassName in childClassNames:
            nameVFuncsBFS(childClassName)

def nameVFuncsFromKernelClassesBFS():
    for className in kernelClassNameSet:
        nameVFuncsBFS(className)

def namePatternFuncsForAll():
    for kextPrefix in getAllKEXTPrefixes():
        namePatternFuncsForKEXT(kextPrefix)

def nameFuncIfMetaClassConstructor(funcEA):
    func = get_func(funcEA)
    if func.size() == 56 or func.size() == 52:
        funcStartEA = func.startEA
        shouldBL_EA = funcStartEA + 0x1c
        if GetMnem(shouldBL_EA) == "BL" and GetOpnd(shouldBL_EA, 0).startswith("__ZN11OSMetaClassC2EPKcPKS") :
            shouldClassString_EA = funcStartEA + 8
            className = None
            if GetMnem(shouldClassString_EA) == "ADRP" and GetMnem(shouldClassString_EA+4) == "ADD":
                classStringAddr = GetOperandValue(shouldClassString_EA, 1) + GetOperandValue(shouldClassString_EA+4, 2)
                className = getStringAtAddr(classStringAddr)
            elif GetMnem(shouldClassString_EA) == "ADR":
                classStringAddr = GetOperandValue(shouldClassString_EA, 1)
                className = getStringAtAddr(classStringAddr)
            if not None is className:
                metaClassCPrefix = "__ZN" + getMangledNameOfName(className) + "9MetaClass"
                CCnt = 1
                CName = metaClassCPrefix + "C" + str(CCnt) + "Ev"
                CAddr = get_name_ea(0, CName)
                while CAddr != BADADDR and CAddr != funcEA:
                    ''' Somewhere else has the name already '''
                    CCnt += 1
                    CName = metaClassCPrefix + "C" + str(CCnt) + "Ev"
                    CAddr = get_name_ea(0, CName)

                #setFuncName(funcEA, CName)
                setNameOverride(funcEA, CName)
                funcType = "void " + CName + "(" + className + "::MetaClass *this)"
                setFuncType(funcEA, funcType)
                return True

    return False

def setConstructorName(funcEA, className):
    mangledClassName = getMangledNameOfName(className)
    CCnt = 1
    CName = "__ZN" + mangledClassName + "C" + str(CCnt) + "EPK11OSMetaClass"
    CAddr = get_name_ea(0, CName)
    while CAddr != BADADDR and CAddr != funcEA:
        ''' Somewhere else has the name already '''
        CCnt += 1
        CName = "__ZN" + mangledClassName + "C" + str(CCnt) + "EPK11OSMetaClass"
        CAddr = get_name_ea(0, CName)
    #setFuncName(funcEA, CName)
    setNameOverride(funcEA, CName)
    funcType = "void " + CName + "(" + className + "*this, OSMetaClass *)"
    setFuncType(funcEA, funcType)

def nameFuncIfConstructor(funcEA):
    func = get_func(funcEA)
    if func.size() == 36 or func.size() == 24:
        funcStartEA = func.startEA
        shouldVTOff = 12 if func.size == 36 else 8
        shouldVTable_EA = funcStartEA + shouldVTOff
        vtableName = None
        if GetMnem(shouldVTable_EA) == "ADRP" and GetMnem(shouldVTable_EA+4) == "ADD":
            vtableNameAddr = GetOperandValue(shouldVTable_EA, 1) + GetOperandValue(shouldVTable_EA+4, 2)
            if func.size() == 24:
                vtableNameAddr -= 0x10
            vtableName = getName(vtableNameAddr)
        elif GetMnem(shouldVTable_EA) == "ADR":
            vtableNameAddr = GetOperandValue(shouldVTable_EA, 1)
            if func.size() == 24:
                vtableNameAddr -= 0x10
            vtableName = getName(vtableNameAddr)
        if not None is vtableName and vtableName.startswith("__ZTV"):
            if getDeNameOfName(vtableName) is None:
                print "nameFuncIfConstructor:", hex(funcEA), vtableName 
            className = getDeNameOfName(vtableName)[12:]
            setConstructorName(funcEA, className)
            return True

    elif func.size() == 72:
        funcStartEA = func.startEA
        shouldGMetaClass_EA = funcStartEA + 16
        shouldBL_EA = funcStartEA + 28
        shouldBL_InstCon = funcStartEA + 52
        if GetMnem(shouldBL_EA) == "BL" and GetMnem(shouldBL_InstCon) == "BL" and \
                GetOpnd(shouldBL_InstCon, 0).startswith("__ZNK11OSMetaClass19instanceConstructedEv"):
            gMetaClassName = None
            if GetMnem(shouldGMetaClass_EA) == "ADRP" and GetMnem(shouldGMetaClass_EA+4) == "ADD":
                gMetaClassAddr = GetOperandValue(shouldGMetaClass_EA, 1) + GetOperandValue(shouldGMetaClass_EA+4, 2)
                gMetaClassName = getName(gMetaClassAddr)
            elif GetMnem(shouldGMetaClass_EA) == "ADR":
                gMetaClassAddr = GetOperandValue(shouldGMetaClass_EA, 1)
                gMetaClassName = getName(gMetaClassAddr)
            if not None is gMetaClassName:
                deGMetaClassName = getDeNameOfName(gMetaClassName)
                className = deGMetaClassName[:-12]
                setConstructorName(funcEA, className)
                return True
    return False

def namePatternFuncsForKEXT(kextPrefix, override=False):
    textSegStartEA, textSegEndEA = getTextAreaForKEXT(kextPrefix)
    #textSeg = get_segm_by_name(kextPrefix + ":__text")
    #textSegStartEA = textSeg.startEA
    #textSegEndEA = textSeg.endEA
    for funcEA in Functions(textSegStartEA, textSegEndEA):
        funcName = getName(funcEA)
        if override or (not funcName.startswith("__") and funcName != "___cxa_pure_virtual"):
            if nameFuncIfMetaClassConstructor(funcEA):
                continue
            if nameFuncIfConstructor(funcEA):
                continue

def nameVFuncsForAll(ignorePhaseDone=False):
    phase = "nameVirtualFuncsForAll"
    if (not ignorePhaseDone) and checkPhaseDone(phase):
        return
    print "[+] Name All Virtual Functions"

    nameVFuncsFromKernelClassesBFS()
    markPhaseDone(phase)

def findSymbolsForKEXT(kextPrefix):
    nameVFuncsForKext(kextPrefix)
    namePatternFuncsForKEXT(kextPrefix)

def findSymbolsForAll(ignorePhaseDone=False):
    nameVFuncsForAll(ignorePhaseDone)
    namePatternFuncsForAll()

def nameVFuncsForKext(kextPrefix):
    if not kextPrefix in moduleNameToClassNamesMap:
        return
    classNameSet = moduleNameToClassNamesMap[kextPrefix]
    for className in classNameSet:
        nameVFuncsForClass(className)

print "[+] Arm64SymbolFinder loaded"
