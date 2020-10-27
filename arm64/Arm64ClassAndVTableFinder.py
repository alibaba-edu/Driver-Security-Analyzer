# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
idaapi.require("Arm64Utils")
from Arm64Utils import *

def checkFuncNameIsSuperConstructor(funcName, className):
    result = False
    if className in classNameToParentClassNameMap:
        parentClassName = classNameToParentClassNameMap[className]
        superConstructorFuncName = "__ZN" + str(len(parentClassName)) + parentClassName + "C2EPK11OSMetaClass"
        if funcName.startswith(superConstructorFuncName):
            result = True
        else:
            superConstructorFuncName = "__ZN" + str(len(parentClassName)) + parentClassName + "C1EPK11OSMetaClass"
            if funcName.startswith(superConstructorFuncName):
                result = True
    return result

def findVTableAddrInMetaClassAlloc(func):
    vtableAddr = BADADDR
    if not None is func:
        insns = list(Heads(func.startEA, func.endEA))
        #for insnEA in Heads(func.startEA, func.endEA):
        for i in range(len(insns)-1, -1, -1):
            insnEA = insns[i]
            if insnEA + 16 < func.endEA:
                if GetMnem(insnEA) == "ADRP" and \
                        GetMnem(insnEA+4) == "ADD" and \
                        GetMnem(insnEA+8) == "ADD" and \
                        GetOperandValue(insnEA+8, 2) == 0x10 and \
                        GetMnem(insnEA+12) == "STR":

                    vtableAddr = GetOperandValue(insnEA, 1) + GetOperandValue(insnEA+4, 2) + 0x10

                elif GetMnem(insnEA) == "ADR" and \
                        GetMnem(insnEA+4) == "NOP" and \
                        GetMnem(insnEA+8) == "ADD" and \
                        GetOperandValue(insnEA+8, 2) == 0x10 and \
                        GetMnem(insnEA+12) == "STR":

                    vtableAddr = GetOperandValue(insnEA, 1) + 0x10

                elif GetMnem(insnEA) == "ADRP" and \
                        GetMnem(insnEA+4) == "ADD" and \
                        GetMnem(insnEA+8) == "STR":
                        #GetOpnd(insnEA+8, 1).startswith("[X0]"):

                    vtableAddr = GetOperandValue(insnEA, 1) + GetOperandValue(insnEA+4, 2)

                elif GetMnem(insnEA) == "ADR" and GetMnem(insnEA+4) == "NOP" \
                        and GetMnem(insnEA+8) == "STR" and GetOpnd(insnEA+8, 1).startswith("[X0]"):
                    vtableAddr = GetOperandValue(insnEA, 1)

                if vtableAddr != BADADDR:
                    break

    if vtableAddr != BADADDR:
        segName = getSegName(vtableAddr)
        if segName.endswith("__const"):
            return vtableAddr
        else:
            vtableAddr = BADADDR
    return vtableAddr

def parseMetaClassAllocFunc(metaClassAllocFuncEA, className=None):
    # find class vtable in ::MetaClass::alloc function
    # if not found (i.e., abstract class), 
    # try to follow getMetaClass
    segName = getSegName(metaClassAllocFuncEA)
    #if segName in ["__TEXT_EXEC:__text", "__TEXT:__text"]: 
    #    # DO NOT PARSE KERNEL METACLASSES
    #    return
    if className is None:
        name = getName(metaClassAllocFuncEA)
        deName = getDeFuncNameOfName(name)
        className = deName[:-18]
    else:
        if className.endswith("::MetaClass"):
            className = className[:-11]
    if not isFuncStart(metaClassAllocFuncEA):
        ida_utilities.force_function(metaClassAllocFuncEA)
    func = get_func(metaClassAllocFuncEA)
    funcName = getName(metaClassAllocFuncEA)
    if None is funcName:
        funcName = "__ZN{}{}9MetaClass5allocEv".format(len(className), className)
    if not None is func:
        vtStartEA = BADADDR
        if func.size() > 8:
            vtStartEA = findVTableAddrInMetaClassAlloc(func)
            if vtStartEA == BADADDR:
                if GetMnem(func.endEA-4) == "B":
                    vtStartEA = findVTableAddrInMetaClassAlloc(get_func(GetOperandValue(func.endEA-4,0)))
        else:
            vtStartEA = findVTableAddrByTraceGetMetaClassFunction(className)

        if vtStartEA == BADADDR:
            print "[!] Unable to find vtable from metaclass::alloc {} or trace getMetaClass".format(getName(metaClassAllocFuncEA))
            return
            None
        #elif getName(vtStartEA) != "__ZTV" + getMangledNameOfName(className):
        if getName(vtStartEA) != "__ZTV" + getMangledNameOfName(className):
            #print "[!] Inconsistent vtable {} in metaclass::alloc: {}".format(getName(vtStartEA), getName(metaClassAllocFuncEA))
            parseVTable(vtStartEA, className, True)
    SetType(metaClassAllocFuncEA, className + "*" + funcName + "(" + className + "::MetaClass *this" + ")")


def findVTableAddrByTraceGetMetaClassFunction(className):
    if None is className or className in ["OSMetaClass"]:
        return BADADDR
    #gMetaClassName = "__ZN" + str(len(className)) + className + "10gMetaClassE"
    gMetaClassName = "__ZN" + getMangledNameOfName(className) + "10gMetaClassE"
    gMetaClassAddr = get_name_ea(0, gMetaClassName)
    if gMetaClassAddr == BADADDR:
        print "findVTableAddrByTraceGetMetaClassFunction {} BADADDR".format(gMetaClassName)
    xrefs = getXRefsTo(gMetaClassAddr)
    getMetaClassFuncEA = None
    for xref in xrefs:
        segName = getSegName(xref)
        #print "gMetaClass xref: {:016X} segName: {} isInSameKEXT: {}".format(xref,segName,isInSameKEXT(xref, gMetaClassAddr))
        if segName.endswith("__text") and isInSameKEXT(xref, gMetaClassAddr):
            xrefFunc = get_func(xref)
            #if (not None is xrefFunc) and (xrefFunc.size() == 12):
            if (not None is xrefFunc) and (xrefFunc.size() >= 12) and (xref+8) < xrefFunc.endEA:
                #print "findVTableAddrByTraceGetMetaClassFunction {:016X} size 12".format(xref)
                mnem0 = GetMnem(xref)
                mnem1 = GetMnem(xref + 4)
                mnem2 = GetMnem(xref + 8)
                if mnem0 == "ADRP" and mnem1 == "ADD" and mnem2 == "RET" and \
                    GetOpnd(xref, 0) == "X0" and \
                    GetOpnd(xref+4, 0) == "X0" and GetOpnd(xref+4, 1) == "X0" and \
                    GetOperandValue(xref, 1) + GetOperandValue(xref+4, 2) == gMetaClassAddr:
                        getMetaClassFuncEA = xrefFunc.startEA
                        break
    if not None is getMetaClassFuncEA:
        getMetaClassFuncEARefs = getXRefsTo(getMetaClassFuncEA)
        for ea in list(getMetaClassFuncEARefs):
            if (not isEAValid(ea)) or (not getSegName(ea).endswith("__const")):
                getMetaClassFuncEARefs.remove(ea)
        if len(getMetaClassFuncEARefs) != 1:
            print "{:016X} {}::getMetaClass has wrong refs {}".format(getMetaClassFuncEA, className, getMetaClassFuncEARefs)
            return BADADDR
        vtableItemEA = getMetaClassFuncEARefs[0]
        
        currentEA = vtableItemEA
        while Qword(currentEA) != 0:
            currentEA -= 8
        return currentEA + 8 # vtable start ea
    return BADADDR

def parseVTable(vtableStartEA, demangledClassName, shouldOverride=False, fromSymbol=False):
    # already parsed, no need to parse Again
    segName = getSegName(vtableStartEA)
    shouldSetName = not fromSymbol
    #shouldSetName = (segName != "__DATA_CONST:__const" and segName != "__DATA:__const")
    vtableStartName = "vtableStart_" + demangledClassName
    if demangledClassName.endswith("::MetaClass"):
        vtableName = "__ZTVN" + getMangledNameOfName(demangledClassName) + "E"
    else:
        vtableName = "__ZTV" + getMangledNameOfName(demangledClassName)

    # TODO uncomment these
    alreadyParsedStartEA, alreadyParsedEndEA = getVTableAddrOfClass(demangledClassName)
    if alreadyParsedStartEA != BADADDR and alreadyParsedEndEA-alreadyParsedStartEA > 0:
        alreadyParsedVTSid = getVTableStructIdOfClass(demangledClassName)
        if alreadyParsedStartEA == vtableStartEA:
            shouldSetName = False
            if alreadyParsedVTSid != BADADDR:
                if demangledClassName.endswith("::MetaClass"):
                    theClassName = demangledClassName[:-len("::MetaClass")]
                    theClassVTStart, theClassVTEnd = getVTableAddrOfClass(theClassName)
                    if theClassVTStart != BADADDR:
                        # MetaClass::alloc has finished analysis
                        return
                else:
                    return

        else:
            print "[!] For {}, alreadyParsedStartEA {:016X} != vtableStartEA {:016X}".format(demangledClassName, alreadyParsedStartEA, vtableStartEA)

    oldName = getName(vtableStartEA-0x10)
    if not None is oldName and oldName.startswith("__"):
        shouldSetName = False

    if shouldSetName:
        if shouldOverride:
            setNameOverride(vtableStartEA-0x10, vtableName)
            setNameOverride(vtableStartEA, vtableStartName)
        else:
            set_name(vtableStartEA-0x10, vtableName)
            set_name(vtableStartEA, vtableStartName)

    alreadyExist = False
    vtableFuncEAList = []
    vtableEndEA = vtableStartEA

    vtableStrucName = "vtable_" + demangledClassName
    classStrucName = demangledClassName

    vtableStructId = GetStrucIdByName(vtableStrucName)
    if vtableStructId == BADADDR:
        vtableStructId = AddStrucEx(-1, vtableStrucName, 0)
    elif shouldOverride:
        DelStruc(vtableStructId)
        vtableStructId = AddStrucEx(-1, vtableStrucName, 0)

    set_struc_hidden(get_struc(vtableStructId), 1)

    classStrucId = GetStrucIdByName(classStrucName)
    if classStrucId == BADADDR:
        classStrucId = AddStrucEx(-1, classStrucName, 0)
        set_struc_hidden(get_struc(classStrucId), 1)
    if GetStrucSize(classStrucId) == 0:
        AddStrucMember(classStrucId, "vtable", 0, qwrdflag(), -1, 8)

    SetMemberType(classStrucId, 0, qwrdflag(), -1, 1)
    SetOrAddMemberName(classStrucId, 0, "vtable")
        
    ret = SetType(GetMemberId(classStrucId, 0), "struct " + vtableStrucName + " *")

    classNameToVTableStructIdMap[demangledClassName] = vtableStructId

    vtableStructSize = GetStrucSize(vtableStructId)
    if vtableStructSize > 0:
        classNameToVTableAddrMap[demangledClassName] = (vtableStartEA, vtableStartEA + vtableStructSize + 0x8)
        alreadyExist = True
        #return

    #print "SetClassMemberType: " + str(ret)
    metaClassAllocFuncEA = None
    while True:
        funcEA = Qword(vtableEndEA)
        vtableFuncEAList.append(funcEA)
        virtualFuncEASet.add(funcEA)
        ida_utilities.force_function(funcEA)
        func = get_func(funcEA)
        if funcEA == 0 or None is func:
            classNameToVTableAddrMap[demangledClassName] = (vtableStartEA, vtableEndEA)
            classNameToVTableFuncEAListMap[demangledClassName] = vtableFuncEAList
            break
        vtableEndEA = vtableEndEA + 0x8 
    vtItemCnt = (vtableEndEA-vtableStartEA)/8

    for currentEA in range(vtableStartEA, vtableEndEA, 8):
        #print getName(Qword(currentEA))
        op_plain_offset(currentEA, 0, 0)
        funcEA = Qword(currentEA)
        funcName = getName(funcEA) 
        funcFlags = GetFlags(funcEA)
        deFuncName = getDeFuncNameAtEA(funcEA)
        memberOffset = currentEA-vtableStartEA

        if demangledClassName.endswith("::MetaClass"):
            mangledClassName = getMangledNameOfName(demangledClassName)
            if not funcName.startswith("__"):
                funcIndex = (currentEA-vtableStartEA)/8
                funcNameToSet = None
                allocIndex = getMetaClassAllocIndex()
                if allocIndex == -1 or allocIndex >= vtItemCnt:
                    allocIndex = vtItemCnt - 1
                if funcIndex == 0:
                    funcNameToSet = "__ZN" + mangledClassName + "D1Ev"
                elif funcIndex == 1:
                    funcNameToSet = "__ZN" + mangledClassName + "D0Ev"
                elif funcIndex == allocIndex:
                    funcNameToSet = "__ZN" + mangledClassName + "5allocEv"
                    metaClassAllocFuncEA = funcEA

                if  not None is funcNameToSet:
                    set_name(funcEA, funcNameToSet)

            elif (not None is deFuncName) and deFuncName.endswith("::MetaClass::alloc"):
                metaClassAllocFuncEA = funcEA

        elif (None is funcName) or (funcName.startswith("sub_")):
            vfuncMemberId = GetMemberId(vtableStructId, memberOffset)
            if vfuncMemberId != -1 and vfuncMemberId != BADADDR:
                vfuncMemberName = get_member_name(vfuncMemberId, memberOffset)
                if (not None is vfuncMemberName) and vfuncMemberName.startswith("__") and (not vfuncMemberName.startswith("___cxa_pure_virtual") ) and (not None is getDeNameOfName(vfuncMemberName)):
                    set_name(funcEA, vfuncMemberName)
        
        # TODO
        # in case two members have the same name, e.g., ___cxa_pure_virtual
        AddStrucMember(vtableStructId, "member" + str(memberOffset/8), memberOffset, qwrdflag(), -1, 8)
        SetOrAddMemberName(vtableStructId, memberOffset, funcName)
        SetMemberComment(vtableStructId, memberOffset, hex(funcEA), 1)
        memberId = GetMemberId(vtableStructId, memberOffset)

        addXref(memberId, funcEA, 1)
        addXref(funcEA, memberId, 1)

        funcPTRType = tryToGetFuncPTRTypeForVirtualFunc(funcEA, demangledClassName)
        if funcPTRType != None:
            SetType(memberId, funcPTRType)

        #print "funcFlags: " + hex(funcFlags), "funcType: " + str(GetType(funcEA)), "funcDemangledName: " + Demangle(funcName, GetLongPrm(INF_LONG_DN)) , "guessType: " + str(GuessType(funcEA)), "memberId: " + hex(GetMemberId(vtableStructId, currentEA-vtableStartEA))
        if GetType(memberId) == None:
            if deFuncName != None:
                print("SetType Failed: " + deFuncName + " " + funcPTRType)
            else:
                print("SetType Failed: " + funcName + " " + funcPTRType)

    createWholeVTableStructForClass(demangledClassName)

    if not None is metaClassAllocFuncEA:
        #print "metaClassAllocFuncEA: {} {:016X}".format(metaClassAllocFuncEA, vtableStartEA)
        parseMetaClassAllocFunc(metaClassAllocFuncEA, demangledClassName)

metaclass_alloc_index = -1
def getMetaClassAllocIndex():
    global metaclass_alloc_index
    if metaclass_alloc_index != -1:
        return metaclass_alloc_index
    vtStartEA, vtEndEA = getVTableAddrOfClass("OSMetaClassMeta")
    if not None is vtStartEA:
        for ea in range(vtEndEA-8, vtStartEA-8, -8):
            funcname = Name(Qword(ea))
            if funcname == "__ZNK15OSMetaClassMeta5allocEv":
                metaclass_alloc_index = (ea - vtStartEA)/8
                return metaclass_alloc_index
    return -1

def tryToGetFuncPTRTypeForVirtualFunc(funcEA, className):
    funcType = GetType(funcEA)
    funcName = getName(funcEA) 
    funcPTRType = None
    deFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
    if funcType == None:
        funcType = GuessType(funcEA)
        if funcType == None:
            funcType = "__int64 ("
            if deFuncName != None:
                #print("Parse Type: " + deFuncName)
                classNameInFuncName, pureFuncName, arglist = parseFuncProtoWORet(deFuncName, True)            
                if len(arglist) == 0 :
                    funcType = funcType + "void"
                elif len(arglist) == 1:
                    funcType = funcType + arglist[0]
                else:
                    funcType = funcType + arglist[0]
                    for i in range(1, len(arglist)):
                        funcType = funcType + ", " + arglist[i]
            else:
                funcType = funcType + className + "*this"

            funcType = funcType + ")"

    if funcType != None:
        funcTypeArgStartLoc = funcType.find("(")
        funcPTRType = funcType[:funcTypeArgStartLoc] + "(*)" +  funcType[funcTypeArgStartLoc:]

    return funcPTRType

def locateOSMetaClassConsForUnnamedKernel():
    if kernelcache_status.isKernelSymbolic:
        return
    if not kernelcache_status.isMerged():
        print "[!] Do not know how to locateOSMetaClassConstructorForUnnamedKernel for not merged kernel cache"
        return
    seg = get_segm_by_name("__kmod_init")
    if None is seg:
        print "[?] No __kmod_init for merged kc"
        return
    if seg.endEA - seg.startEA < 8*0x10:
        print "[?] Size of __kmod_init {} too small".format(seg.endEA - seg.startEA)
        return
    metaClassCons = None
    for i in range(0, 0x10):
        ea = seg.startEA + 8 * i
        funcEA = Qword(ea)
        func = get_func(funcEA)
        for insnEA in Heads(func.startEA, func.endEA):
            mnem = GetMnem(insnEA)
            if mnem == "BL":
                prevEA = prev_head(insnEA)
                if GetMnem(prevEA) == "MOV" and GetOpnd(prevEA) == "W3":
                    metaClassCons = GetOperandValue(insnEA, 0)
                    break
        if not None is metaClassCons:
            break
    if not None is metaClassCons:
        SetName(metaClassCons, "__ZN11OSMetaClassC2EPKcPKS_j")
        SetType(metaClassCons, "__int64 OSMetaClass__OSMetaClass(OSMetaClass *this, const char *, const OSMetaClass *, unsigned int)")
    return metaClassCons
                

def parseModInitFuncs(modInitFuncs):
    parsedClassInfoList = []
    failedClasses = set()
    for modInitFuncEA in modInitFuncs:
        modInitFuncName = getName(modInitFuncEA)
        if modInitFuncName.startswith("sub_"):
            set_name(modInitFuncEA, "InitFunc_{:016X}".format(modInitFuncEA))
        classInfoList, noVTableClasses = parseModInitFunc(modInitFuncEA)
        parsedClassInfoList.extend(classInfoList)
        failedClasses.update(noVTableClasses)
    return parsedClassInfoList, failedClasses


def checkIfGMetaClassRetAreAllGetMetaClass():
    for ea, name in Names():
        if name.endswith("10gMetaClassE"):
            xref = get_first_dref_to(ea)
            while xref != BADADDR:
                xrefSegName = getSegName(xref)
                if xrefSegName.endswith(":__text"):
                    if GetMnem(xref) == "ADRP" and GetMnem(xref+4) == "ADD" and GetMnem(xref+8) == "RET":
                        None
                xref = get_next_dref_to(ea, xref)


def parseModInitFunc(modInitFuncEA):
    modInitFuncName = getName(modInitFuncEA)
    print "[+] parseModInitFunc {:016X}".format(modInitFuncEA)
    #print "modInitFuncName: " + str(modInitFuncName)
    #print "getClassListInModInitFunc at {:016X}".format(modInitFuncEA)
    classList = getClassListInModInitFunc(modInitFuncEA)
    noVTableClasses = set()
    for classInfo in classList:
        # hello
        (gMetaClassAddr, className, parentGMetaClassAddr, parentClassName, classSize, metaClassVTStartEA) = classInfo
        #print "[+] {} in modInitFunc {:016X}".format(classInfo, modInitFuncEA)
        if None in classInfo and not None is parentClassName:
            print "[!] At", hex(modInitFuncEA), ", None in ", classInfo

        if not None is className:
            for key in classNameToParentMetaClassAddrMap.copy():
                if classNameToParentMetaClassAddrMap[key] == gMetaClassAddr:
                    classParentRecognized(key, className)

        gMetaClassName = "__ZN" + str(len(className)) + className + "10gMetaClassE"


        metaClassName = "__ZN" + str(len(className)) + className + "9metaClassE"

        metaClassVTEAName_old = getName(metaClassVTStartEA)
        metaClassVTableName = "__ZTVN" + str(len(className)) + className + "9MetaClassE"

        gMetaClassAddrOldName = getName(gMetaClassAddr)
        if not gMetaClassAddrOldName.startswith("__"):
            set_name(gMetaClassAddr, gMetaClassName)
        elif gMetaClassName != gMetaClassAddrOldName:
            raise Exception("{:016X} already had gMetaClass {}, but not {} ".format(gMetaClassAddr, gMetaClassAddrOldName, gMetaClassName))

        #if metaClassVTStartEA != None and \
        #    metaClassVTStartEA != BADADDR and \
        #    metaClassVTEAName_old != None and \
        #    (metaClassVTEAName_old.startswith("unk_") or \
        #    metaClassVTEAName_old.startswith("off_") or \
        #    metaClassVTEAName_old == metaClassVTableName):
        if metaClassVTStartEA != None and \
            metaClassVTStartEA != BADADDR:
            parseVTable(metaClassVTStartEA, className + "::MetaClass")
        #if type(gMetaClassAddr) != int:
        #    print hex(modInitFuncEA), gMetaClassAddr

        SetType(gMetaClassAddr, className + "::MetaClass")

        xrefs = getXRefsTo(gMetaClassAddr, findCodeRef=False)
        for xref in xrefs:
            segname = getSegName(xref)
            if segname.endswith("__const"):
                SetType(xref, className + "::MetaClass *")

        if parentClassName != None:
            classParentRecognized(className, parentClassName)
        else:
            classNameToParentMetaClassAddrMap[className] = parentGMetaClassAddr

        # Add class struct
        #print "[+] createClassStruct {} {}".format(className, classSize)
        classStrucId = createClassStruct(className, classSize)

        classStrucEA = GetStrucIdx(classStrucId)
        #print "classStrucId: "+ hex(classStrucId), "classStrucEA: " + hex(classStrucEA), "memberId: " + hex(GetMemberId(classStrucId, 0))
        #print ""

        set_struc_hidden(get_struc(classStrucId), 1)
        
        vtStartEA, vtEndEA = getVTableAddrOfClass(className)
        if vtStartEA == BADADDR:
            print "[!] Still unable to find vtable of {}".format(className)
            noVTableClasses.add(className)

        keepCon_VTAndVTS_ForClass(className+"::MetaClass")
        keepCon_VTAndVTS_ForClass(className)

    return classList, noVTableClasses

def getModInitFuncsForKEXT(kext):
    modinitfuncs = []
    if not kernelcache_status.isMerged:
        modInitFuncSeg = get_segm_by_name(kext+":__mod_init_func")
        if None is modInitFuncSeg:
            print "[!] {} not exist".format(kext+":__mod_init_func")
        else:
            return [Qword(ea) for ea in range(modInitFuncSeg.startEA, modInitFuncSeg.endEA, 8)]
    else:
        textstart, textend = getTextAreaForKEXT(kext)
        kmodinit_seg = get_segm_by_name("__kmod_init")
        if not None is kmodinit_seg:
            for ea in range(kmodinit_seg.startEA, kmodinit_seg.endEA, 8):
                funcea = Qword(ea)
                if funcea >= textstart and funcea < textend:
                    modinitfuncs.append(funcea)
    return modinitfuncs


def parseModInitsForKEXT(kextPrefix):
    modInitFuncs = getModInitFuncsForKEXT(kextPrefix)
    classInfoList, failedClasses = \
        parseModInitFuncs(modInitFuncs)
    for classInfo in classInfoList:
        className = classInfo[1]
        if kextPrefix:
            classNameFoundInKEXT(className, kextPrefix)
    return classInfoList, failedClasses


def parseModInitFuncSeg(modInitFuncSeg):
    segname = getSegName(modInitFuncSeg)
    kextPrefix = None
    if None is segname:
        return 
    if ":" in segname:
        kextPrefix = segname[:segname.find(":")]
    classInfoList = []
    if not None is modInitFuncSeg:
        modInitFuncs = [Qword(ea) for ea in range(modInitFuncSeg.startEA, modInitFuncSeg.endEA, 8)]
        classInfoList, failedClasses = \
            parseModInitFuncs(modInitFuncs)
        for classInfo in classInfoList:
            className = classInfo[1]
            if kextPrefix:
                classNameFoundInKEXT(className, kextPrefix)
    return classInfoList, failedClasses

def parseModInitsForAll(ignorePhaseDone=True):
    phase = "parseModInitsForAll"
    if not ignorePhaseDone and checkPhaseDone(phase):
        return
    print "[+] Parse All ModInitFunc Segments"

    segs = getAllSegsOfMODINITFUNC()
    segs.extend(getAllSegsOfKMODINIT())
    classInfoList = []
    failedClasses = set()
    for seg in segs:
        segname = getSegName(seg)
        if not (segname.startswith("__DATA_CONST:") or segname.startswith("__DATA:")):
            c, f = parseModInitFuncSeg(seg)
            classInfoList.extend(c)
            failedClasses.update(f)

    segs = getAllSegsOfKMODINIT()
    for seg in segs:
        parseModInitFuncSeg(seg)
        classInfoList.extend(c)
        failedClasses.update(f)

    parsedClassNameSet = set()
    for className in list(classNameToParentMetaClassAddrMap):
        parentMetaClassAddr = classNameToParentMetaClassAddrMap[className]
        name = getName(parentMetaClassAddr)
        if (name is not None) and not name.startswith("unk_"):
            parentMetaClassName =  Demangle(name, GetLongPrm(INF_SHORT_DN))
            if parentMetaClassName != None:
                parentClassName = parentMetaClassName[:parentMetaClassName.rfind("::")]
                classParentRecognized(className, parentClassName)
                parsedClassNameSet.add(className)
    for className in parsedClassNameSet:
        if className in classNameToParentMetaClassAddrMap:
            classNameToParentMetaClassAddrMap.pop(className)

    storeNecessaryClassInfoInPersistNode()
    markPhaseDone(phase)
    return classInfoList, failedClasses




def parseAllKnownVTablesByName():
    phase = "parseAllKnownVTablesByName"
    if checkPhaseDone(phase):
        return
    print "[+] Parse All Predefined VTables"
    # VTables in __DATA_CONST:__const are organized in a different way like other kexts
    names = Names()
    for nameTuple in names:
        ea = nameTuple[0]
        name = nameTuple[1]
        demangledName = Demangle(nameTuple[1], INF_SHORT_DN)
        if demangledName != None and demangledName.startswith("`vtable for'"):
            demangledClassName = demangledName[len("`vtable for'"):]
            segName = getSegName(ea)
            #if (segName.endswith("__const") or segName.endswith("__data")) and not demangledClassName.endswith("::MetaClass"): 
            if segName == "__DATA_CONST:__const" or segName == "__DATA:__const" or segName == "__const":
            #print hex(nameTuple[0]), nameTuple[1], Demangle(nameTuple[1], INF_SHORT_DN)
                vtableStartEA = ea + 16
                parseVTable(vtableStartEA, demangledClassName, fromSymbol=True)
                predefinedClassNameSet.add(demangledClassName)
    markPhaseDone(phase)

print "[+] Arm64ClassAndVTableFinder loaded"
