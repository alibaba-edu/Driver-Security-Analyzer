# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
from idaapi import *
from idc import *
from idautils import *
require("idaapi")
import time
from enum import Enum
import graphviz
import plistlib
from capstone import *

from UtilClasses import *
idaapi.require("UtilClasses")

from HeaderClangParser import *
idaapi.require("HeaderClangParser")

import netnode as m_netnode

import logging
logger = logging.getLogger(__name__)

# Never call require require("globalData")
from globalData import *

import sys
thisScriptFilePath = os.path.realpath(__file__)
ida_kernelcache_path = os.path.join(os.path.dirname(thisScriptFilePath), "../ida_kernelcache/ida_kernelcache")
# uses some functionalities from ida_kernelcache, e.g., for untagging pointers, forcing IDA pro to recognize functions, etc.
sys.path.insert(0, ida_kernelcache_path) 

thisScriptFilePath = os.path.realpath(__file__)
batchCmdsPath = os.path.join(os.path.dirname(thisScriptFilePath), "../batch")
sys.path.insert(0, batchCmdsPath) 

resultsDirPath = os.path.join(os.path.dirname(thisScriptFilePath), "../results")
logsDirPath = os.path.join(os.path.dirname(thisScriptFilePath), "../logs")
dataDirPath = os.path.join(os.path.dirname(thisScriptFilePath), "../data")

idaapi.require("batchUtils")

#DEBUG = True
DEBUG = False

'''
o_void = 0
o_reg = 1
o_mem = 2
o_phrase = 3
o_displ = 4
o_imm = 5
o_far = 6
o_near = 7
o_idpspec0 = 8
o_idpspec1 = 9
o_idpspec2 = 10
o_idpspec3 = 11
o_idpspec4 = 12
o_idpspec5 = 13
'''

def GetMnem_wrapper(ea):
    mnem = idc.GetMnem(ea)
    if not None is mnem:
        mnem = mnem.upper()
    return mnem


def SetOrAddMemberName(sid, offset, name):
    memberId = GetMemberId(sid, offset)
    if memberId == -1 or memberId == BADADDR:
        return AddStrucMember(sid, name, offset, qwrdflag(), -1, 8)
    else:
        return idc.SetMemberName(sid, offset, name)


def getFilePathWithRelPath(relPath):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), relPath)

def getName(ea):
    if isEAValid(ea):
        version = getVersionNumber()
        if version>=7.0:
            return get_name(ea)
        return Name(ea)
    return ida_struct.get_member_name(ea)

def getDeNameAtEA(ea):
    mangledName = getName(ea)
    demangledName = Demangle(mangledName, GetLongPrm(INF_LONG_DN))
    #if None is demangledName :
    #    return mangledName
    return demangledName

def getDeFuncNameAtEA(ea):
    mangledName = getName(ea)
    return getDeFuncNameOfName(mangledName)

def getDeNameOfName(mangledName):
    demangledName = Demangle(mangledName, GetLongPrm(INF_LONG_DN))
    return demangledName

def getDeFuncNameOfName(mangledName):
    demangledName = Demangle(mangledName, GetLongPrm(INF_LONG_DN))
    if None is demangledName or "(" not in demangledName:
        return None
        #return mangledName.split("(")[0]
    return demangledName.split("(")[0]

def isUserDefinedName(name):
    for nameTuple in Names():
        if name == nameTuple[1]:
            f = idc.GetFlags(nameTuple[0])
            if idc.hasUserName(f):
                return nameTuple[0]
            else:
                return None

import ida_utilities

def setFuncName(ea, name, flags=0):
    orignalName = getName(ea)
    if orignalName != "___cxa_pure_virtual":
        forceFunction(ea)
        return idc.set_name(ea, name, flags)
    return 0

def forceFunction(ea):
    if isBinaryArm64():
        ret = ida_utilities.force_function(ea)
        if not ret:
            next_func = get_next_func(ea)
            if not None is next_func:
                for current_ea in range(ea, next_func.startEA, 4):
                    MakeCode(current_ea)
                    None
            ret = ida_utilities.force_function(ea)
        return ret

def setFuncType(ea, funcType):
    if (None is funcType) or funcType == "":
        return 0
    if ea in confirmedFuncTypes:
        return 1
    funcTypeTinfo = getTinfoForTypeStr(funcType)
    if (None is funcTypeTinfo) or (not funcTypeTinfo.is_func()):
        return 0
    orignalName = getName(ea)
    if orignalName != "___cxa_pure_virtual":
        forceFunction(ea)
        return SetType(ea, funcType)
    return 0

def setNameOverride(ea, name):
    if getName(ea) == name:
        return True
    userDefinedNameEA = isUserDefinedName(name)
    if userDefinedNameEA != None:
        set_name(userDefinedNameEA, "")
    return set_name(ea, name)

def setName(ea, name, flag=0, isoverride=False):
    if isoverride:
        return setNameOverride(ea, name)
    else:
        return set_name(ea, name, flag)


def SetOrAddMemberNameOverride(strucId, offset, name):
    member = get_member_by_name(get_struc(strucId), name)
    if not None is member:
        name += str(offset/8)
    SetOrAddMemberName(strucId, offset, name)

def findFirstNameInMangledName(mangledName, startPos=0):
    return firstNameLen, chCnt


def replaceClassInMangledName(mangledName, new):
    mangledNameLen = len(mangledName)
    chCnt = 0
    isFirst = True
    mangledNamePrefix = ""
    prevNameEndPos = 0
    while chCnt == 0 or (ord(mangledName[chCnt])>= ord("0") and ord(mangledName[chCnt]) <= ord("9")):
        prevNameEndPos = chCnt
        while chCnt < mangledNameLen:
            ch = mangledName[chCnt]
            if ord(ch) >= ord("0") and ord(ch) <= ord("9"):
                break
            chCnt += 1
        nameLenStartPos = chCnt
        nameLenStr = ""
        while chCnt < mangledNameLen:
            ch = mangledName[chCnt]
            if ord(ch) < ord("0") or ord(ch) > ord("9"):
                break
            else:
                nameLenStr = nameLenStr + ch
            chCnt += 1
        nameLen = int(nameLenStr)
        chCnt += nameLen
        if isFirst:
            mangledNamePrefix = mangledName[:nameLenStartPos]
            isFirst = False
    if mangledName[chCnt] == "D" or mangledName[chCnt] == "C":
        mangledNameSuffix = mangledName[chCnt:]
    else:
        mangledNameSuffix = mangledName[prevNameEndPos:]

    newName = mangledNamePrefix + getMangledNameOfName(new) + mangledNameSuffix
    return newName


thisFileType = idaapi.get_file_type_name().strip()
thisFilePath = idc.get_idb_path()
thisFileName = os.path.basename(thisFilePath)
idbFilePath = thisFilePath
idbFileName = thisFileName
modulename = idbFileName[:-4]


def rebuildAllInternalDataWOParseModInitFunc(ignoreInheritance=False):

    print "[+] Rebuild All Internal Data Structures Without Parsing ModInitFunc Segments"
    #print "rebuildAllInternalDataWOParseModInitFunc called"
    
    global classNameToParentClassNameMap
    global classNameToParentMetaClassAddrMap
    global classNameToVTableAddrMap 
    global classNameToVTableStructIdMap 
    global classNameToClassStructIdMap 
    global predefinedStructNameToIdMap 
    global classNameToVTableFuncEAListMap 
    global virtualFuncEASet 
    global predefinedClassNameSet 
    global classNameToWholeVTableStructIdMap 
    global classNameToChildClassNameSetMap 
    global classNameToVirtualCFuncInfoMap 
    global funcEAToCFuncMap

    names = Names()

    for nameTuple in names:
        ea = nameTuple[0]
        name = nameTuple[1]
        demangledName = Demangle(nameTuple[1], INF_SHORT_DN)

        if demangledName != None and demangledName.endswith("::superClass"):
            childClassName = demangledName[:-12]
            superClassGMetaClassName = getName(Qword(ea))
            if not (Qword(ea) == 0 or None is superClassGMetaClassName):
                demangledSuperClassGMetaClassName = Demangle(superClassGMetaClassName, INF_SHORT_DN)
                superClassName = demangledSuperClassGMetaClassName[:-12]
                classParentRecognized(childClassName, superClassName)
        elif demangledName != None and demangledName.endswith("::gMetaClass"):
            className = demangledName[:-12]
            segName = get_segm_name(ea)
            if segName.endswith(":__common"):
                moduleName = segName[:-9]
                classNameFoundInKEXT(className, moduleName)
        elif demangledName != None and demangledName.startswith("`vtable for'"):
            demangledClassName = demangledName[len("`vtable for'"):]
            vtableStructName = "vtable_" + demangledClassName

            #TODO there should be other file types including arm and x86
            classStrucName = None
            classStrucId = BADADDR
            classStrucName = demangledClassName
            if not None is classStrucName:
                classStrucId = GetStrucIdByName(classStrucName)

            wholeVTableStructName = "whole_vtable_" + demangledClassName
            segName = get_segm_name(ea)
            #if (segName.endswith("__const") or segName.endswith("__data")): 
            if segName == "__DATA_CONST:__const" or segName == "__const" or segName == "__DATA:__const":
                if not None is predefinedClassNameSet:
                    predefinedClassNameSet.add(demangledClassName)
            vtableStartEA = ea + 16
            wholeVTableStartEA = ea
            vtableStructId = GetStrucIdByName(vtableStructName)
            if vtableStructId == BADADDR or segName == "UNDEF":
                continue
            vtableStructSize = GetStrucSize(vtableStructId)
            vtableEndEA = vtableStartEA + vtableStructSize
            vtableFuncEAList = []
            vtableEA = vtableStartEA
            while vtableEA < vtableEndEA:
                funcEA = Qword(vtableEA)
                vtableFuncEAList.append(funcEA)
                if not None is virtualFuncEASet:
                    virtualFuncEASet.add(funcEA)
                vtableEA = vtableEA + 0x8

            if not None is classNameToVTableAddrMap:
                classNameToVTableAddrMap[demangledClassName] = (vtableStartEA, vtableEndEA)
            
            if not None is classNameToVTableStructIdMap:
                classNameToVTableStructIdMap[demangledClassName] = vtableStructId 

            if not None is classNameToVTableFuncEAListMap:
                classNameToVTableFuncEAListMap[demangledClassName] = vtableFuncEAList

            if not None is classNameToClassStructIdMap and classStrucId != BADADDR:
                classNameToClassStructIdMap[demangledClassName] = classStrucId

            #if demangledClassName.endswith("::MetaClass"):
            #    continue

            if not ignoreInheritance:
                if segName != "__DATA_CONST:__const" and segName != "__DATA:__const":
                    # VTables in __DATA_CONST:__const are organized in a different way like other kexts, no gMetaClass preceeding the vtable
                    parentMetaClassName =  Demangle(getName(Qword(wholeVTableStartEA-0x8)), GetLongPrm(INF_SHORT_DN))
                    #print hex(wholeVTableStartEA-0x8), parentMetaClassName
                    if parentMetaClassName != None:
                        parentClassName = parentMetaClassName[:parentMetaClassName.rfind("::")]
                        classParentRecognized(demangledClassName, parentClassName)

def storeClassParentInPersistNode(className, parentClassName):
    persistParentClassNames = getPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES)
    persistParentClassNames[className] = parentClassName
    setPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES, persistParentClassNames)


def classParentRecognized(className, parentClassName):
    global classNameToParentClassNameMap, classNameToChildClassNameSetMap
    if not None is classNameToParentClassNameMap:
        classNameToParentClassNameMap[className] = parentClassName
    if not None is classNameToChildClassNameSetMap:
        if parentClassName not in classNameToChildClassNameSetMap:
            classNameToChildClassNameSetMap[parentClassName] = set()
        classNameToChildClassNameSetMap[parentClassName].add(className)
    if className in classNameToParentMetaClassAddrMap:
        classNameToParentMetaClassAddrMap.pop(className)
    #storeClassParentInPersistNode(className, parentClassName)


def rename_stub(ea):
    if isBinaryArm64():
        if not (ua_mnem(ea) == 'ADRP' and ua_mnem(ea + 4) == 'LDR' and ua_mnem(ea + 8) == 'BR'):
            #print("Not a stub function @ 0x{:x}??".format(ea))
            return
    #print "rename_stub {:016X}".format(ea)

    forceFunction(ea)

    changed_name = False
    changed_type = False

    page = get_immvals(ea, 1)[0]
    offset = get_immvals(ea + 4, 1)[0]
    target_func = get_qword(page + offset)

    name = getName(target_func)
    if name and not name.startswith('sub_') and not name.startswith('loc_'):

        seg_num = get_segm_num(ea)
        new_name = name + '_' + str(seg_num)
        if getName(ea) != new_name:
            # We now use seg number to count the suffix
            set_name(ea, new_name, SN_FORCE)

        # Add a comment to easily navigate to the called function from the stub
        set_cmt(ea + 8, name, 0)

        changed_name = True

    func_type = print_type(target_func, 0)
    if func_type:
        changed_type = apply_cdecl(None, ea, func_type + ';')

    #print("{:x}: {} {}".format(ea, "y" if changed_name else "n", "y" if changed_type else "n"))

def keepCon_ItemAndGOTItem(itemEA, gotLocEA, keepNameCon=True, keepTypeCon=True):
    gotSegNum = get_segm_num(gotLocEA)
    itemName = getName(itemEA)
    itemSegName = get_segm_name(itemEA)
    if itemSegName.endswith("__text"):
        forceFunction(itemEA)
    
    if keepNameCon:
        #print itemName
        #if not None is itemName and not itemName.startswith("unk_") and not itemName.startswith("off_"):
        if not None is itemName and itemName.startswith("_"):
            set_name(gotLocEA, itemName + "_ptr_" + str(gotSegNum), SN_FORCE)
        else:
            set_name(gotLocEA, "")
    objTinfo = getTinfoAtEA(itemEA)
    if keepTypeCon:
        if not None is objTinfo:
            objPtrTinfo = tinfo_t()
            objPtrTinfo.create_ptr(objTinfo)
            ida_nalt.set_tinfo(gotLocEA, objPtrTinfo)
    if is_func(GetFlags(itemEA)):
        xref = get_first_dref_to(gotLocEA)
        while xref != None and xref != BADADDR:
            xrefSegName = get_segm_name(xref)
            if xrefSegName.endswith("__stubs"):
                if isBinaryArm64() and GetMnem(xref) == "ADRP":
                    xref_func_startEA = xref
                    #if not getName(xref_func_startEA).startswith(itemName):
                    rename_stub(xref_func_startEA)
                    if not None is objTinfo:
                        ida_nalt.set_tinfo(xref_func_startEA, objTinfo)

            xref = get_next_dref_to(gotLocEA, xref)

def keepCon_ItemAndGOTs(itemEA, keepNameCon=True, keepTypeCon=True):
    xref = get_first_dref_to(itemEA)
    while xref != None and xref != BADADDR:
        segName = get_segm_name(xref)
        if segName.endswith("__got"):
            keepCon_ItemAndGOTItem(itemEA, xref, keepNameCon, keepTypeCon)
        xref = get_next_dref_to(itemEA, xref)

def keepAllCon_VTAndVTS():
    for className in classNameToVTableAddrMap:
        keepCon_VTAndVTS_ForClass(className)

def keepCon_VTAndVTS_ForClass(className):
    (vtableStartEA, vtableEndEA) = getVTableAddrOfClass(className)
    #print "keepCon_VTAndVTS_ForClass {} {:016X} {:016X}".format(className, vtableStartEA, vtableEndEA)
    vtableStructId = getVTableStructIdOfClass(className)
    if vtableStructId == BADADDR or vtableStartEA == BADADDR:
        return
    vtableEA = vtableStartEA
    while vtableEA < vtableEndEA:
        offset = vtableEA - vtableStartEA
        funcEA = Qword(vtableEA)
        funcName = getName(funcEA)  
        AddStrucMember(vtableStructId, "member" + str(offset/8), offset, qwrdflag(), -1, 8)
        memberId = GetMemberId(vtableStructId, offset)
        keepCon_VFuncAndVTSMember(funcEA, vtableStructId, offset, True, True)
        vtableEA = vtableEA + 0x8

def addXref(xrefFrom, xrefTo, flag, isData=True):
    if xrefFrom != 0 and xrefTo != 0:
        existXref = get_first_dref_from(xrefFrom)
        while existXref != None and existXref != BADADDR:
            if existXref == xrefTo:
                return
            existXref = get_next_dref_from(xrefFrom, existXref)
        try:
            if isData:
                add_dref(xrefFrom, xrefTo, flag)
            else:
                add_cref(xrefFrom, xrefTo, flag)
        except Exception as e:
            None

def keepCon_VFuncAndVTSMember(funcEA, vtableStructId, offset, keepNameCon=True, keepTypeCon=True, isFromFuncToMember = True):
    #print "keepCon_VFuncAndVTSMember", offset, funcEA
    memberId = GetMemberId(vtableStructId, offset)
    memberName = ida_struct.get_member_name(memberId)
    funcName = getName(funcEA)  
    addXref(memberId, funcEA, 1)
    addXref(funcEA, memberId, 1)
    if None is funcName:
        #print "keepCon_VFuncAndVTSMember funcName None {} {} 0x{:016X}".format(vtableStructId, offset, funcEA)
        return
    if funcName.startswith("___cxa_pure_virtual") or funcName.startswith("nullsub_"):
        return
    if isFromFuncToMember:
        SetMemberComment(vtableStructId, offset, hex(funcEA), 1)
        if keepNameCon:
            if memberName != funcName and memberName != None and memberName.replace("::", "__") != funcName:
                SetOrAddMemberNameOverride(vtableStructId, offset, funcName)

        if keepTypeCon:
            funcTinfo = getTinfoAtEA(funcEA)
            if None is funcTinfo:
                #print "[!] keepCon_VFuncAndVTSMember {:016X} funcTinfo None".format(funcEA)
                return
            funcPtrTinfo = tinfo_t()
            funcPtrTinfo.create_ptr(funcTinfo)
            SetType(memberId, str(funcPtrTinfo))
            #funcType = GetType(funcEA)
            #if funcType != None:
            #    funcTypeArgStartLoc = funcType.find("(")
            #    funcPTRType = funcType[:funcTypeArgStartLoc] + "(*)" +  funcType[funcTypeArgStartLoc:]
            #    SetType(memberId, funcPTRType)
    else:
        if keepNameCon:
            if memberName != funcName and memberName != None and memberName.replace("::", "__") != funcName:
                demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
                # We do not want to change func name if it has a mangled name
                if None is demangledFuncName:
                    setNameOverride(funcEA, memberName);
                    addXref(memberId, funcEA, 1)
                    addXref(funcEA, memberId, 1)

        if keepTypeCon:
            funcName = getName(funcEA)  
            funcPTRType = GetType(memberId)
            if funcType != None:
                funcPTRStartLoc = funcPTRType.find("(")
                funcPTREndLoc = funcPTRType.find(")")
                funcType = funcPTRType[:funcPTRStartLoc] + " " + funcName + " " +  funcPTRType[funcPTREndLoc + 1:]
                SetType(funcEA, funcType)

def getAllParentVirtualFuncAtOffset(className, funcEA, offset):
    parentVirtualFuncEAToClassNameMap = {}
    while className in classNameToParentClassNameMap and className != None and className != "OSObject" and offset != -1:
        parentClassName = classNameToParentClassNameMap[className]
        if parentClassName in classNameToVTableAddrMap:
            parentVTableStartEA, parentVTableEndEA = classNameToVTableAddrMap[parentClassName]
            if parentVTableStartEA + offset < parentVTableEndEA:
                parentFuncEA = Qword(parentVTableStartEA + offset)
                if parentFuncEA != funcEA:
                    parentVirtualFuncEAToClassNameMap[parentFuncEA] = parentClassName
        className = parentClassName
    return parentVirtualFuncEAToClassNameMap

def getAllChildVirtualFuncAtOffset(className, funcEA, offset):
    childVirtualFuncEAToClassNameMap = {}
    if not None is className and className in classNameToChildClassNameSetMap and offset != -1:
        childClassNameSet = classNameToChildClassNameSetMap[className]
        for childClassName in childClassNameSet:
            if childClassName in classNameToVTableAddrMap:
                childVTableStartEA, childVTableEndEA = classNameToVTableAddrMap[childClassName]
                if childVTableStartEA + offset < childVTableEndEA:
                    childFuncEA = Qword(childVTableStartEA + offset)
                    if childFuncEA != funcEA and getName(funcEA) != "___cxa_pure_virtual":
                        childVirtualFuncEAToClassNameMap[childFuncEA] = childClassName
                    childMapForChild = getAllChildVirtualFuncAtOffset(childClassName, childFuncEA, offset)
                    childVirtualFuncEAToClassNameMap.update(childMapForChild)
    return childVirtualFuncEAToClassNameMap

def getAllChildMemberIdAtOffset(className, offset):
    childMemberIdToClassStructIdMap = {}
    if not None is className and className in classNameToChildClassNameSetMap and offset != -1:
        childClassNameSet = classNameToChildClassNameSetMap[className]
        for childClassName in childClassNameSet:
            if childClassName in classNameToClassStructIdMap:
                childClassStructId = classNameToClassStructIdMap[childClassName]
                if childClassStructId != BADADDR:
                    childClassStructSize = get_struc_size(childClassStructId)
                    if offset < childClassStructSize:
                        memberId = GetMemberId(childClassStructId, offset)
                        childMemberIdToClassStructIdMap[memberId] = childClassStructId 
                        childMapForChild = getAllChildMemberIdAtOffset(childClassName, offset)
                        childMemberIdToClassStructIdMap.update(childMapForChild)
    return childMemberIdToClassStructIdMap

def keepAllConsistency_AncestorToDescendant():
    None

def keepAllCon_ParentAndChild():
    for className in classNameToVTableAddrMap:
        keepCon_ParentAndChildren(className)

def keepCon_ParentAndChildren(className):
    if className in classNameToVTableAddrMap:
        (vtableStartEA, vtableEndEA) = classNameToVTableAddrMap[className]
        vtableEA = vtableStartEA
        if className in classNameToParentClassNameMap:
            parentClassName = classNameToParentClassNameMap[className]
            if parentClassName in classNameToVTableAddrMap:
                (parentVTableStartEA, parentVTableEndEA) = classNameToVTableAddrMap[parentClassName]
                # only process the methods defined by itself
                vtableEA = vtableStartEA + (parentVTableEndEA - parentVTableStartEA)
        while vtableEA < vtableEndEA:
            offset = vtableEA - vtableStartEA
            funcEA = Qword(vtableEA)
            funcName = getName(funcEA)  
            keepCon_ParentAndChildrenVTableAtOffset(className, funcEA, offset, True, True)
            vtableEA = vtableEA + 0x8


def keepCon_ParentAndChildrenClassStructAtOffset(parentClassName, offset, keepNameCon, keepTypeCon):
    #print "keepCon_ParentAndChildrenClassStructAtOffset", parentClassName, hex(offset)
    if parentClassName != None and parentClassName in classNameToClassStructIdMap:
        childMemberIdToClassStructIdMap = getAllChildMemberIdAtOffset(parentClassName, offset)
        parentClassStructId = classNameToClassStructIdMap[parentClassName]
        parentClassStruct = get_struc(parentClassStructId)
        member = idaapi.get_member(parentClassStruct, offset)
        if None is member:
            #print "member is None", parentClassName, hex(offset)
            return
        memberName = ida_struct.get_member_name(member.id)
        if keepNameCon and not (memberName is None or memberName.startswith("member") or memberName.startswith("field")):
            for childMemberId in childMemberIdToClassStructIdMap:
                childClassStructId = childMemberIdToClassStructIdMap[childMemberId]
                childMemberName = ida_struct.get_member_name(childMemberId)
                if childMemberName.startswith("member") or childMemberName.startswith("field"):
                    childMemberNewName = memberName
                    SetOrAddMemberName(childClassStructId, offset, childMemberNewName)
                    #print "SetOrAddMemberName", hex(childClassStructId), hex(offset), childMemberNewName
        memberType = GetType(member.id)
        if keepTypeCon and not None is memberType:
            for childMemberId in childMemberIdToClassStructIdMap:
                childClassStructId = childMemberIdToClassStructIdMap[childMemberId]
                childMemberType = GetType(childMemberId)
                if None is childMemberType:
                    childMemberNewType = memberType
                    SetType(childMemberId, childMemberNewType)

def keepCon_ParentAndChildrenVTableAtOffset(parentClassName, funcEA, offset, keepNameCon, keepTypeCon):
    if parentClassName != None:
        childVirtualFuncEAToClassNameMap = getAllChildVirtualFuncAtOffset(parentClassName, funcEA, offset)
        funcName = getName(funcEA)
        if None is funcName:
            #print "keepCon_ParentAndChildrenVTableAtOffset funcName None {} {} 0x{:016X}".format(parentClassName, offset, funcEA)
            return
        #if None is funcName:
        #    print "parentClassName {}, 0x{:016X} name None".format(parentClassName, funcEA)
        demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
        if keepNameCon and funcName != "___cxa_pure_virtual" and not funcName.startswith("sub_"):
            for childFuncEA in childVirtualFuncEAToClassNameMap:
                childFuncName = getName(childFuncEA)
                childClassName = childVirtualFuncEAToClassNameMap[childFuncEA]
                childFuncNewName = None
                if demangledFuncName != None:
                    childFuncNewName = replaceClassInMangledName(funcName, childClassName)
                elif "::" in funcName:
                    #childFuncNewName = funcName.replace(parentClassName, childClassName)
                    childFuncNewName = childClassName + funcName[funcName.rfind("::"):]
                if not None is childFuncNewName and childFuncNewName != childFuncName and childFuncName != "___cxa_pure_virtual":
                    set_name(childFuncEA, childFuncNewName)
                    #print "keepCon_ParentAndChildrenVTableAtOffset", parentClassName, hex(funcEA), funcName, hex(offset), hex(childFuncEA), childClassName

        if keepTypeCon and funcName != "___cxa_pure_virtual" :
            funcType = GetType(funcEA)
            # in some conditions, we can not know the parent func type but we can know the child func type, 
            # in these cases, we should first set the parent func type for propagation
            arglist = parseFuncTypeToGetArglist(funcType)
            if len(arglist) > 0 and not (arglist[0].startswith(parentClassName+"*") or arglist[0].startswith(parentClassName+" *")):
                arglist.insert(0, parentClassName + "*" + "this")
            for childFuncEA in childVirtualFuncEAToClassNameMap:
                childFuncClassName = childVirtualFuncEAToClassNameMap[childFuncEA]
                childFuncType = GetType(childFuncEA)
                childFuncName = getName(childFuncEA)
                childDemangledFuncName = Demangle(childFuncName, GetLongPrm(INF_LONG_DN))
                if None is childDemangledFuncName and childFuncName != "___cxa_pure_virtual":
                    childFuncArgList = parseFuncTypeToGetArglist(childFuncType)
                    # propagate parent func type only when the parent func has more args than children
                    if len(arglist) > len(childFuncArgList):
                        childFuncNewType = funcType.replace(parentClassName, childFuncClassName)
                        childFuncNewTypeArgStartLoc = childFuncNewType.find("(")
                        childFuncNewType = childFuncNewType[:childFuncNewTypeArgStartLoc] + " " + childFuncClassName + childFuncNewType[childFuncNewTypeArgStartLoc:]
                        if childFuncType != childFuncNewType:
                            SetType(childFuncEA, childFuncNewType)


def keepAllConsistency():
    print "[+] Keep Everything in consistency"
    # Too many problems, should not be used
    # print classNameToParentClassNameMap
    keepAllCon_VTAndVTS()
    keepAllCon_ParentAndChild()
 
def splitArgString(argString):
    bracketCnt = 0
    arglist = []
    currentArg = ""
    if argString == "" or argString == "void":
        return []
    argString = argString + ","
    for i in range(0, len(argString)):
        ch = argString[i]
        if ch == ",":
            if bracketCnt == 0:
                if not getTinfoForTypeStr(currentArg).is_well_defined():
                    if currentArg == "void":
                        continue
                    elif "(*)" in currentArg:
                        funcPtr = currentArg
                        funcPtrArgStr = funcPtr[funcPtr.find("(*)")+3:]
                        funcPtrArgStr = funcPtrArgStr[funcPtrArgStr.find("(")+1:funcPtrArgStr.rfind(")")]
                        funcPtrArgList = splitArgString(funcPtrArgStr)
                        newFuncPtrArgStr = ", ".join(funcPtrArgList)
                        currentArg = funcPtr[:funcPtr.find("(*)")+3] + "(" + newFuncPtrArgStr + ")"
                    elif currentArg[-1] == "*":
                        currentArg = "void * " + currentArg[:currentArg.find("*")].replace("::", "__")
                    else:
                        currentArg = "uint64_t " + currentArg.replace("::", "__")
                currentArg = currentArg.strip()
                arglist.append(currentArg)
                currentArg = ""
                continue
        elif ch == "(":
            bracketCnt += 1
        elif ch == ")":
            bracketCnt -= 1
        currentArg = currentArg + ch

    return arglist

def parseFuncTypeToGetArglist(funcType):
    className, pureFuncName, arglist = parseFuncProtoWORet(funcType)
    return arglist


def convertArgStringToArgType(argString):
    argString = argString.strip()
    idx = len(argString)-1
    if ")" in argString:
        return argString[:argString.rfind(")")+1]
    elif "*" in argString:
        return argString[:argString.rfind("*")+1]
    elif " " in argString:
        return argString[:argString.rfind(" ")].strip()
    else:
        return argString

def convertArgStringListToArgTypeList(argStringList):
    argTypeList = list()
    for argString in argStringList:
        argTypeList.append(convertArgStringToArgType(argString))
    return argTypeList
    None

'''
class VarType:
    def __init__(self, typeString):
        typeString = typeString.strip()
        self.typeString = typeString
        self.tinfo = getTinfoForTypeStr(typeString)
    def __str__(self):
        if not None is self.tinfo:
            return str(self.tinfo)
        else:
            if self.typeString.endswith("*"):
                return "void " + self.typeString[self.typeString.find("*"):]
            else:
                return "uint64_t"
'''

def convertUnknownArgType(argType):
    #print "[?] Unknown arg: %s"%(argType)
    return "void *" + argType.replace(" ", "").replace("*", "_").replace(":", "_").replace("&", "_").replace(".", "_")

def repairUnknownFuncPTRTypeString(funcPTRType):
    newFuncPTRType = None
    if "(*)" in funcPTRType:
        if funcPTRType.count("(*)") > 1:
            print "[?] Can not repair func pointer type: %s"%(funcPTRType)
        idx =funcPTRType.find("(*)")
        funcType = funcPTRType[:idx] + funcPTRType[idx+3:]
        funcRetType = funcType[:funcType.find("(")]
        argString = funcType[funcType.find("(")+1:funcType.find(")")]
        argStringList = argString.split(",")
        for i in range(0, len(argStringList)):
            arg = argStringList[i]
            argTinfo = getTinfoForTypeStr(arg)
            if None is argTinfo:
                argStringList[i] = convertUnknownArgType(arg)
        newFuncPTRType = funcRetType + " (*)" + "(" + ",".join(argStringList) +  ")"
    else:
        print "[?] Can not repair func pointer type: %s"%(funcPTRType)
    return newFuncPTRType

def parseFuncProtoWORet(funcProtoWORet, isNonStatic=False, knownClassName = None, isThisIncluded=False):
    arglist = []
    demangledClassName = None
    demangledFuncName = None
    #print "funcProtoWithDummyRet:" + funcProtoWithDummyRet
    if funcProtoWORet != None:
        funcProtoWithDummyRet = "void " + funcProtoWORet
        funcProtoWORetWithoutArgs = funcProtoWORet[:funcProtoWORet.find("(")]
        if "::" in funcProtoWORetWithoutArgs:
            demangledClassName = funcProtoWORetWithoutArgs[:funcProtoWORetWithoutArgs.rfind("::")]
            demangledFuncName = funcProtoWORetWithoutArgs[funcProtoWORetWithoutArgs.rfind("::")+2:]
        else:
            demangledFuncName = funcProtoWORetWithoutArgs
        
        funcTinfoWithDummyRet = getTinfoForTypeStr(funcProtoWithDummyRet)

        if not None is funcTinfoWithDummyRet:
            nargs = funcTinfoWithDummyRet.get_nargs()
            for cnt in range(0, nargs):
                arglist.append(str(funcTinfoWithDummyRet.get_nth_arg(cnt)))
        else:
            if funcProtoWORet.find("(") < funcProtoWORet.rfind(")"):
                strOfArgs = funcProtoWORet[funcProtoWORet.find("(")+1:funcProtoWORet.rfind(")")]
                argStringList = []
                bracketLevel = 0
                lastIdx = -1
                isFuncPTR = False
                for i in range(0, len(strOfArgs)):
                    ch = strOfArgs[i]
                    if ch == "(":
                        bracketLevel += 1
                    elif ch == ")":
                        bracketLevel -= 1
                    elif ch == ",":
                        if bracketLevel == 0:
                            arg = strOfArgs[lastIdx+1:i]
                            argTinfo = getTinfoForTypeStr(arg)
                            if None is argTinfo:
                                if isFuncPTR:
                                    arg = repairUnknownFuncPTRTypeString(arg)
                                    if not arg:
                                        arg = "void *"
                                else:
                                    arg = convertUnknownArgType(arg)
                            arglist.append(arg)

                            lastIdx = i
                            isFuncPTR = False
                        else:
                            isFuncPTR = True


        if demangledClassName is None:
            demangledClassName = knownClassName


        if isNonStatic and demangledClassName != None:
            #and (len(arglist) == 0 or (arglist[0] != demangledClassName + "*" and arglist[0] != demangledClassName + " *")):
            thisType = demangledClassName + " *" + "this"
            if len(arglist) > 0:
                arg0Tinfo = getTinfoForTypeStr(arglist[0])
                if not None is arg0Tinfo and arg0Tinfo.is_ptr():
                    arg0ObjTinfo = arg0Tinfo.get_pointed_object()
                    if arg0ObjTinfo.is_struct():
                        arg0_pointed_obj_typestr = str(arg0ObjTinfo).strip()
                        if arg0_pointed_obj_typestr.startswith("struct "):
                            arg0_pointed_obj_typestr = arg0_pointed_obj_typestr[7:].strip()
                        if isClassDescendantOfClass(demangledClassName, arg0_pointed_obj_typestr):
                            arglist[0] = thisType

            if isThisIncluded:
                if len(arglist) == 0:
                    arglist.append(thisType)
                else:
                    arglist[0] = thisType
            else:
                if len(arglist) == 0 or (not (isTypeStrEqual(arglist[0], thisType))):
                    arglist.insert(0, thisType)
    
    return demangledClassName, demangledFuncName, arglist

def isTypeStrEqual(typeStr1, typeStr2):
    tinfo1 = getTinfoForTypeStr(typeStr1)
    tinfo2 = getTinfoForTypeStr(typeStr2)   
    if (not tinfo1) or (not tinfo2):
        return False
    return tinfo1 == tinfo2

def logMessage(message, logFile=None):
    if None is logFile:
        logFile = globalLogFile
    logFile.write(message + "\n")
    #print message

def generateClassHierachyGraph(parentClassName, depth):
    if len(classNameToChildClassNameSetMap) == 0:
        rebuildAllInternalDataWOParseModInitFunc()
    classNameList = []
    classNameList.append((parentClassName, depth))
    while len(classNameList) != 0:
        className, curDepth = classNameList.pop()
        if className in classNameToChildClassNameSetMap:
            childClassNameSet = classNameToChildClassNameSetMap[className]
            for childClassName in childClassNameSet:
                classNameList.append((childClassName, curDepth+1))
        logMessage(" |"*curDepth + "--" + className)

def isVersion68():
    version = idaapi.get_hexrays_version()
    return version.startswith("2.2.0.") 

def isVersion70():
    version = idaapi.get_hexrays_version()
    return version.startswith("7.0.0") 

def getVersionNumber():
    return float(idaapi.get_kernel_version())

#AllDecompiledFuncs = decompileAllFuncs()

def updateDecompiledFuncAtEA(funcStartEA):
    if not None is AllDecompiledFuncs:
        cfunc = decompileFuncInTextAtEA(funcStartEA)
        AllDecompiledFuncs[funcStartEA] = cfunc

def testDecompileAllFuncs():
    startTime = time.time()
    decompileAllFuncs()
    endTime = time.time()
    print "decompileAllFuncTime: " + str(endTime-startTime)
    outfile = open("decompileAllFuncTime.txt", "w")
    outfile.write("decompileAllFuncTime: " + str(endTime-startTime) + "\n")
    outfile.close()


def decompileAllFuncs():
    decompiledFuncs = {}
    for funcStartEA in Functions():
        cfunc = decompileFuncInTextAtEA(funcStartEA)
        if not cfunc is None:
            decompiledFuncs[funcStartEA] = cfunc
    return decompiledFuncs

def decompileAllVirtualFuncs():
    for className in classNameToVTableFuncEAListMap:
        decomileVirtualFuncsForClass(className)

def decomileVirtualFuncsForClass(className):
    if className in classNameToVTableFuncEAListMap:
        vtableFuncEAList = classNameToVTableFuncEAListMap[className]
        for vtableFuncEA in vtableFuncEAList:
            decompiledCFunc = decompile(vtableFuncEA)
            if className not in classNameToVirtualCFuncInfoMap:
                classNameToVirtualCFuncInfoMap[className] = []
            classNameToVirtualCFuncInfoMap[className].append(decompiledCFunc)

def createStruct(structName, structSize):
    structId = AddStrucEx(-1, structName, 0)
    for memberOffset in range(0, structSize, 8):
        AddStrucMember(structId, "member" + str(memberOffset/8), memberOffset, qwrdflag(), -1, 8)


def createClassStruct_new(className, classSize):
    #print "Create Class %s of Size %d"%(className, classSize)
    classStrucName = className
    classStrucId = GetStrucIdByName(classStrucName)
    if classStrucId == BADADDR:
        classStrucId = AddStrucEx(-1, classStrucName, 0)
    else:
        currentClassSize = GetStrucSize(classStrucId)
        if currentClassSize >= classSize:
            print "[!] createClassStruct was interrupted for {} (toSize: {}, currentSize: {})".format(className, classSize, currentClassSize)
        set_struc_hidden(get_struc(classStrucId), 1)
        return classStrucId
    AddStrucMember(classStrucId, "lastmember", 0, qwrdflag(), -1, 8)
    s = get_struc(classStrucId)
    expand_struc(s, 0, classSize-8)
    AddStrucMember(classStrucId, "vtable", 0, qwrdflag(), -1, 8)
    set_struc_hidden(get_struc(classStrucId), 1)
    return classStrucId

def createClassStruct(className, classSize, hideOvermuchMembers=True):
    #print "Create Class %s of Size %d"%(className, classSize)
    classStrucName = className
    classStrucId = GetStrucIdByName(classStrucName)
    if classStrucId == BADADDR:
        classStrucId = AddStrucEx(-1, classStrucName, 0)
    currentClassSize = GetStrucSize(classStrucId)
    if hideOvermuchMembers:
        #setMemberThresholdForClassSize = 0x1300
        setMemberThresholdForClassSize = 0x8000
    else:
        setMemberThresholdForClassSize = classSize
    classSizeWithIndivMembers = classSize if classSize <= setMemberThresholdForClassSize else setMemberThresholdForClassSize
    # Add member one by one
    #print currentClassSize, classSizeWithIndivMembers
    starttime = time.time()
    for memberOffset in range(currentClassSize, classSizeWithIndivMembers, 8):
        AddStrucMember(classStrucId, "member" + str(memberOffset/8), memberOffset, qwrdflag(), -1, 8)
    endtime = time.time()
    global wait_for_analysis_time
    wait_for_analysis_time += endtime-starttime
    if classSize > classSizeWithIndivMembers:
        AddStrucMember(classStrucId, "members", classSizeWithIndivMembers, qwrdflag(), -1, classSize - classSizeWithIndivMembers)
    set_struc_hidden(get_struc(classStrucId), 1)
    return classStrucId


def getAllClassSize():
    logFilePath = getFilePathWithRelPath("../results/iOS_Classes.txt")
    logFile = open(logFilePath, "w")
    rebuildAllInternalDataWOParseModInitFunc()
    #for (idx, structId, structName) in Structs():
    for className in classNameToParentClassNameMap:
        parentClassName = classNameToParentClassNameMap[className]
        structName = className
        structId = GetStrucIdByName(structName)
        if not structName.startswith("vtable_") and not structName.startswith("whole_vtable_") and not structName.endswith("::MetaClass"):
            structSize = GetStrucSize(structId)
            #print structName, structSize, hex(structSize)
            logMessage(structName + "\t" + str(structSize) + "\t" + hex(structSize) + "\t" + parentClassName, logFile)
    logFile.close()

def setNameAndTypeForExternalMethod(funcAddr, className, isDispatch):
    sMethodName = getName(funcAddr)
    sMethodDemangledName = Demangle(sMethodName, GetLongPrm(INF_LONG_DN))
    targetType = className + " *"
    if not None is sMethodDemangledName:
        arglist = parseFuncTypeToGetArglist(sMethodDemangledName)
        if len(arglist) == 3 and not arglist[0].startswith("OSObject"):
            targetType = arglist[0]
    elif None is sMethodDemangledName or sMethodName.startswith("sub_"):
        sMethodName = "{}::sMethod_{:08X}".format(className, funcAddr%0x100000000)
        set_name(funcAddr, sMethodName)

    if isDispatch:
        sMethodType = "uint32_t " + sMethodName + "(" + targetType + " this, void * reference, IOExternalMethodArguments * arguments)"
    else:
        sMethodType = "uint32_t " + sMethodName + "(" + targetType + " this, void * p2, void * p3, void * p4, void * p5, void * p6)"
    SetType(funcAddr, sMethodType)


def isIOExternalMethodDispatchAtEA_old(guessEA, isNextIgnore=False):
    guessValue0 = Qword(guessEA)
    guessValue1 = Qword(guessEA+8)
    guessValue2 = Qword(guessEA+0x10)
    guessValue3 = Qword(guessEA+0x18) # next head
    if (is_func(GetFlags(guessValue0)) and \
            (guessValue1 < binaryMinEA or guessValue1 > binaryMaxEA) and \
            (guessValue2 < binaryMinEA or guessValue2 > binaryMaxEA)) :
        if isNextIgnore:
            return True 
        elif is_func(GetFlags(guessValue3)):
            return True
    return False

def isIOExternalMethodDispatchAtEA(guessEA, className=None, segName=None):
    guessQValue0 = Qword(guessEA)
    guessQValue1 = Qword(guessEA+8)
    guessQValue2 = Qword(guessEA+0x10)
    guessDValue1 = Dword(guessEA+8)
    guessDValue2 = Dword(guessEA+0xc)
    guessDValue3 = Dword(guessEA+0x10)
    guessDValue4 = Dword(guessEA+0x14)
    #if (is_func(GetFlags(guessQValue0)) and \
    #        (guessDValue1 <= 0xffffffff and guessDValue1 >= 0) and \
    #        (guessDValue2 <= 0xffffffff and guessDValue2 >= 0) and \
    #        (guessDValue3 <= 0xffffffff and guessDValue3 >= 0) and \
    #        (guessDValue4 <= 0xffffffff and guessDValue4 >= 0)):
    if is_func(GetFlags(guessQValue0)) and (not is_func(GetFlags(guessQValue1))) and (not is_func(GetFlags(guessQValue2))):
        if (None is className) and (None is segName):
            return True
        deFuncName = getDeFuncNameAtEA(guessQValue0)
        if not None is deFuncName:
            if deFucnName.startswith(className + "::"):
                return True
            else:
                return False
        else:
            if getSegName(guessQValue0) == segName:
                return True
            else:
                return False
                None

            return True
    return False

def isIOExternalTrapAtEA(guessEA):
    guessValue0 = Qword(guessEA)
    guessValue1 = Qword(guessEA+8)
    guessValue2 = Qword(guessEA+0x10)
    if guessValue0 == 0 and guessValue2 == 0:
        return True
        #if is_func(GetFlags(guessValue1)):
        #    return True
    return False

def isIOExternalMethodAtEA(guessEA):
    guessValue0 = Qword(guessEA)
    guessValue1 = Qword(guessEA+8)
    guessValue2 = Qword(guessEA+0x10)
    guessValue3 = Qword(guessEA+0x18)
    guessValue4 = Qword(guessEA+0x20)
    guessValue5 = Qword(guessEA+0x28)
    if guessValue0 == 0 and guessValue2 == 0 and guessValue3 < 5 and guessValue4 <= 0xffffffff and guessValue5 <= 0xffffffff:
        return True
        #if is_func(GetFlags(guessValue1)):
        #    return True
    return False

def isMethodStructAtEA(guessEA, userEntryName):
    if userEntryName == "externalMethod":
        return isIOExternalMethodDispatchAtEA(guessEA)
    elif userEntryName == "getTargetAndTrapForIndex":
        return isIOExternalTrapAtEA(guessEA)
    else:
        return isIOExternalMethodAtEA(guessEA)

#TODO deprecate this
def isMethodStructAtEA_old(guessEA, isDispatch):
    if isDispatch:
        return isIOExternalMethodDispatchAtEA(guessEA)
    else:
        return isIOExternalMethodAtEA(guessEA)


def getMethodStructSizeAndFuncOff(userEntryName):
    if userEntryName == "externalMethod":
        return 0x18, 0
    elif userEntryName == "getTargetAndTrapForIndex":
        return 0x18, 8
    else:
        return 0x30, 8

def collectSMethodsFromArrayAt(sMethodArrayStartEA, sMethodTotal, userEntryName):
    sMethodEAs = []
    funcPtrs = []
    size_Struct, funcPtrOff = getMethodStructSizeAndFuncOff(userEntryName)
    if sMethodTotal == -1:
        currentEA = sMethodArrayStartEA
        seg = getseg(currentEA)
        sMethodTotal = 0
        while currentEA < seg.endEA:
            if not isMethodStructAtEA(currentEA, userEntryName):
                break
            sMethodTotal += 1
            currentEA += size_Struct
    for sMethodCnt in range(0, sMethodTotal):
        sMethodStructStartEA = sMethodArrayStartEA + size_Struct * sMethodCnt
        sMethodEAs.append(sMethodStructStartEA)
        funcPtrs.append(Qword(sMethodStructStartEA + funcPtrOff)) 
    return sMethodEAs, funcPtrs

def parseSMethodArrayAtAddr(sMethodArrayStartEA, sMethodTotal, className, isDispatch):
    alreadyNamed = False
    oldName = getName(sMethodArrayStartEA)
    if (not None is oldName) and (oldName.startswith("__")):
        alreadyNamed = True
    size_MethodDispatch = 0x18
    size_Method = 0x30
    size_Struct = size_MethodDispatch if isDispatch else size_Method
    if sMethodTotal == -1:
        currentEA = sMethodArrayStartEA
        seg = getseg(currentEA)
        sMethodTotal = 0
        while currentEA < seg.endEA:
            if not isMethodStructAtEA_old(currentEA, isDispatch):
                break
            sMethodTotal += 1
            currentEA += size_Struct
    if isDispatch:
        if not alreadyNamed:
            for sMethodCnt in range(0, sMethodTotal):
                sMethodStructStartEA = sMethodArrayStartEA + size_MethodDispatch * sMethodCnt
                sMethodFuncAddr = Qword(sMethodStructStartEA)
                if sMethodFuncAddr != 0:
                    setNameAndTypeForExternalMethod(sMethodFuncAddr, className, True)
                    SetType(sMethodStructStartEA, "IOExternalMethodDispatch")
            SetType(sMethodArrayStartEA, "IOExternalMethodDispatch[{}] ".format(sMethodTotal))
            set_name(sMethodArrayStartEA, "{}_sMethods".format(className), SN_FORCE)
        className2SMethods_MethodDispatch[className] = [ea for ea in range(sMethodArrayStartEA, sMethodArrayStartEA+0x18*sMethodTotal, 0x18)]
    else:
        if not alreadyNamed:
            for sMethodCnt in range(0, sMethodTotal):
                sMethodStructStartEA = sMethodArrayStartEA + size_Method * sMethodCnt
                sMethodFuncAddr = Qword(sMethodStructStartEA + 0x8)
                setNameAndTypeForExternalMethod(sMethodFuncAddr, className, False)
                SetType(sMethodStructStartEA, "IOExternalMethod")
            SetType(sMethodArrayStartEA, "IOExternalMethod[{}] ".format(sMethodTotal))
            set_name(sMethodArrayStartEA, "{}_sMethods".format(className), SN_FORCE)
        className2SMethods_Method[className] = [ea for ea in range(sMethodArrayStartEA, sMethodArrayStartEA+0x30*sMethodTotal, 0x30)]


def importHeaderFile(headerFilePath):
    oldOrdinalQty = idaapi.get_ordinal_qty(idaapi.cvar.idati)
    ret = idaapi.idc_parse_types(headerFilePath, idc.PT_FILE)
    if ret==0:
        newOrdinalQty = idaapi.get_ordinal_qty(idaapi.cvar.idati)
        print "oldOrdinalQty, newOrdinalQty:", oldOrdinalQty, newOrdinalQty
        if newOrdinalQty > oldOrdinalQty:
            for i in range(oldOrdinalQty, newOrdinalQty):
                idaapi.import_type(idaapi.cvar.idati, i, idaapi.idc_get_local_type_name(i))
        return True
    else:
        print ""
        print ret
        return False
    None

def iDEALoadTilFile(tilFilePath):
 
    #print "before load_til"
    loadedTil = ida_typeinf.load_til(tilFilePath)
    #print loadedTil
    selfTil = ida_typeinf.get_idati()
    
    if not None is loadedTil:
        newOrdinalQty = ida_typeinf.get_ordinal_qty(loadedTil)
        #print "newOrdinalQty: {}".format(newOrdinalQty)
        if newOrdinalQty <= 0:
            return False
    
        for i in range(1, newOrdinalQty):
            import_name = ida_typeinf.get_numbered_type_name(loadedTil, i)
            #print "{} import_name: {} ".format(i, import_name)
    
            if not None is import_name and not "$" in import_name and not import_name.startswith("__PHASE__"):
                if ida_typeinf.get_type_ordinal(selfTil, import_name) == 0:
                    #print "{} not defined".format(import_name)
                    ida_typeinf.import_type(loadedTil, i, import_name)
    '''
                ida_typeinf.import_type(loadedTil, i, import_name)
                #if None is getTinfoForTypeStr(import_name):
                #    print "{} was not in local types".format(import_name)
                #    ida_typeinf.import_type(loadedTil, i, import_name)
        return True
    else:
        return False
    '''


def importNecessaryHeaders(isKernel=False):
    ''' Import header file from publich xcode headers and kernel ida file's exported headers'''
    phase = "importNecessaryHeaders"
    #if checkPhaseDone(phase):
    #    return
    print "[+] Import Necessary Headers"
    #importHeaderFile(getFilePathWithRelPath("../Headers/IOUserClient_mine.h"))
    if not isKernel:
        #loadTilFile()
        #importHeaderFile(getFilePathWithRelPath("../Headers/kernel_development.h"))
        importHeaderFile(getFilePathWithRelPath("../Headers/kernel.h"))

    importHeaderFile(getFilePathWithRelPath("../Headers/XcodePublicHeaders.h"))
    for i in range(1, idaapi.get_ordinal_qty(idaapi.cvar.idati)):
        try:
            typeStr = GetLocalType(i, 0)
            if typeStr.startswith("struct "):
                typeStructName = typeStr[typeStr.rfind(" ")+1:]
                if GetStrucIdByName(typeStructName) == BADADDR:
                    idaapi.import_type(idaapi.cvar.idati, i, idaapi.idc_get_local_type_name(i))
        except Exception as e:
            None
    markPhaseDone(phase)

def preparePredefinedStructNameToIdMap():
    print "[+] Prepare Predefined Structs"
    for idx, sid, name in Structs():
        predefinedStructNameToIdMap[name] = sid

def hideAllStructs():
    for structTuple in Structs():
        set_struc_hidden(get_struc(structTuple[1]), 1)
    
def backResolveInPseudoCodeFunc(funcStartEA, variable, startEA):
    cfunc = None
    try:
        cfunc = decompile(funcEA)
        cfunc_treeitems = cfunc.treeitems
        for item in cfunc_treeitems:
            None
    except Exception as e:
        print 'could not decompile: %s' % (str(e), )


def getStringAtAddr(ea):
    #segName = get_segm_name(ea)
    #if segName.endswith("__cstring"):
    return idc.GetString(ea)

def getTinfoForTypeStr(typeStr):
    if None is typeStr:
        return None
    typeStr = typeStr.replace("const ", "")
    tinfo = tinfo_t()
    if getVersionNumber() >= 7.0:
        parse_decl2(idaapi.cvar.idati, typeStr + ";", tinfo, 1)
    else:
        parse_decl2(idaapi.cvar.idati, typeStr + ";", typeStr, tinfo, 1)
    if tinfo.is_well_defined():
        return tinfo
    else:
        return None


def setTypeForFuncAtEA(funcEA, typeToSet):
    orignalName = getName(funcEA)
    ret = 0
    if orignalName != "___cxa_pure_virtual":
        forceFunction(funcEA)
        ret = SetType(funcEA, typeToSet)
    xref = get_first_dref_to(funcEA)
    vfuncMemId = BADADDR
    while xref != None and xref != BADADDR:
        if is_member_id(xref):
            memberName = ida_struct.get_member_name(xref)
            if not memberName is None:
                vfuncMemId = xref
                funcType = GetType(funcEA)
                if funcType != None:
                    ''' I should also do SetType for children's vtable structs ''' 
                    funcTypeArgStartLoc = funcType.find("(")
                    funcPTRType = funcType[:funcTypeArgStartLoc] + "(*)" +  funcType[funcTypeArgStartLoc:]
                    SetType(vfuncMemId, funcPTRType)
        else:
            xrefSegName = get_segm_name(xref)
            if xrefSegName.endswith(":__got"):
                keepCon_ItemAndGOTItem(funcEA, xref)
        xref = get_next_dref_to(funcEA, xref)
    return ret

def getAllChildFuncEAsForClass(className):
    childFuncEASetList = []
    vtableStartEA = 0
    vtableEndEA = BADADDR
    vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
    if  vtableStartEA != BADADDR and vtableEndEA != BADADDR :
        vtableSize = vtableEndEA - vtableStartEA
        classNameSet = getDescendantsForClass(className)
        for vtOff in range(0, vtableSize, 8):
            childFuncEASet = set()
            parentFuncEA = Qword(vtableStartEA + vtOff)
            for childClassName in classNameSet:
                cVTStartEA, cVTEndEA = getVTableAddrOfClass(childClassName)
                if cVTStartEA != BADADDR and vtOff != BADADDR and cVTStartEA + vtOff < cVTEndEA:
                    childFuncEA = Qword(cVTStartEA + vtOff)
                    if (childFuncEA != parentFuncEA):
                        childFuncEASet.add(childFuncEA)
            childFuncEASetList.append(childFuncEASet)
    return childFuncEASetList

def getChildFuncEAsForClassAtVTOff(className, vtOff, shouldResultExcludeParent=True):
    childFuncEASet = set()
    vtableStartEA = 0
    vtableEndEA = BADADDR
    if shouldResultExcludeParent:
        vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
    if  vtableStartEA != BADADDR and vtOff != BADADDR and vtableStartEA + vtOff < vtableEndEA:
        parentFuncEA = Qword(vtableStartEA + vtOff)
        classNameSet = getDescendantsForClass(className)
        for childClassName in classNameSet:
            cVTStartEA, cVTEndEA = getVTableAddrOfClass(childClassName)
            if cVTStartEA != BADADDR and vtOff != BADADDR and cVTStartEA + vtOff < cVTEndEA:
                childFuncEA = Qword(cVTStartEA + vtOff)
                if (not shouldResultExcludeParent) or (shouldResultExcludeParent and childFuncEA != parentFuncEA):
                    childFuncEASet.add(childFuncEA)

    return childFuncEASet

def getParentFuncEAsForClassAtVTOff(className, vtOff):
    parentFuncEASet = set()
    vtableStartEA = 0
    vtableEndEA = BADADDR
    vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
    if  vtableStartEA != BADADDR and vtOff != BADADDR and vtableStartEA + vtOff < vtableEndEA:
        parentFuncEA = Qword(vtableStartEA + vtOff)
        classNameSet = getDescendantsForClass(className)
        for childClassName in classNameSet:
            cVTStartEA, cVTEndEA = getVTableAddrOfClass(childClassName)
            if cVTStartEA != BADADDR and vtOff != BADADDR and cVTStartEA + vtOff < cVTEndEA:
                parentFuncEA = Qword(cVTStartEA + vtOff)
                if (not shouldResultExcludeParent) or (shouldResultExcludeParent and parentFuncEA != parentFuncEA):
                    parentFuncEASet.add(parentFuncEA)

    return parentFuncEASet

def getRetTypeOfFuncAtAddr(ea):
    funcType = GetType(ea)
    return getRetTypeFromFuncType(funcType)

def getRetTypeFromFuncType(funcType):
    if not None is funcType:
        loc = funcType.find(" ")
        returnType = funcType[:loc]
        for i in range(loc, len(funcType)):
            if funcType[i] == " ":
                returnType = returnType + " "
            elif funcType[i] == "*":
                returnType = returnType + "*"
            else:
                break
        return returnType
    return None

returnTypeChangedFuncs = {}

def changeRetTypeOfFuncAtAddr(funcAddr, newReturnType):
    segName = getSegName(funcAddr)
    if not segName.endswith("__text"):
        return
    
    oldFuncTinfo = getTinfoOfFuncAtEA(funcAddr)
    if None is oldFuncTinfo:
        forceFunction(funcAddr)
    oldFuncTinfo = getTinfoOfFuncAtEA(funcAddr)
    oldReturnType = "uint64_t"
    funcType = GetType(funcAddr)
    if not None is oldFuncTinfo:
        oldReturnTinfo = str(oldFuncTinfo.get_rettype())
        if isTinfoInterested(oldReturnTinfo):
            return False
    else:
        oldReturnType = getRetTypeFromFuncType(funcType)
    #if (None is oldReturnType) or (oldReturnType != newReturnType and (not isTinfoInterested(getTinfoForTypeStr(oldReturnType)))):
    if oldReturnType != newReturnType:
        if not None is funcType:
            funcTypeArgStartLoc = funcType.find("(")
            newFuncType = newReturnType +  " " + getName(funcAddr) + funcType[funcTypeArgStartLoc:]
            setTypeForFuncAtEA(funcAddr, newFuncType)
            #print "changeRetTypeOfFuncAtAddr 0x%016x, newType: %s"%(funcAddr, newFuncType)
            return True
    return False

def setTypeForMemeber(structId, memberOff, typeString):

    #print "setTypeForMemeber", hex(structId), memberOff, typeString
    if typeString.startswith("whole_vtable_") or typeString.startswith("vtable_") :
        return
    if memberOff == 0: 
        # Do not change vtable member
        return
    memberId = GetMemberId(structId, memberOff)
    oldMemberName = ida_struct.get_member_name(memberId)
    if oldMemberName != "vtable":
        SetType(memberId, typeString)

    if "*" in typeString:
        typeStringPrefix = typeString[:typeString.find("*")].strip()
    else:
        typeStringPrefix = typeString

    if None is oldMemberName:
        SetOrAddMemberName(structId, memberOff, "member" + str(memberOff/8) + "_" + typeStringPrefix )
    elif (not typeStringPrefix.startswith("whole_vtable_")) and \
            (not typeStringPrefix.startswith("vtable_")) and \
            not oldMemberName == "vtable":
        memberName = "member{}_{}".format(memberOff/8, typeStringPrefix)
        SetOrAddMemberName(structId, memberOff, memberName)
    #elif (not typeStringPrefix.startswith("whole_vtable_")) and \
    #        (not typeStringPrefix.startswith("vtable_")) and \
    #        (not (("_" + typeStringPrefix) in oldMemberName)):
    #    SetOrAddMemberName(structId, memberOff, oldMemberName + "_" + typeStringPrefix )


def solveVariableTypeInAllFuncs():
    phase = "solveVariableTypeInAllFuncs"
    if checkPhaseDone(phase):
        return
    print "[+] Solve Variable Type In All Functions"
    for funcEA in Functions():
        solveVariableTypeInFuncAtEA(funcEA)
    markPhaseDone(phase)

def solveVariableTypeInFuncsForKext(kextPrefix):
    textSegName = kextPrefix + ":__text"
    textSegs = getSegsByName(textSegName)
    for textSeg in textSegs:
        for funcEA in Functions(textSeg.startEA, textSeg.endEA):
            solveVariableTypeInFuncAtEA(funcEA)

def findAssignTargetOfExprResult(cfunc, currentItem):
    currentItem = cfunc.body.find_parent_of(currentItem).to_specific_type
    if currentItem.op == 48: #cast:
        currentItem = cfunc.body.find_parent_of(currentItem).to_specific_type

    if currentItem.op == 80: #return
        return currentItem.to_specific_type
    elif currentItem.op == 2: # asg
        assignTargetItem = currentItem.x.to_specific_type
        if assignTargetItem.op == 65 or assignTargetItem.op == 60: # var or memptr
            return assignTargetItem 
        elif assignTargetItem.op == 57 and assignTargetItem.x.op == 68 and len(assignTargetItem.a) == 1 and (assignTargetItem.a[0].op == 60 or assignTargetItem.a[0].op == 65): # 68 stands for helper functions, e.g., BYTE(), LDWORD(), HDWORD()...
            return assignTargetItem.a[0]
    return None


def isAddrInTextSeg(funcStartEA):
    funcSegName = get_segm_name(funcStartEA)
    if funcSegName is None:
        return False
    return funcSegName.endswith("__text")

def isAddrInUNDEFSeg(funcEA):
    funcSegName = get_segm_name(funcStartEA)
    if funcSegName is None:
        return False
    return funcSegName.endswith("UNDEF")

def isFuncVirtual(funcStartEA):
    xref = get_first_dref_to(funcStartEA)
    while xref != None and xref != BADADDR:
        member = get_member_by_id(xref)
        if member:
            return True
        xref = get_next_dref_to(funcStartEA, xref)
    return False
    #return funcStartEA in virtualFuncEASet


def propagateTypeInBB(bbStartEA, varTypes):
    None
    
def solveVariableTypeInFuncAtEA(funcStartEA):
    nullDevFile = open("/dev/null", "w")
    cfunc = None
    #print "[-] Solve Variable Type In Func At EA 0x%016x"%(funcStartEA) 
    try:
        if isAddrInTextSeg(funcStartEA):
            cfunc = idaapi.decompile(funcStartEA)
            cfunc.build_c_tree()
            nullDevFile.write(str(cfunc))
            #print cfunc
            solveVariableTypeInFunc(cfunc)

            funcEA = cfunc.entry_ea
            if funcEA in AllLvarTypesToModify:
                lvarTypesToModify = AllLvarTypesToModify[funcEA]
                print lvarTypesToModify
                for t in lvarTypesToModify:
                    print t[0].name, t[1].dstr()
                saveLvarTinfoListInFuncAtEA(funcEA, lvarTypesToModify)

    except Exception as e:
        print 'could not solveVariableTypeInFuncAtEA 0x%016x: %s' % (funcStartEA, str(e), )
        traceback.print_exc()
    nullDevFile.close()


def solveVariableTypeInFunc(cfunc):
    """ indeed, this function can only set members' type and function's return type according to their assignments in functions, 
        since cfunc comes from decompile(funcAddr), which can not affect the original disassemble code
    """
    solveVariableTypeByArgumentsInFunc(cfunc)
    solveVariableTypeByCallsInFunc(cfunc)

def solveVariableTypeByArgumentsInFunc(cfunc):
    arguments = cfunc.arguments
    for argLvar in arguments:
        propagateTypeInfuncByNameFromIndex(cfunc, argLvar.name, argLvar.tif, 1)

def findLvarNearestAssignWithMetaClass(cfunc, fromExpr, LvarIdx):
    # This is not acurate
    treeItems = cfunc.treeitems
    fromItemIndex = fromExpr.index
    fromItem = treeItems[fromItemIndex]
    fromEA = fromItem.ea

    for itemIndex in range(fromItemIndex-1, -1, -1):
        currentItem = treeItems[itemIndex].to_specific_type
        
        if currentItem.op == 2: # asg
            assignTarget = None
            assignTargetItem = currentItem.x.to_specific_type
            if assignTargetItem.op == 65 or assignTargetItem.op == 60: # var or memptr
                assignTarget = assignTargetItem 
            elif assignTargetItem.op == 57 and assignTargetItem.x.op == 68 and len(assignTargetItem.a) == 1 and (assignTargetItem.a[0].op == 60 or assignTargetItem.a[0].op == 65): # 68 stands for helper functions, e.g., BYTE(), LDWORD(), HDWORD()...
                assignTarget = assignTargetItem.a[0]
            if not assignTarget is None and assignTarget.op == 65: # var
                assignTargetLVarIdx = assignTarget.v.idx
                if assignTargetLVarIdx == LvarIdx:
                    assignSource = currentItem.y.to_specific_type
                    if assignSource.op == 51: # ptr, *
                        assignSource = assignSource.x.to_specific_type
                    if assignSource.op == 48: # cast, (X) 
                        assignSource = assignSource.x.to_specific_type
                    if assignSource.op == 52: #ref, &
                        assignSource = assignSource.x.to_specific_type
                    if assignSource.op ==  64: #obj
                        classString = None
                        # found cast metaClass obj. for now, only consider const metaClass obj, not lvar
                        metaClassDemangledName = getDeNameAtEA(assignSource.obj_ea)
                        if not None is metaClassDemangledName:
                            if metaClassDemangledName.endswith("::gMetaClass"):
                                classString = metaClassDemangledName[:-len("::gMetaClass")]
                            elif metaClassDemangledName.endswith("::metaClass"):
                                classString = metaClassDemangledName[:-len("::metaClass")]
                        if classString != None:
                            return classString
    return None

def findLvarNearestAheadAssignSource(cfunc, fromExpr, lvarIdx):
    # This is not acurate
    treeItems = cfunc.treeitems
    fromItemIndex = fromExpr.index
    fromItem = treeItems[fromItemIndex]
    fromEA = fromItem.ea

    for itemIndex in range(fromItemIndex-1, -1, -1):
        currentItem = treeItems[itemIndex].to_specific_type
        if currentItem.op == 2: # asg
            assignTarget = None
            assignTargetItem = currentItem.x.to_specific_type
            if assignTargetItem.op == 65 or assignTargetItem.op == 60: # var or memptr
                assignTarget = assignTargetItem 
            elif assignTargetItem.op == 57 and assignTargetItem.x.op == 68 and len(assignTargetItem.a) == 1 and (assignTargetItem.a[0].op == 60 or assignTargetItem.a[0].op == 65): # 68 stands for helper functions, e.g., BYTE(), LDWORD(), HDWORD()...
                assignTarget = assignTargetItem.a[0]
            if not assignTarget is None and assignTarget.op == 65: # var
                assignTargetLVarIdx = assignTarget.v.idx
                if assignTargetLVarIdx == lvarIdx:
                    return  currentItem.y.to_specific_type
    return None

def solveVariableTypeByCallsInFunc(cfunc):
    callExprList = getCallExprListOfFunc(cfunc)

    #print cfunc
    #print "solveVariableTypeInFunc: 0x%016x, len(cfunc.treeitems): %d, len(callExprList): %d"%(cfunc.entry_ea, len(cfunc.treeitems), len(callExprList))
    for callExpr in callExprList:
        arglist = callExpr.a
        calledFuncExpr = callExpr.x

        if calledFuncExpr.op == 48: # cast
            calledFuncExpr = calledFuncExpr.x

        if len(arglist) == 0:
            continue

        arg0 = arglist[0]
        arg0Type = None 
        #if arg0.op == 48: # cast
        #    arg0Expr = arg0.to_specific_type
        #    realArg0 = arg0Expr.operands['x']
        #    arg0Type = realArg0.type.dstr() # this is tinfo_t, really
        #elif arg0.op == 65: # var
        #    arg0Type = arg0.type.dstr()  # this is tinfo_t, really
        #print arg0Type

        # OSMetaClass::allocClassWithName
        #if 'obj_ea' in calledFuncExpr.operands:
        if calledFuncExpr.op == 64: # obj, non-virtual function call
            calledFuncEA = calledFuncExpr.operands['obj_ea']
            #className = arg0Type.replace("*", "").strip()
            calledFuncName = getName(calledFuncEA)
            calledDemangledFuncName = getDeFuncNameAtEA(calledFuncEA)
            calledDemangledFuncNameParts = None
            if calledDemangledFuncName != None:
                calledDemangledFuncNameParts = calledDemangledFuncName.split("::")
            if calledFuncName.startswith("__ZN11OSMetaClass18allocClassWithName"):
                classString = None
                arg0 = arg0.to_specific_type
                # get alloc type, for now, only consider const string argument
                if "x" in arg0.operands and arg0.x.obj_ea != None: # x stands for cast
                    stringAddr = arg0.to_specific_type.x.obj_ea
                    classString = getStringAtAddr(stringAddr)
                elif "obj_ea" in arg0.to_specific_type.operands:
                    stringAddr = arg0.to_specific_type.obj_ea
                    classString = getStringAtAddr(stringAddr)

                if not classString is None:
                    tinfo = getTinfoForTypeStr(classString + " *")
                    currentExpr = callExpr.to_specific_type
                    assignTarget = findAssignTargetOfExprResult(cfunc, currentExpr)
                    if not None is assignTarget:
                        setTypeAndPropagateForTargetExpr(cfunc, assignTarget, tinfo)

            elif calledFuncName == "__ZN8OSObjectnwEm":
                None

            # cast
            elif calledFuncName == "__ZNK15OSMetaClassBase8metaCastEPK11OSMetaClass" or calledFuncName == "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass":
                arg0 = arglist[0].to_specific_type
                arg1 = arglist[1].to_specific_type
                if arg0.op == 48: # cast, (X)
                    arg0 = arg0.x.to_specific_type
                if arg1.op == 51: # ptr, *
                    arg1 = arg1.x.to_specific_type
                if arg1.op == 48: # cast, (X) 
                    arg1 = arg1.x.to_specific_type

                classString = None
                if arg1.op == 52: #ref, &
                    arg1 = arg1.x.to_specific_type
                if arg1.op ==  64: #obj
                    # found cast metaClass obj. for now, only consider const metaClass obj, not lvar
                    metaClassDemangledName = getDeNameAtEA(arg1.obj_ea)
                    if not metaClassDemangledName is None:
                        if metaClassDemangledName.endswith("::gMetaClass"):
                            classString = metaClassDemangledName[:-len("::gMetaClass")]
                        elif metaClassDemangledName.endswith("::metaClass"):
                            classString = metaClassDemangledName[:-len("::metaClass")]
                elif arg1.op == 65:
                    # The type string is in a lvar
                    classString = findLvarNearestAssignWithMetaClass(cfunc, callExpr, arg1.v.idx)

                if not classString is None:
                    tinfo = getTinfoForTypeStr(classString + " *")
                    currentExpr = callExpr.to_specific_type

                    arg0Target = arg0.to_specific_type
                    setTypeAndPropagateForTargetExpr(cfunc, arg0Target, tinfo)

                    assignTarget = findAssignTargetOfExprResult(cfunc, currentExpr)
                    if not None is assignTarget:
                        #print assignTarget, tinfo.dstr()
                        setTypeAndPropagateForTargetExpr(cfunc, assignTarget, tinfo)
            

            elif not calledDemangledFuncNameParts is None and len(calledDemangledFuncNameParts)>1 and calledDemangledFuncNameParts[0]==calledDemangledFuncNameParts[1]:
                # constructor function
                
                classString = calledDemangledFuncNameParts[0]
                if not None is classString:
                    tinfo = getTinfoForTypeStr(classString + " *")
                    arg0 = arg0.to_specific_type
                    if arg0.op == 48: #cast
                        arg0 = arg0.x.to_specific_type
                    setTypeAndPropagateForTargetExpr(cfunc, arg0, tinfo)
            else:
                calledFuncReturnType = getRetTypeOfFuncAtAddr(calledFuncEA)
                if calledFuncReturnType != None:
                    tinfo = getTinfoForTypeStr(calledFuncReturnType)
                    if tinfo.is_ptr():
                        currentExpr = callExpr.to_specific_type
                        assignTarget = findAssignTargetOfExprResult(cfunc, currentExpr)
                        if not None is assignTarget:
                            setTypeAndPropagateForTargetExpr(cfunc, assignTarget, tinfo)


        elif calledFuncExpr.op == 60: #memptr
            structExpr = calledFuncExpr.operands['x']
            memberOffset = calledFuncExpr.operands['m']
            structType = structExpr.type
            structTypeStr = structType.dstr().strip()
            print structTypeStr
            
            if structTypeStr.startswith("struct vtable_"):
                vtableStructName = structTypeStr[7:].split("*")[0].strip()
                structId = GetStrucIdByName(vtableStructName)           
                memberId = GetMemberId(structId, memberOffset)
                calledFuncReturnType = getRetTypeOfFuncAtAddr(memberId)
                print hex(callExpr.ea), calledFuncReturnType
                
                if calledFuncReturnType != None:
                    tinfo = getTinfoForTypeStr(calledFuncReturnType)
                    if tinfo.is_ptr():
                        currentExpr = callExpr.to_specific_type
                        assignTarget = findAssignTargetOfExprResult(cfunc, currentExpr)
                        if not None is assignTarget:
                            setTypeAndPropagateForTargetExpr(cfunc, assignTarget, tinfo)
                None
            elif structTypeStr == "struct vtable_ *":
                # this was considered to be MetaClass::alloc, but seldom used
                None
            elif structTypeStr == "struct vtable_IOCommandGate *" and memberOffset == 224:
                # if commandgate, keep solving 
                targetType = calledFuncExpr.operands['x'].operands['x'].operands['x'].type
                # this is IOCommandGate::runAction
                arg1 = arglist[1]
                calledGatedFuncEA = None
                if arg1.op == 48: # cast
                    calledGatedFuncEA = arg1.operands['x'].obj_ea
                if calledGatedFuncEA != None:
                    None

callGraphForAll = {}
unsolvedCallsForAll = {}

def buildCallGraphForAllFuncs():
    for funcStartEA in Functions():
        callGraph, unsolvedCalls = buildCallGraphForFuncAtEA(funcStartEA)
        callGraphForAll[funcStartEA] = callGraph
        unsolvedCallsForAll[funcStartEA] = unsolvedCalls


def buildCallGraphForFuncAtEA(funcEA):
    cfunc = decompileFuncInTextAtEA(funcEA)
    return buildCallGraphForFunc(cfunc)


def getFuncEAFromVFuncMember(vtableStructName, memberOffset):
    if vtableStructName.endswith("*"):
        vtableStructName = vtableStructName[:-1]
    if vtableStructName.startswith("struct "):
        vtableStructName = vtableStructName[len("struct "):]
    vtableStructName = vtableStructName.strip()
    vtableStructId = GetStrucIdByName(vtableStructName)
    vtableStruct = get_struc(vtableStructId)
    methodMember = get_member(vtableStruct, memberOffset)
    calledFuncEA = BADADDR
    if not methodMember is None:
        methodName = ida_struct.get_member_name(methodMember.id)
        calledFuncEA = get_name_ea(0, methodName)
        if calledFuncEA == BADADDR:
            calledFuncEA = methodMember.id
    return calledFuncEA

def getCalledFuncEAOfCallExpr(cfunc, calledFuncExpr):
    calledFuncEA = BADADDR
    calledFuncExpr = calledFuncExpr.to_specific_type
    if calledFuncExpr.op == 48: # cast 
        calledFuncExpr = calledFuncExpr.x
    if calledFuncExpr.op == 64: # obj, non-virtual function call
        calledFuncEA = calledFuncExpr.operands['obj_ea']
        #calledFuncName = getName(calledFuncEA)
    elif calledFuncExpr.op == 60 or calledFuncExpr.op == 59: #memptr or memref
        structExpr = calledFuncExpr.operands['x']
        structType = structExpr.type
        structTypeStr = structType.dstr().strip()
        memberOffset = calledFuncExpr.operands['m']
        calledFuncEA = getFuncEAFromVFuncMember(structTypeStr, memberOffset)
    elif calledFuncExpr.op == 51: # ptr
        calledFuncExpr = calledFuncExpr.x
        if calledFuncExpr.op == 48:
            calledFuncExpr = calledFuncExpr.x
        if calledFuncExpr.op == 52 and calledFuncExpr.x.op == 58 and (calledFuncExpr.x.x.op == 60 or calledFuncExpr.x.x.op == 59) :
            structExpr = calledFuncExpr.x.x.x
            structType = structExpr.type
            structTypeStr = structType.dstr().strip()
            memberOffset = calledFuncExpr.x.x.m + calledFuncExpr.x.y.n.value(get_int_type_by_width_and_sign(8,1))
            calledFuncEA = getFuncEAFromVFuncMember(structTypeStr, memberOffset)
    elif calledFuncExpr.op == 65: # var
        assignSource = findLvarNearestAheadAssignSource(cfunc, calledFuncExpr, calledFuncExpr.v.idx)
        if not None is assignSource:
            calledFuncEA = getCalledFuncEAOfCallExpr(cfunc, assignSource)
    return calledFuncEA

def buildCallGraphForFunc(cfunc):
    callGraph = {}
    unsolvedCalls = []
    if not None is cfunc:
        callExprList = getCallExprListOfFunc(cfunc)
        for callExpr in callExprList:
            insnOp = GetMnem(callExpr.ea)
            if insnOp != "call" and insnOp != "jmp":
                continue
            #print hex(callExpr.ea)
            arglist = callExpr.a
            calledFuncExpr = callExpr.x
            if calledFuncExpr.op == 48: # cast, maybe function ptr cast
                calledFuncExpr = calledFuncExpr.x.to_specific_type
            calledFuncExprEA = calledFuncExpr.ea
            calledFuncEA = getCalledFuncEAOfCallExpr(cfunc, calledFuncExpr)
            #print hex(callExpr.ea), hex(calledFuncEA)
            if not None is calledFuncEA and calledFuncEA != BADADDR:
                callGraph[callExpr.ea] = calledFuncEA
                addXref(callExpr.ea, calledFuncEA, 1)
            else:
                unsolvedCalls.append(callExpr.ea)
    return callGraph, unsolvedCalls 


import os

def drawCallGrapForFuncAtEA(funcStartEA):
    if len(callGraphForAll ) == 0:
        buildCallGraphForAllFuncs()
    os.environ["PATH"] += os.pathsep + "/usr/local/Cellar/graphviz/2.40.1/bin/"
    if funcStartEA in callGraphForAll:
        callGraph = callGraphForAll[funcStartEA]
        graph = graphviz.Digraph(format='png')
        visitedFuncEAs = []
        graph.node(getName(funcStartEA))
        representCallGraphTree(graph, funcStartEA, callGraph, visitedFuncEAs)
        graph.render("callgraph")

def representCallGraphTree(graph, funcEA, callGraph, visitedFuncEAs):
    visitedFuncEAs.append(funcEA)
    funcName = getName(funcEA)
    for calledFuncEA in callGraph.values():
        calledNodeName = getName(calledFuncEA)
        graph.node(calledNodeName)
        graph.edge(funcName, calledNodeName)
        if not calledFuncEA in visitedFuncEAs:
            if calledFuncEA in callGraphForAll:
                calledCallGraph = callGraphForAll[calledFuncEA]
                representCallGraphTree(graph, calledFuncEA, calledCallGraph, visitedFuncEAs)
    visitedFuncEAs.pop()

def getMemberForCMemberExpr(cMemPtrOrRefExpr):
    if cMemPtrOrRefExpr.op == 60 or cMemPtrOrRefExpr.op == 59:
        structExpr = cMemPtrOrRefExpr.operands['x']
        # TODO Some error here, need further check com.apple.driver.AppleBacklight
        if None is structExpr:
            return None
        structType = structExpr.type
        structTypeStr = structType.dstr().strip()
        memberOffset = cMemPtrOrRefExpr.operands['m']
        #print structTypeStr, memberOffset
        if structTypeStr.endswith("*"):
            StrucName = structTypeStr[:-1].strip()
            StrucId = GetStrucIdByName(StrucName)
            Struct = get_struc(StrucId)
            Member = get_member(Struct, memberOffset)
            return Member
    return None

def parseNamesInGOTSeg(gotSegEA):
    ''' assign types to vtable names in got seg  ''' 
    gotSegStartEA = SegStart(gotSegEA)
    gotSegEndEA = SegEnd(gotSegEA)
    currentEA = gotSegEA
    while currentEA < gotSegEndEA:
        realName = getName(Qword(currentEA))
        deName = getDeNameAtEA(Qword(currentEA))
        newName = realName + "_0"
        set_name(currentEA, newName)
        if None is deName:
            currentEA += 0x8
            continue
        if realName.startswith("__ZTV"): # vtable
            demangledRealName = deName
            className = demangledRealName[len("`vtable for'"):]
            wholeVTableStructId = createWholeVTableStructForClass(className)
            SetType(currentEA, "struct whole_vtable_" + className + "*")
            SetType(Qword(currentEA), "struct whole_vtable_" + className)
        elif deName.endswith("::gMetaClass"):
            className = deName[:-len("::gMetaClass")]
            SetType(currentEA, className + "::MetaClass *")
            SetType(Qword(currentEA), className + "::MetaClass" )
        elif deName.endswith("::metaClass"):
            className = deName[:-len("::metaClass")]
            SetType(currentEA, className + "::MetaClass **")
            SetType(Qword(currentEA), className + "::MetaClass *" )
        currentEA += 0x8

def addXrefsForAllStructMemsInFunc(cfunc):
    for item in cfunc.treeitems:
        if item.op == 60: #memptr
            item = item.to_specific_type

            fromEA = item.ea 
            member = getMemberForCMemberExpr(item)
            if not None is member:
                while fromEA == BADADDR:
                    item = cfunc.body.find_parent_of(item)
                    # TODO Some error here, need further check com.apple.driver.usb.cdc.ecm
                    if None is item:
                        break
                    fromEA = item.ea
                if fromEA != BADADDR:
                    addXref(fromEA, member.id, 1)

def addXrefsForAllStructMems():
    print "[+] Add Xrefs For All Structs' Members"
    decompiledFuncs = decompileAllFuncs()
    for funcEA in decompiledFuncs:
        cfunc = decompiledFuncs[funcEA]
        addXrefsForAllStructMemsInFunc(cfunc)

class UsageType(Enum):
    UNKNOWN=0
    CONDITION=1
    ASSIGN=2
    ASSIGNMEM=3
    FUNCCALL=4
    RETURN=5

def getTheOtherOperandOfOp(opItem, operand):
    if opItem.x == operand:
        return opItem.y
    else:
        return opItem.x

def isPrevOpOnPtrVarValid(opStackOnVRef, currentType):
    return len(opStackOnVRef) == 1 and opStackOnVRef[0][0] == 35 and opStackOnVRef[0][1].op == 61 and currentType.get_ptrarr_objsize() != -1 # only consider const num add on ptr var

LOGIC_COMPARE_OPS = [22, 23, 24, 25, 26, 27, 28, 29, 30, 31] 

def reprOpStack(cfunc, opStack):
    represent = "x"
    for opInfo in opStack:
        op = opInfo[0]
        otherOperand = opInfo[1]
        opname = cexpr_t.op_to_typename[op]
        otherOperandRepr = ""
        if not otherOperand is None:
            if otherOperand.op == 61: # num
                otherOperandRepr = str(otherOperand.n.value(get_int_type_by_width_and_sign(8,1)))
            elif otherOperand.op == 65: # var
                otherOperandRepr = cfunc.lvars[otherOperand.v.idx].name
            elif otherOperand.op == 60: # memptr
                getNameForCMemberExpr(cfunc, otherOperand)
            else:
                otherOperandRepr = otherOperand.opname
        represent = "(" +  represent + " " + opname  + " " + otherOperandRepr + ")"
    return represent
        
def getUsageOfVRefItem(cfunc, vRefItem, usageVarStartPos, isVRefLvarPtr):
    item = vRefItem
    vRefLvarIdx = vRefItem.v.idx
    vRefLvar = cfunc.lvars[vRefLvarIdx]
    vRefLvarType = vRefLvar.tif
    isUsagePtr = isVRefLvarPtr
    usageSize = vRefLvarType.get_size()
    opStackOnVRef = []
    parentItem = cfunc.body.find_parent_of(item).to_specific_type
    while type(parentItem) != idaapi.cinsn_t:
        if parentItem.op == 48: #cast
            if isPrevOpOnPtrVarValid(opStackOnVRef, vRefLvarType):
                addedOffset = (opStackOnVRef[0][1].n.value(get_int_type_by_width_and_sign(8,1))) * vRefLvarType.get_ptrarr_objsize()
                usageVarStartPos = usageVarStartPos + addedOffset
                opStackOnVRef = []
            castType = parentItem.type
            vRefLvarType = castType
            if castType.is_ptr():
                isUsagePtr = True
        elif parentItem.op == 51: # ptr
            if isPrevOpOnPtrVarValid(opStackOnVRef, vRefLvarType):
                addedOffset = (opStackOnVRef[0][1].n.value(get_int_type_by_width_and_sign(8,1))) * vRefLvarType.get_ptrarr_objsize()
                usageVarStartPos = usageVarStartPos + addedOffset
                opStackOnVRef = []
                usageSize = vRefLvarType.get_ptrarr_objsize()
            isUsagePtr = False
        elif parentItem.op == 57: # call
            if parentItem.x.op != 68: # helper
                calledFuncExpr = parentItem.x
                calledFuncEA = get_first_dref_from(parentItem.ea)
                if calledFuncEA is None or calledFuncEA == BADADDR:
                    calledFuncEA = getCalledFuncEAOfCallExpr(cfunc, calledFuncExpr)
                argIndex = len(parentItem.a)-1
                while argIndex >= 0:
                    if parentItem.a[argIndex].to_specific_type == item:
                        break
                    argIndex = argIndex - 1
                if calledFuncEA != BADADDR and argIndex != -1:
                    calledFuncNameDemangled = getDeFuncNameAtEA(calledFuncEA)
                    if calledFuncNameDemangled is None:
                        calledFuncNameDemangled = getName(calledFuncEA)
                    return (UsageType.FUNCCALL, parentItem.ea, calledFuncEA, argIndex, calledFuncNameDemangled), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
                else:
                    return (UsageType.UNKNOWN, parentItem.ea, parentItem, item), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
        elif parentItem.op >= 2 and parentItem.op <= 15: # assign ops
            assignTarget = findAssignTargetOfExprResult(cfunc, item)
            if not assignTarget is None:
                if assignTarget.op == 65: #vref
                    return (UsageType.ASSIGN, parentItem.ea, assignTarget.v.idx), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
                elif assignTarget.op == 60: #memptr
                    member = getMemberForCMemberExpr(assignTarget)
                    return (UsageType.ASSIGNMEM, parentItem.ea, member, get_member_fullname(member.id)), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
            else:
                return (UsageType.UNKNOWN, parentItem.ea, parentItem, item), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
            None
        else:
            opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
            if parentItem.op >= 22 and parentItem.op <= 31 : # logical comparisons
                None
            elif parentItem.op == 17 or parentItem.op == 18 or parentItem.op == 49: # logic or, logic and, logic not
                None
            elif parentItem.op == 58: # idx
                None
        #elif parentItem.op == 35: #add
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 36: #sub
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 37: #mul
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 38 or parentItem.op == 39: #div
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 40 or parentItem.op == 41 : #mod
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 21: #band
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 19: #bor
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))
        #elif parentItem.op == 20: #xor
        #    opStackOnVRef.append((parentItem.op, getTheOtherOperandOfOp(parentItem, item)))

        item = parentItem
        parentItem = cfunc.body.find_parent_of(item).to_specific_type
    if parentItem.op == 73: #if
        return (UsageType.CONDITION, parentItem.ea, parentItem, item), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
    elif parentItem.op == 80: #ret
        return (UsageType.RETURN, parentItem.ea, parentItem, item), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))
    return (UsageType.UNKNOWN, parentItem.ea, parentItem, item), (usageVarStartPos, usageSize, isUsagePtr), (opStackOnVRef, reprOpStack(cfunc, opStackOnVRef))

def getCFuncArgIdxByCallArgIdx(callArgIdx, argTotalNum):
    if argTotalNum <= 2:
        return callArgIdx
    else:
        if callArgIdx == 0 or callArgIdx == 1:
            return callArgIdx + ((argTotalNum - 2) if argTotalNum <=4 else 2)
        elif callArgIdx == 2 or callArgIdx == 3:
            return callArgIdx - 2
        else:
            return callArgIdx

def sortUsageListByPosInVar(usageList):
    return sorted(usageList, key=lambda usage: usage[1][0])

def sortUsageListByUsageEA(usageList):
    return sorted(usageList, key=lambda usage: usage[0][1])

def printMsg(msg):
    print msg
    None

def printUsageList(usageList):
    for usage in usageList:
        print usage[0][0].name, hex(usage[0][1]), usage[1][0], usage[1][1], usage[2][1]
        None

def analyzeInputArgUsageInMethod(methodEA, argIndex, startPosInOrigInput, argSize, isArgPtr):
    propagatedSet = {}
    usageList = []
    cfunc = decompileFuncInTextAtEA(methodEA)
    if cfunc == None:
        return []
    argIndex = getCFuncArgIdxByCallArgIdx(argIndex, len(cfunc.arguments))
    #print argIndex
    argLvar = cfunc.arguments[argIndex]
    argLvarName = argLvar.name
    propagatedSet[argLvarName] = (startPosInOrigInput, argSize, isArgPtr) # argSize -1 stands for not sure of size
    if not cfunc is None:
        cfunc_treeitems = cfunc.treeitems
        for item in cfunc_treeitems:
            item = item.to_specific_type
            if (item.op >= 2 and item.op <= 15): # assign 
                assignTarget = findAssignTargetOfExprResult(cfunc, item.x)
                if not assignTarget is None and assignTarget.op == 65 and cfunc.lvars[assignTarget.v.idx].name in propagatedSet: # stop propagation for reassigned lvars
                    propagatedSet.pop(cfunc.lvars[assignTarget.v.idx].name)
            if item.op == 65: #var
                itemLvarIdx = item.v.idx
                itemLvar = cfunc.lvars[itemLvarIdx]
                itemLvarName = itemLvar.name
                if itemLvarName in propagatedSet:
                    propagatedInfo = propagatedSet[itemLvarName]
                    usage = getUsageOfVRefItem(cfunc, item, propagatedInfo[0], propagatedInfo[2])
                    if not None is usage:
                        usageInfo = usage[0]
                        usageVarLoc = usage[1]
                        usageOpStack = usage[2]

                        usageType = usageInfo[0]
                        usageEA = usageInfo[1]
                        
                        if usageType == UsageType.ASSIGN:
                            assignTargetLVarIdx = usageInfo[2]
                            assignTargetLVar = cfunc.lvars[assignTargetLVarIdx]
                            assignTargetLVarName = assignTargetLVar.name
                            propagatedSet[assignTargetLVarName] = usageVarLoc
                        else:
                            usageList.append(usage)
                            if usageType == UsageType.FUNCCALL:
                                calledFuncEA = usageInfo[2]
                                callArgIdx = usageInfo[3]
                                #print propagatedSet
                                #print hex(usageEA), hex(calledFuncEA), callArgIdx, usageVarLoc
                                usageList.extend(analyzeInputArgUsageInMethod(calledFuncEA, callArgIdx, usageVarLoc[0], usageVarLoc[1], usageVarLoc[2]))
                            elif usageType == UsageType.CONDITION:
                                None
    #print propagatedSet
    usageList = sortUsageListByPosInVar(usageList)
    #for usage in usageList:
    #    print usage 
    return usageList

wait_for_analysis_time = 0

def wait_for_analysis_to_finish():
    print("[+] waiting for analysis to finish...")
    global wait_for_analysis_time
    starttime = time.time()
    idaapi.autoWait()
    idc.Wait()
    endtime = time.time()
    wait_for_analysis_time += endtime-starttime

    print("[+] analysis finished.")

def initHexRaysPlugin():
    wait_for_analysis_to_finish()
    if not idaapi.init_hexrays_plugin():
        print "forcing hexrays to load..."
        load_plugin_decompiler()
    if not idaapi.init_hexrays_plugin():
        raise Exception("hexrays decompiler is not available :(")

#def isBinaryArm64():
#    fileTypeName = idaapi.get_file_type_name()
#    if "Mach-O file" in fileTypeName and fileTypeName.endswith("ARM64"):
#        return True
#    return False

def isBinaryArm():
    return idaapi.get_file_type_name().endswith("ARM")
def isBinaryArm64():
    return "ARM64" in idaapi.get_file_type_name()
def isBinaryX86():
    return idaapi.get_file_type_name().endswith("X86")
def isBinaryX86_64():
    return idaapi.get_file_type_name().endswith("X86_64")

def load_plugin_decompiler():
    # load decompiler plugins (32 and 64 bits, just let it fail)
    print "[+] trying to load decompiler plugins"
    if isBinaryX86_64():
        # 64bit plugins
        idc.RunPlugin("hexx64", 0)
    elif isBinaryX86():
        # 32bit plugins
        idc.RunPlugin("hexrays", 0)
    elif isBinaryX86():
        idc.RunPlugin("hexarm", 0)
    elif isBinaryArm64():
        idc.RunPlugin("hexarm64", 0)
    print "[+] decompiler plugins loaded."


def findUsageOfStructMem(structMemFullName):
    version = getVersionNumber()
    if version < 7.0:
        member = get_member_by_fullname(structMemFullName, None)
    else:
        member = get_member_by_fullname(structMemFullName)
    memId = member.id


def setFuncTypeWithFuncInfo(funcEA, funcInfo, isFuncPtr=False):
    typeToSet = funcInfo.getFuncTypeToSet(isFuncPtr)
    #print "[-]", hex(funcEA), typeToSet
    ret = setFuncType(funcEA, typeToSet)
    if None is ret or ret == False or ret == 0:
        print "[!] SetType {} failed at {:016X}".format(typeToSet, funcEA)
        return False
    return True

def getKernFuncEAByName(funcName):
    startEA = 0
    if isBinaryArm64():
        kernelTextSeg = get_segm_by_name("__TEXT_EXEC:__text")
        if None is kernelTextSeg:
            kernelTextSeg = get_segm_by_name("__TEXT:__text")
        if None is kernelTextSeg:
            kernelTextSeg = get_segm_by_name("__text")
        if None is kernelTextSeg:
            print "[!] Can not find kernel text segment."
        else:
            startEA = kernelTextSeg.startEA
    funcEA = get_name_ea(startEA, funcName)
    #print "[-]", funcName, "at", hex(funcEA)
    return funcEA

import json


def parseKernelHeadersAndSetType():
    global confirmedFuncTypes
    global kernelClassNameSet
    #phase = "parseKernelHeadersAndSetType"
    #if checkPhaseDone(phase):
    #    return
    print "[+] Parse Kernel Headers And Set Type"
    parseResults = loadKernelHeaders()
    parseResultOfAllClasses = parseResults["classes"]
    for className in parseResultOfAllClasses:
        kernelClassNameSet.add(className)
        parseResultOfClass = parseResultOfAllClasses[className]
        for mangledFuncName in parseResultOfClass:
            funcEA = getKernFuncEAByName(mangledFuncName)
            if funcEA != BADADDR:
                funcInfo = parseResultOfClass[mangledFuncName]
                ret = setFuncTypeWithFuncInfo(funcEA, funcInfo, False)
                if ret:
                    keepCon_ItemAndGOTs(funcEA)
                confirmedFuncTypes[funcEA] = getTinfoOfFuncAtEA(funcEA)
        if isBinaryArm64():
            if (className in classNameToVTableAddrMap):
                keepCon_VTAndVTS_ForClass(className)
        elif isBinaryX86_64():
            # In macOS driver binaries, vtables of kernel classes are imported, we need to parse imported structures
            if not isX64BinaryKernel():
                continue
            if className == "OSMetaClass" or className == "OSObject":
                # Too many
                continue
            vtsName = "vtable_" + className
            vtsStructId = GetStrucIdByName(vtsName)
            if vtsStructId != None and vtsStructId != BADADDR:
                vtsStruct = get_struc(vtsStructId)
                childFuncEASetList = getAllChildFuncEAsForClass(className)
                if len(childFuncEASetList) == 0:
                    continue
                for mangledFuncName in parseResultOfClass:
                    funcInfo = parseResultOfClass[mangledFuncName]
                    if funcInfo.isVirtual:
                        vfuncMember = get_member_by_name(vtsStruct, mangledFuncName)
                        if not None is vfuncMember:
                            typeToSet = funcInfo.getFuncTypeToSet(True)
                            SetType(vfuncMember.id, typeToSet)
                            childFuncEAs = childFuncEASetList[vfuncMember.soff/8]
                            for ea in childFuncEAs:
                                changeRetTypeOfFuncAtAddr(ea, funcInfo.returnType)
                        else:
                            print "[?] {} is not in class {}".format(mangledFuncName, className)

    wait_for_analysis_to_finish()
    #markPhaseDone(phase)

def parseClientMemForType():
    None

def parseClientMemForTypeFunc(clientMemForTypeFuncEA):
    funcName = getDeFuncNameAtEA(clientMemForTypeFuncEA)
    if not funcName is None and funcName.endswith():
        None
    None

def gatherInfoAboutInstructions():
    insnInfoMap = {}
    for funcStartEA in Functions():
        func = idaapi.get_func(funcStartEA)
        funcEndEA = func.endEA
        heads = Heads(funcStartEA, funcEndEA)
        for head in heads:
            operator = GetMnem(head)
            if operator not in insnInfoMap:
                insnInfoMap[operator] = 0
            insnInfoMap[operator] += 1
    #for operator in insnInfoMap:
    #    print operator, ": ", insnInfoMap[operator]
    for key, value in sorted(insnInfoMap.iteritems(), key=lambda (k,v): (v,k)):
        print "%s: %s" % (key, value)
    return insnInfoMap


def markPhaseDone(phase):
    # if "." in struct name, then IDA pro will crash
    phase = phase.replace(".", "_")
    if not checkPhaseDone(phase):
        phaseStructName = "__PHASE_" + phase + "__" 
        createClassStruct(phaseStructName, 0)

def checkPhaseDone(phase):
    phaseStructName = "__PHASE_" + phase + "__" 
    strucId = GetStrucIdByName(phaseStructName)
    return strucId != BADADDR


AllControlFlowInsnTraceList = {}
AllControlFlowInsnTraceListByBB = {}

def extractControlFlowTracesOfAllFuncs():
    for funcEA in Functions():
        controlFlowInsnTraceList, controlFlowInsnTraceListByBB = extractControlFlowTracesOfFuncAtEA(funcEA)
        AllControlFlowInsnTraceList[funcEA] = controlFlowInsnTraceList
        AllControlFlowInsnTraceListByBB[funcEA] = controlFlowInsnTraceListByBB


def extractControlFlowTracesOfFuncAtEA(funcEA):
    func = idaapi.get_func(funcEA)
    controlFlowTraces = []
    controlFlowInsnTraceListByBB = []
    controlFlowInsnTraceList = []
    if not func is None:
        flowchart = idaapi.FlowChart(func)
        firstBB = flowchart[0]
        recursivelyExtractControlFlowTracesFromBB(firstBB, [], controlFlowTraces)
        for controlFlowTrace in controlFlowTraces:
            headListByBB = []
            headList = []
            for bb in controlFlowTrace:
                heads = Heads(bb.startEA, bb.endEA)
                headListByBB.append(heads)
                headList.extend(heads)
            controlFlowInsnTraceListByBB.append(headListByBB)
            controlFlowInsnTraceList.append(headList)
            traceStr = ""
            for bb in controlFlowTrace:
                traceStr = traceStr + " -> " + hex(bb.startEA)
            print traceStr
    return controlFlowInsnTraceList, controlFlowInsnTraceListByBB

        
def recursivelyExtractControlFlowTraceFromBB(bb, controlFlowTrace, controlFlowTraces):
    controlFlowTrace.append(bb)
    bbSuccs = list(bb.succs())
    if len(bbSuccs) == 0 or set(bbSuccs).issubset(controlFlowTrace):
        controlFlowTraces.append(controlFlowTrace)
    else:
        for succ in bbSuccs:
            if not succ in controlFlowTrace:
                recursivelyExtractControlFlowTraceFromBB(succ, controlFlowTrace)
    controlFlowTrace.pop()

def createWholeVTableStructForClass(className):
    vtableStructName = "vtable_" + className
    vtableStructId = GetStrucIdByName(vtableStructName)
    #print vtableStructName, hex(vtableStructId)
    wholeVTableStructName = "whole_vtable_" + className
    wholeVTableStructId = GetStrucIdByName(wholeVTableStructName)
    if wholeVTableStructId == BADADDR:
        wholeVTableStructId = AddStrucEx(-1, wholeVTableStructName, 0)
    currentStructSize = GetStrucSize(wholeVTableStructId)
    if currentStructSize <= 0x10:
        AddStrucMember(wholeVTableStructId, "padding", 0, qwrdflag(), -1, 0x10)
        if vtableStructId != BADADDR:
            vtableSize = get_struc_size(vtableStructId)
            AddStrucMember(wholeVTableStructId, "vtable", 0x10, qwrdflag(), -1, vtableSize)
            SetType(GetMemberId(wholeVTableStructId, 0x10), vtableStructName)
    if wholeVTableStructId != BADADDR:
        set_struc_hidden(get_struc(wholeVTableStructId), 1)
    return wholeVTableStructId

import exceptions
def saveLvarTinfoListInFuncAtEA(entry_ea, lvarTypes):
    if getVersionNumber() >= 7.0:
        saveLvarTinfoListInFuncAtEA_70(entry_ea, lvarTypes)
    else:
        saveLvarTinfoListInFuncAtEA_68(entry_ea, lvarTypes)

def saveLvarTinfoListInFuncAtEA_70(entry_ea, lvarTypes):
    class lvar_modifier(idaapi.user_lvar_modifier_t):
        def __init__(self):
            idaapi.user_lvar_modifier_t.__init__(self)
            self.lvarTypesIter = iter(lvarTypes)
            return
        def modify_lvars(self, lvinf):
            # lvinf's type is ida_hexrays.lvar_uservec_t
            for lvarType in lvarTypes:
                # lvarType is a tuple (lvar_t, tinfo_t)
                lvar_saved_info = lvar_saved_info_t()
                lvar = lvarType[0]
                tinfo = lvarType[1]
                #print lvar, tinfo
                lvar_saved_info.ll = lvar
                lvar_saved_info.type = tinfo
                lvinf.lvvec.push_back(lvar_saved_info)
            return True

    modifier = lvar_modifier()
    modify_user_lvars(entry_ea, modifier)

def saveLvarTinfoListInFuncAtEA_68(entry_ea, lvarTypes):
    # First defined the visitor class

    class dump_lvar_info_t(idaapi.user_lvar_visitor_t):
    
        def __init__(self):
            idaapi.user_lvar_visitor_t.__init__(self)
            self.displayed_header = False
            self.lvarTypesIter = iter(lvarTypes)
            return
        
        def get_info_qty_for_saving(self):
            return len(lvarTypes)
        
        def get_info_for_saving(self, lv):
            try:
                lvarType = self.lvarTypesIter.next()
                lvar = lvarType[0]
                tinfo = lvarType[1]
                lv.ll = lvar
                lv.type = tinfo
                #print hex(entry_ea), lvar, tinfo
                return True
            except exceptions.StopIteration as e:
                return False
        
        def handle_retrieved_info(self, lv):
            
            try:
                if not self.displayed_header:
                    self.displayed_header = True;
                    print "------- User defined local variable information"
                
                print "Lvar defined at %x" % (lv.ll.defea, )
                
                if len(str(lv.name)):
                    print "  Name: %s" % (str(lv.name), )
                
                if len(str(lv.type)):
                    #~ print_type_to_one_line(buf, sizeof(buf), idati, .c_str());
                    print "  Type: %s" % (str(lv.type), )
                
                if len(str(lv.cmt)):
                    print "  Comment: %s" % (str(lv.cmt), )
            except:
                traceback.print_exc()
            return 0
    
        def handle_retrieved_mapping(self, lm):
            return 0
        
        def get_info_mapping_for_saving(self):
            return None
    
    # Now iterate over all user definitions
    dli = dump_lvar_info_t();
    idaapi.save_user_lvar_settings(entry_ea, dli)

def saveLvarTypeInFuncAtEA(entry_ea, lvar, tinfo):
    # Display user-defined local variable information
    # First defined the visitor class

    class dump_lvar_info_t(idaapi.user_lvar_visitor_t):
    
        def __init__(self):
            idaapi.user_lvar_visitor_t.__init__(self)
            self.isLvarTypeSaved = False
            return
        
        def get_info_qty_for_saving(self):
            return 1
        
        def get_info_for_saving(self, lv):
            if not self.isLvarTypeSaved:
                self.isLvarTypeSaved = True
                lv.ll = lvar
                lv.type = tinfo
                #print lvar, tinfo
                #print hex(entry_ea), lvar, tinfo
                return True
            else:
                return False
        
        def handle_retrieved_info(self, lv):
            return 0
    
        def handle_retrieved_mapping(self, lm):
            return 0
        
        def get_info_mapping_for_saving(self):
            return None
    
    # Now iterate over all user definitions
    dli = dump_lvar_info_t();
    idaapi.save_user_lvar_settings(entry_ea, dli)

def collectExternalMethodsForClass(className=None):
    # Only consider function with IOExternalMethod
    externalMethods = []
    for funcStartEA in Functions():
        funcType = GetType(funcStartEA)
        demangledFuncName = getDeFuncNameAtEA(funcStartEA)
        if demangledFuncName is None or (not className is None and not demangledFuncName.startswith(className + "::")):
            continue
        if not None is funcType:
            arglist = parseFuncTypeToGetArglist(funcType)
            if arglist != None and len(arglist)>2 and arglist[-2].startswith("void *") and arglist[-1].startswith("IOExternalMethodArguments *"):
                # this is a dispatch method
                externalMethods.append(funcStartEA)
                if len(arglist) > 3 and "::" in demangledFuncName:
                    className = demangledFuncName[:demangledFuncName.find("::")]
                    setNameAndTypeForExternalMethod(funcStartEA, className, True)
            elif demangledFuncName.endswith("::getTargetAndMethodForIndex"):
                # TODO find address from const section in getTargetAndMethodForIndex callback?
                None

    return externalMethods


def collectExternalMethodCallBacksForClass(className=None):
    externalMethodCallBacks = []
    for funcStartEA in Functions():
        funcType = GetType(funcStartEA)
        demangledFuncName = getDeFuncNameAtEA(funcStartEA)
        if demangledFuncName is None or (not className is None and not demangledFuncName.startswith(className + "::")):
            continue
        if demangledFuncName.endswith("::externalMethod") or demangledFuncName.endswith("::getTargetAndMethodForIndex"):
            externalMethodCallBacks.append(funcStartEA)
    return externalMethodCallBacks

def getAllParentForClass(className):
    allParentClasses = set()
    currentClassName = className
    while currentClassName in classNameToParentClassNameMap:
        parentClassName = classNameToParentClassNameMap[currentClassName]
        allParentClasses.add(parentClassName)
        currentClassName = parentClassName
    return allParentClasses

def getDescendantsForClass(parentClassName):
    #print "getDescendantsForClass {}".format(parentClassName)
    descendantsClassNameSet = set()
    if not parentClassName in classNameToChildClassNameSetMap:
        childClassNameSet = set()
        for className in classNameToParentClassNameMap:
            if classNameToParentClassNameMap[className] == parentClassName:
                childClassNameSet.add(className)
        classNameToChildClassNameSetMap[parentClassName] = childClassNameSet
    childClassNameSet = classNameToChildClassNameSetMap[parentClassName]
    classNameList = list(childClassNameSet)
    total = len(classNameList)
    while total > 0:
        #print classNameList
        currentClassName = classNameList.pop()
        descendantsClassNameSet.add(currentClassName)
        if currentClassName in classNameToChildClassNameSetMap:
            currentChildClassNameSet = classNameToChildClassNameSetMap[currentClassName]
            classNameList.extend(list(currentChildClassNameSet))
        total = len(classNameList)

    return descendantsClassNameSet

def isClassDescendantOfClass(descendantClassName, ancestorClassName):
    #print classNameToParentClassNameMap
    if (None is descendantClassName) or (None is ancestorClassName):
        return False
    if ancestorClassName == "OSObject":
        return True
    currentClassName = descendantClassName
    while currentClassName in classNameToParentClassNameMap:
        currentParentClassName = classNameToParentClassNameMap[currentClassName]
        if currentParentClassName == ancestorClassName:
            return True
        if currentParentClassName == None:
            return False
        currentClassName = currentParentClassName
    return False

def collectCallableUserClients():
    externalMethodCBs = collectExternalMethodCallBacksForClass()
    callableUCNames = set()
    for cbEA in externalMethodCBs:
        demangledFuncName = getDeFuncNameAtEA(cbEA)
        if not None is demangledFuncName and "::" in demangledFuncName:
            UCClassName = demangledFuncName[:demangledFuncName.find("::")]
            callableUCNames.add(UCClassName)
            UCDescentantNames = getDescendantsForClass(UCClassName)
            callableUCNames.union(UCDescentantNames)
        else:
            print "[!] Something wrong at ", hex(cbEA)

    for callableUCName in callableUCNames:
        print callableUCName

    return callableUCNames

def getBBAtEA(ea):
    func = get_func(ea)
    if None is func:
        return None
    fc = FlowChart(func, None, FC_PREDS)
    for bb in fc:
        if bb.startEA <= ea and bb.endEA > ea:
            return bb
    return None

def getArgListForFuncAtEA(funcStartEA):
    funcType = GetType(funcStartEA)
    return parseFuncTypeToGetArglist(funcType)


def collectUserEntriesWithUserInputForClass(className=None):
    userEntries = {}
    for funcStartEA in Functions():
        funcDemangledName = getDeFuncNameAtEA(funcStartEA)
        if funcDemangledName is None or (not className is None and not funcDemangledName.startswith(className + "::")):
            continue
        if "::" in funcDemangledName:
            basicFuncName = funcDemangledName[funcDemangledName.find("::")+2:]
            if basicFuncName == "externalMethod":
                userEntries[funcStartEA] = [(1, "reference"), (2, "IOExternalMethodArguments")]
            elif basicFuncName == "getTargetAndMethodForIndex":
                None

                
    externalMethods = collectExternalMethodsForClass(className)
    print "externalMethods", externalMethods
    externalMethodCallBacks = collectExternalMethodCallBacksForClass(className)
    userEntries.extend(externalMethods)
    userEntries.extend(externalMethodCallBacks)
    return userEntries 

    
    None

UserEntryCallBacks = ["clientClose", "registerNotificationPort", "clientMemoryForType"]
def collectUserEntryFuncsForClass(className=None):
    userEntryFuncs = []
    for funcStartEA in Functions():
        funcDemangledName = getDeFuncNameAtEA(funcStartEA)
        if funcDemangledName is None or (not className is None and not funcDemangledName.startswith(className + "::")):
            continue
        if "::" in funcDemangledName:
            basicFuncName = funcDemangledName[funcDemangledName.find("::")+2:]
            if basicFuncName in UserEntryCallBacks:
                userEntryFuncs.append(funcStartEA)
    externalMethods = collectExternalMethodsForClass(className)
    print "externalMethods", externalMethods
    externalMethodCallBacks = collectExternalMethodCallBacksForClass(className)
    userEntryFuncs.extend(externalMethods)
    userEntryFuncs.extend(externalMethodCallBacks)
    return userEntryFuncs

def isSameFunc(ea1, ea2):
    func1 = get_func(ea1)
    func2 = get_func(ea2)
    return not None is func1 and not None is func2 and func1.startEA == func2.startEA
    
def splitRegOffAddr(regOffAddr):
    regOffAddrParts = regOffAddr.split("+")
    result = []
    for regOffAddrPart in regOffAddrParts:
        if "-" in regOffAddrPart:
            negParts = regOffAddrPart.split("-")
            for i in range(1, len(negParts)):
                negParts[i] = "-" + negParts[i]
            result.extend(negParts)
        else:
            result.append(regOffAddrPart)
    return result

def getMemberTypeAtOff(classType, memberOff):
    result = None
    classType = classType.strip()
    if classType[-1] == "*":
        classType = classType[:classType.find("*")].strip()
    classStructId = GetStrucIdByName(classType)
    memberId = GetMemberId(classStructId, memberOff)
    result = GetType(memberId)
    return result

def setMemberTypeAtOff(classType, memberOff, newType, isOverride):
    result = None
    classType = classType.strip()
    if classType[-1] == "*":
        classType = classType[:classType.find("*")].strip()
    classStructId = GetStrucIdByName(classType)
    memberId = GetMemberId(classStructId, memberOff)
    oldType = GetType(memberId)
    if oldType is None or oldType == "" or oldType == "?" or isOverride:
        SetType(memberId, newType)

def findRootClasses():
    rootClassSet = set()
    global classNameToVTableAddrMap
    global classNameToParentClassNameMap
    for className in classNameToVTableAddrMap:
        if not className in classNameToParentClassNameMap and not className.endswith("::MetaClass"):
            rootClassSet.add(className)
    return rootClassSet

def getRegIdFromRegName(regName):
    ri = reg_info_t()
    ret = parse_reg_name(regName, ri)
    if ret:
        return ri.reg
    else:
        #print "[!] Unrecognized reg, ", regName
        return None

def findSignedCMP():
    for funcStartEA in Functions():
        func = get_func(funcStartEA)
        funcEndEA = func.endEA
        currentEA = funcStartEA
        insnEAs = Heads(funcStartEA, funcEndEA)
        for insnEA in insnEAs:
            op = GetMnem(insnEA)
            if op[:2] == "jg" or op[:2] == "jl":
                print "signed compare at ", hex(insnEA), " in ", hex(funcStartEA)#, getDeFuncNameAtEA(funcStartEA)

def makeCodeInTextSections():
    for segStartEA in Segments():
        segName = get_segm_name(segStartEA)
        segEndEA = SegEnd(segStartEA)
        if segName.endswith("__text"):
            for head in Heads(segStartEA, segEndEA):
                op = GetMnem(head)
                if op == "":
                    MakeCode(head)

def getAllKEXTNameSet():
    allKextNameSet = set()
    for segStartEA in Segments():
        segName = get_segm_name(segStartEA)
        segNamePrefix = segName[:segName.find(":")]
        allKextNameSet.add(segNamePrefix)
    return allKextNameSet

def getBytesOfFuncAtEA(funcEA):
    func = get_func(funcEA)
    return getBytesOfFunc(func)

def getBytesOfFunc(func):
      code = ""
      for byte in idc.GetManyBytes(func.startEA, func.endEA-func.startEA):
  	 code += byte
      return code

def parseSwitchTable(startEA, endEA):
    switchBaseEA = startEA
    for currentEA in range(startEA, endEA, 4):
        MakeData(currentEA, 536870912, 4, 0)
        switchOffset = 0x100000000 - Dword(currentEA)
        switchTarget = switchBaseEA-switchOffset
        MakeComm(currentEA, hex(switchTarget)) # set comment to be the target ea

dataStructLogFileName = thisFileName[:thisFileName.find(".")] + "_dataStruct.plist"
dataStructLogFilePath = os.path.join(os.path.dirname(thisFilePath), dataStructLogFileName)

def loadDataStructs():
    if os.path.isfile(dataStructLogFilePath):
        dataStructs = {}
        dataStructs["classNameToParentClassNameMap"] = classNameToParentClassNameMap 
        dataStructs["classNameToParentMetaClassAddrMap"] = classNameToParentMetaClassAddrMap 
        dataStructs["classNameToVTableAddrMap"] = classNameToVTableAddrMap 
        dataStructs["classNameToVTableStructIdMap"] = classNameToVTableStructIdMap 
        dataStructs["classNameToClassStructIdMap"] = classNameToClassStructIdMap 
        dataStructs["predefinedStructNameToIdMap"] = predefinedStructNameToIdMap 
        dataStructs["classNameToVTableFuncEAListMap"] = classNameToVTableFuncEAListMap 
        dataStructs["virtualFuncEASet"] = virtualFuncEASet 
        dataStructs["predefinedClassNameSet"] = predefinedClassNameSet 
        dataStructs["classNameToWholeVTableStructIdMap"] = classNameToWholeVTableStructIdMap 
        dataStructs["classNameToChildClassNameSetMap"] = classNameToChildClassNameSetMap 
        dataStructs["classNameToVirtualCFuncInfoMap"] = classNameToVirtualCFuncInfoMap 
    None

def logDataStructs():
    dataStructs = {}
    dataStructs["classNameToParentClassNameMap"] = classNameToParentClassNameMap 
    dataStructs["classNameToParentMetaClassAddrMap"] = classNameToParentMetaClassAddrMap 
    dataStructs["classNameToVTableAddrMap"] = classNameToVTableAddrMap 
    dataStructs["classNameToVTableStructIdMap"] = classNameToVTableStructIdMap 
    dataStructs["classNameToClassStructIdMap"] = classNameToClassStructIdMap 
    dataStructs["predefinedStructNameToIdMap"] = predefinedStructNameToIdMap 
    dataStructs["classNameToVTableFuncEAListMap"] = classNameToVTableFuncEAListMap 
    dataStructs["virtualFuncEASet"] = virtualFuncEASet 
    dataStructs["predefinedClassNameSet"] = predefinedClassNameSet 
    dataStructs["classNameToWholeVTableStructIdMap"] = classNameToWholeVTableStructIdMap 
    dataStructs["classNameToChildClassNameSetMap"] = classNameToChildClassNameSetMap 
    dataStructs["classNameToVirtualCFuncInfoMap"] = classNameToVirtualCFuncInfoMap 
    biplist.writePlist(dataStructs, dataStructLogFilePath)

   
def clearAllInternalData():
    global classNameToParentClassNameMap
    global classNameToParentMetaClassAddrMap
    global classNameToVTableAddrMap 
    global classNameToVTableStructIdMap 
    global classNameToClassStructIdMap 
    global predefinedStructNameToIdMap 
    global classNameToVTableFuncEAListMap 
    global virtualFuncEASet 
    global predefinedClassNameSet 
    global classNameToWholeVTableStructIdMap 
    global classNameToChildClassNameSetMap 
    global classNameToVirtualCFuncInfoMap 
    global funcEAToCFuncMap
    classNameToParentClassNameMap = {"IOService":"IORegistryEntry", "IOUserClient":"IOService"}
    classNameToParentMetaClassAddrMap.clear()
    classNameToVTableAddrMap.clear()
    classNameToVTableStructIdMap.clear()
    classNameToClassStructIdMap.clear()
    predefinedStructNameToIdMap.clear()
    classNameToVTableFuncEAListMap.clear()
    virtualFuncEASet.clear()
    predefinedClassNameSet.clear()
    classNameToWholeVTableStructIdMap.clear()
    classNameToChildClassNameSetMap.clear()
    classNameToVirtualCFuncInfoMap.clear()


def getArgListFromArgString(argString):
    if argString[0] == "(" and argString[-1] == ")":
        argString = argString[1:-1]
    if argString.strip() == "":
        return ["void"]
    argList = argString.split(",")
    for i in range(0, len(argList)):
        arg = argList[i]
        argList[i] = arg.strip()
    return argList

netNodeDB = None
PERSIST_NODE_NAME_CLASSINFOS = "classinfos.iDEA.PersistData"
PERSIST_NODE_NAME_ANALYSIS = "analysis.iDEA.PersistData"

def getiDEAPersistNode(persistNodeName):
    return m_netnode.Netnode(persistNodeName)

def killiDEAPersistNode(persistNodeName):
    m_netnode.Netnode(persistNodeName).kill()

def setPersistData(name, data, persistNodeName=PERSIST_NODE_NAME_CLASSINFOS):
    n = getiDEAPersistNode(persistNodeName)
    #n[name] = None
    n[name] = data

def byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            byteify(key, ignore_dicts=True): byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data

PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES="class2parentClassNames"
PERSIST_TAG_OF_CLASS_2_PARENT_META_CLASS_ADDRS = "class2parentMetaClassAddrs"
PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS = "class2vtableAddrs"
PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS ="class2vtableStructIds"
PERSIST_TAG_OF_CLASS_2_MODULE_NAMES="class2moduleNames"
PERSIST_TAG_OF_MODULE_2_CLASS_NAMES="module2classNames"
PERSIST_TAG_OF_KERNEL_CLASSES="kernelclasses"

PersistTag2DataStructNameMap = {
        PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES: "classNameToParentClassNameMap",
        PERSIST_TAG_OF_CLASS_2_PARENT_META_CLASS_ADDRS: "classNameToParentMetaClassAddrMap",
        PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS: "classNameToVTableAddrMap", 
        PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS: "classNameToVTableStructIdMap",
        PERSIST_TAG_OF_CLASS_2_MODULE_NAMES: "classNameToModuleNameMap",
        PERSIST_TAG_OF_MODULE_2_CLASS_NAMES: "moduleNameToClassNamesMap",
        PERSIST_TAG_OF_KERNEL_CLASSES: "kernelClassNameSet"
        }

def getGlobalDataOfName(name):
    import sys
    data = getattr(sys.modules[__name__], name)
    return data

import zlib
def getPersistData(name, persistNodeName=PERSIST_NODE_NAME_CLASSINFOS, repairIfFaile=False):
    n = getiDEAPersistNode(persistNodeName)
    n_keys = n.keys()
    try:
        if not name in n:
            dataStructName = PersistTag2DataStructNameMap[name]
            data = getGlobalDataOfName(dataStructName)
            n[name] = data
        return byteify(n[name])
    except (m_netnode.netnode.NetnodeCorruptError, zlib.error) as e:
        if repairIfFaile:
            print "[!] %s corrupted"%(name)
            dataStructName = PersistTag2DataStructNameMap[name]
            data = getGlobalDataOfName(dataStructName)
            setPersistData(name, data, persistNodeName)
            return data
    return None

def loadNecessaryDataFromPersistNode():
    data = getPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES)
    if data:
        classNameToParentClassNameMap.update(data)
        classNameToChildClassNameSetMap.update(invertDict(classNameToParentClassNameMap))
    data = getPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_META_CLASS_ADDRS)
    if data:
        classNameToParentMetaClassAddrMap.update(data)
    data = getPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS)
    if data:
        classNameToVTableAddrMap.update(data)
    data = getPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS)
    if data: 
        classNameToVTableStructIdMap.update(data)
    data = getPersistData(PERSIST_TAG_OF_CLASS_2_MODULE_NAMES)
    if data:
        classNameToModuleNameMap.update(data)
        moduleNameToClassNamesMap.update(invertDict(classNameToModuleNameMap))
    data = getPersistData(PERSIST_TAG_OF_KERNEL_CLASSES)
    if data:
        kernelClassNameSet.update(set(data))

def storeNecessaryClassInfoInPersistNode():
    setPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES, classNameToParentClassNameMap)
    setPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_META_CLASS_ADDRS, classNameToParentMetaClassAddrMap)
    setPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS, classNameToVTableAddrMap)
    setPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS, classNameToVTableStructIdMap)
    setPersistData(PERSIST_TAG_OF_CLASS_2_MODULE_NAMES, classNameToModuleNameMap)
    setPersistData(PERSIST_TAG_OF_KERNEL_CLASSES, list(kernelClassNameSet))

def clearNecessaryClassInfoInPersistNode():
    n = getiDEAPersistNode(PERSIST_NODE_NAME_CLASSINFOS)
    n[PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES]    = {}
    n[PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS]          = {}
    n[PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS]     = {}
    n[PERSIST_TAG_OF_CLASS_2_MODULE_NAMES]          = {}
    n[PERSIST_TAG_OF_KERNEL_CLASSES]                = {}

def getParentClassNameOfClass(className):
    if className in classNameToParentClassNameMap:
        return classNameToParentClassNameMap[className]
    superClassName = "__ZN" + getMangledNameOfName(className) + "10superClassE"
    superClassAddr = get_name_ea(0, superClassName)
    if superClassAddr != BADADDR:
        parentClassGMetaClassName = getName(Qword(superClassAddr))
        gMetaClassDemangledName = getDeNameOfName(parentClassGMetaClassName)
        if not None is gMetaClassDemangledName:
            parentClassName = gMetaClassDemangledName[:gMetaClassDemangledName.rfind("::")]
            classNameToParentClassNameMap[className] = parentClassName
            #persistParentClassNames[className] = parentClassName
            #setPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES, persistParentClassNames)
            return parentClassName
    persistParentClassNames = getPersistData(PERSIST_TAG_OF_CLASS_2_PARENT_CLASS_NAMES)
    if not persistParentClassNames is None and className in persistParentClassNames:
        return persistParentClassNames[className]
    else:
        return None

def getMangledNameOfName(demangledName):
    nameParts = demangledName.split("::")
    result = ""
    for namePart in nameParts:
        result += str(len(namePart)) + namePart
    return result

def storeClassVTableAddrInPersistNode(className, vtableStartEA, vtableEndEA):
    #print "vtableFoundForClass", className, vtableStartEA, vtableEndEA, vtableStructId
    persistVTableAddrs = getPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS)
    persistVTableAddrs[className] = (vtableStartEA, vtableEndEA)
    setPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS, persistVTableAddrs)

def storeClassVTableStructIdInPersistNode(className, vtableStructId):
    print "[+] storeClassVTableStructIdInPersistNode", className, hex(vtableStructId)
    persistVTableStructIds = getPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS)
    persistVTableStructIds[className] = vtableStructId
    setPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS, persistVTableStructIds)

def getVTableAddrOfClass(className):
    #traceback.print_stack()
    if None is className:
        return BADADDR, BADADDR
    if className in classNameToVTableAddrMap:
        vtStartEA, vtEndEA = classNameToVTableAddrMap[className]
        if isEAValid(vtStartEA) and isEAValid(vtEndEA):
            return vtStartEA, vtEndEA
    mangledClassName = getMangledNameOfName(className)
    if "::" in className:
        mangledClassName = "N" + mangledClassName + "E"
    vtableName = "__ZTV" + mangledClassName
    vtableStartEA  = get_name_ea(0, vtableName)
    vtSegName = getSegName(vtableStartEA)
    if vtSegName == "UNDEF":
        # For macOS, external VTable has name but no data
        return BADADDR, BADADDR
    if not None is vtableStartEA and vtableStartEA != BADADDR:
        vtableStartEA += 0x10
        vtableEndEA = vtableStartEA
        while Qword(vtableEndEA) != 0:
            vtableEndEA = vtableEndEA + 8
        classNameToVTableAddrMap[className] = (vtableStartEA, vtableEndEA)
        #storeClassVTableAddrInPersistNode(className, vtableStartEA, vtableEndEA)
        return vtableStartEA, vtableEndEA

    persistVTableAddrs = getPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_ADDRS)
    if not None is persistVTableAddrs and className in persistVTableAddrs:
        return persistVTableAddrs[className]
    #if isBinaryArm64():
    #    print "[!] VTable not found for {}".format(className)
    return BADADDR, BADADDR

def getVTableStructIdOfClass(className):
    if className in classNameToVTableStructIdMap:
        return classNameToVTableStructIdMap[className]
    vtableStructName = "vtable_" + className
    vtableStructId = GetStrucIdByName(vtableStructName)
    if not None is vtableStructId and vtableStructId != BADADDR:
        classNameToVTableStructIdMap[className] = vtableStructId
        return vtableStructId
        #storeClassVTableStructIdInPersistNode(className, vtableStructId)
    persistVTableStructIds = getPersistData(PERSIST_TAG_OF_CLASS_2_VTABLE_STRUCT_IDS)
    if not None is persistVTableStructIds and className in persistVTableStructIds:
        return persistVTableStructIds[className]
    #print "[!] VTable structId not found for", className
    return vtableStructId


def getAllClassNames():
    allClassNames = list(classNameToModuleNameMap.keys())
    allClassNames.extend(list(kernelClassNameSet))
    return allClassNames

def ensureAllNecessaryDataPreparedAndStored():
    allClassNames = list(classNameToModuleNameMap.keys())
    allClassNames.extend(list(kernelClassNameSet))
    for className in allClassNames:
        getVTableStructIdOfClass(className)
        getParentClassNameOfClass(className)
        getVTableAddrOfClass(className)
    storeNecessaryClassInfoInPersistNode()

def storeClassModuleInPersistNode(className, kextPrefix):
    persistModuleNames = getPersistData(PERSIST_TAG_OF_CLASS_2_MODULE_NAMES)
    if not className in persistModuleNames:
        persistModuleNames[className] = kextPrefix
    setPersistData(PERSIST_TAG_OF_CLASS_2_MODULE_NAMES, persistModuleNames)

    persistModule2ClassNames = getPersistData(PERSIST_TAG_OF_MODULE_2_CLASS_NAMES)
    if kextPrefix in persistModule2ClassNames:
        if not className in persistModule2ClassNames[kextPrefix]:
            persistModule2ClassNames[kextPrefix].append(className)
    else:
        persistModule2ClassNames[kextPrefix] = [className]
    setPersistData(PERSIST_TAG_OF_MODULE_2_CLASS_NAMES, persistModule2ClassNames)

def classNameFoundInKEXT(className, kextPrefix):
    if kextPrefix == "__DATA_CONST" or kextPrefix == "__DATA":
        kernelClassNameSet.add(className)
    else:
        if not kextPrefix in moduleNameToClassNamesMap:
            moduleNameToClassNamesMap[kextPrefix] = set()
        moduleNameToClassNamesMap[kextPrefix].add(className)
        classNameToModuleNameMap[className] = kextPrefix
    #storeClassModuleInPersistNode(className, kextPrefix)

def getKEXTPrefixOfClass(className):
    if className in classNameToModuleNameMap:
        return classNameToModuleNameMap[className]
    persistModuleNames = getPersistData(PERSIST_TAG_OF_CLASS_2_MODULE_NAMES)
    if not className in persistModuleNames:
        return persistModuleNames[className]
    return None

#def getClassNamesOfKEXT(kextPrefix):
#    if kextPrefix in moduleNameToClassNamesMap:
#        return moduleNameToClassNamesMap[kextPrefix]
#    persistModule2ClassNames = getPersistData(PERSIST_TAG_OF_MODULE_2_CLASS_NAMES)
#    if kextPrefix in persistModule2ClassNames:
#        return persistModule2ClassNames[kextPrefix]
#    return None

def getClassNameOfFuncAtEA(funcStartEA):
    funcName = getName(funcStartEA)
    className = None
    funcDemangledName = getDeFuncNameOfName(funcName)
    if not None is funcDemangledName:
        funcName = funcDemangledName
    if "::" in funcName:
        className = funcName[:funcName.rfind("::")]
    return className

def invertDict(src):
    dst = {}
    for key in src:
        value = src[key]
        if not value in dst:
            dst[value] = set()
        dst[value].add(key)
    return dst



def getXRefsTo(ea, findDataRef=True, findCodeRef=True):
    allRefs = []
    if findDataRef:
        xref = get_first_dref_to(ea)
        while xref != None and xref != BADADDR:
            allRefs.append(xref)
            xref = get_next_dref_to(ea, xref)
    if findCodeRef:
        xref = get_first_cref_to(ea)
        while xref != None and xref != BADADDR:
            allRefs.append(xref)
            xref = get_next_cref_to(ea, xref)
    return allRefs

def callGraphEdgeFound(fromEA, toEA, funcStartEA=None, callGraph=None):
    callGraph_selected = callGraph_FuncEA2Calls if None is callGraph else callGraph
    if fromEA == BADADDR or toEA == BADADDR or fromEA == -1 or toEA == -1 or fromEA == 0 or toEA == 0 or None is getName(toEA):
        return 
    if None is funcStartEA:
        funcStartEA = get_fchunk_attr(fromEA, FUNCATTR_START)
    if not funcStartEA in callGraph_selected:
        callGraph_selected[funcStartEA] = {}
    if not fromEA in callGraph_selected[funcStartEA]:
        callGraph_selected[funcStartEA][fromEA] = set()
    callGraph_selected[funcStartEA][fromEA].add(toEA)
    addXref(fromEA, toEA, 1, False)

def isTinfoInterested(tinfo):
    if None is tinfo:
        return False
    if not isinstance(tinfo, tinfo_t):
        return False
    if tinfo.is_struct():
        return True
    if str(tinfo) == "mach_port_t":
        return True
    if str(tinfo) == "task" or str(tinfo) == "task*" or str(tinfo) == "task *":
        return True
    #if tinfo.is_ptr() and tinfo.get_pointed_object().is_struct():
    if tinfo.is_funcptr():
        return False
    #if tinfo.is_ptr() and (not tinfo.get_pointed_object().is_void()):
    if str(tinfo).replace("*", "").strip() == "void":
        return False
    if tinfo.is_ptr() and (tinfo.get_pointed_object().is_ptr() or tinfo.get_pointed_object().is_struct()):
        return True
    return False

def funcRetTypeFound(funcStartEA, retType):
    if type(retType) == str:
        retType = getTinfoForTypeStr(retType)
    if isTinfoInterested(retType):
        if not funcStartEA in varTinfos_FuncEA2Ret: 
            varTinfos_FuncEA2Ret[funcStartEA] = retType
        elif str(varTinfos_FuncEA2Ret[funcStartEA]) != str(retType):
            print "[?] We inferred a different ret type {} of func {:016X} (ret: {})".format(str(retType), funcStartEA, str(varTinfos_FuncEA2Ret[funcStartEA]))

def getTinfoAtEA(ea):
    t = tinfo_t()
    if ida_nalt.get_tinfo(t, ea):
        return t
    else:
        return isVTTinfoAtEA(ea)

def isVTTinfoAtEA(ea):
    if getSegName(ea).endswith("__const"):
        name = getName(ea)
        name_0x10 =  getName(ea-0x10)
        if not None is name:
            if name.startswith("__ZTV"):
                deName = getDeNameAtEA(ea)
                className = deName[len("`vtable for'"):]
                return getTinfoForTypeStr("struct whole_vtable_{}".format(className))
            elif name_0x10.startswith("__ZTV"):
                deName = getDeNameAtEA(ea-0x10)
                className = deName[len("`vtable for'"):]
                return getTinfoForTypeStr("struct vtable_{}".format(className))
    return None

def getTinfoOfFunc(func):
    return getTinfoOfFuncAtEA(func.startEA)

def getTinfoOfFuncAtEA(funcEA):
    funcTinfo = tinfo_t()
    if ida_nalt.get_tinfo(funcTinfo, funcEA):
        return funcTinfo
    else:
        funcType = GetType(funcEA)
        if None is funcType:
            funcType = GuessType(funcEA)
        if not None is funcType:
            funcType = funcType.replace("__cdecl", "")
            funcType = funcType.replace("__fastcall", "")
            funcType = funcType.strip()
            funcType = funcType[:funcType.find("(")] + getName(funcEA) + funcType[funcType.find("("):]
            funcTinfo = getTinfoForTypeStr(funcType)
            return funcTinfo
    return None


def getRetTinfoOfFuncAtEA(funcEA, onlyInterested=True):
    if funcEA in varTinfos_FuncEA2Ret:
        return varTinfos_FuncEA2Ret[funcEA]
    returnTinfo = None
    funcTinfo = getTinfoOfFuncAtEA(funcEA)
    if not None is funcTinfo:
        returnTinfo = funcTinfo.get_rettype()
    else:
        funcType = GetType(funcEA)
        if None is funcType:
            funcType = GuessType(funcEA)
        if not None is funcType:
            funcRetType = funcType[:funcType.find("(")]
            funcRetType = funcRetType.replace("__cdecl", "")
            funcRetType = funcRetType.replace("__fastcall", "")
            funcRetType = funcRetType.replace("const ", "")
            funcRetType = funcRetType.strip()
            returnType = funcRetType
            returnTinfo = getTinfoForTypeStr(returnType)
    if not None is returnTinfo:
        if onlyInterested:
            if isTinfoInterested(returnTinfo):
                funcRetTypeFound(funcEA, returnTinfo)
            else:
                returnTinfo = None
    return returnTinfo

def isFuncVirtual(funcEA):
    xref = get_first_dref_to(funcEA)
    while xref != None and xref != BADADDR:
        if is_member_id(xref):
            return True
        xref = get_next_dref_to(funcEA, xref)
    return False


def composeFuncType(arglist, funcName="dummyFunc", returnType="uint64_t"):
    funcName = funcName.replace(".", "_")
    funcType = str(returnType) + " " + funcName + "("
    for i in range(0, len(arglist)):
        arglist[i] = str(arglist[i])
    if len(arglist) == 0 :
        funcType = funcType + "void"
    else:
        funcType += ", ".join(arglist)
    funcType += ")"
    return funcType

def funcArgTypeFound(funcStartEA, argIdx, argType):
    oldFuncTinfo = getTinfoOfFuncAtEA(funcStartEA)
    if None is oldFuncTinfo:
        forceFunction(funcStartEA)
    oldFuncTinfo = getTinfoOfFuncAtEA(funcStartEA)
    func_nargs = 0
    ret_type = "uint64_t"
    arglist = []
    if not None is oldFuncTinfo:
        ret_type = oldFuncTinfo.get_rettype()
        func_nargs = oldFuncTinfo.get_nargs()
        for i in range(0, func_nargs):
            arglist.append(str(oldFuncTinfo.get_nth_arg(i)))
    else:
        print "[?] Old func type None at {:016X}".format(funcStartEA)
    if argIdx+1 > len(arglist):
        for i in range(len(arglist), argIdx+1):
            arglist.append("uint64_t")
    arglist[argIdx] = str(argType)
    funcName = getName(funcStartEA)
    funcType = composeFuncType(arglist, funcName, ret_type)
    setTypeForFuncAtEA(funcStartEA, funcType)


def funcArgsTypesFound(funcStartEA, argTypes):
    oldFuncTinfo = getTinfoOfFuncAtEA(funcStartEA)
    if None is oldFuncTinfo:
        forceFunction(funcStartEA)
    oldFuncTinfo = getTinfoOfFuncAtEA(funcStartEA)
    func_nargs = 0
    ret_type = "uint64_t"
    arglist = []
    if not None is oldFuncTinfo:
        ret_type = oldFuncTinfo.get_rettype()
        func_nargs = oldFuncTinfo.get_nargs()
        func_nargs = 8 if func_nargs > 8 else func_nargs
        for i in range(0, func_nargs):
            arglist.append(str(oldFuncTinfo.get_nth_arg(i)))
    else:
        print "[?] Old func type None at {:016X}".format(funcStartEA)
    maxArgIdx = sorted(argTypes.keys())[-1]
    maxArgIdx = 8 if maxArgIdx > 8 else maxArgIdx
    #print "{:016X} {} {}".format(funcStartEA, argTypes, maxArgIdx)
    if maxArgIdx+1 > len(arglist):
        for i in range(len(arglist), maxArgIdx+1):
            arglist.append("uint64_t")
    for argIdx in argTypes:
        arglist[argIdx] = str(argTypes[argIdx])

    funcName = getName(funcStartEA)
    funcType = composeFuncType(arglist, funcName, ret_type)
    setTypeForFuncAtEA(funcStartEA, funcType)

def getFuncArgOfFuncAtEA(funcEA, argIdx):
    if (funcEA in varTinfos_FuncEA2Args) and (argIdx < len(varTinfos_FuncEA2Args[funcEA])) and (not None is varTinfos_FuncEA2Args[funcEA][argIdx]):
        return varTinfos_FuncEA2Args[funcEA][argIdx]
    funcTinfo = getTinfoOfFuncAtEA(funcEA)
    argTinfo = None
    if not None is funcTinfo:
        if argIdx < funcTinfo.get_nargs():
            argTinfo = funcTinfo.get_nth_arg(argIdx)
    if not None is argTinfo and isTinfoInterested(argTinfo):
        funcArgTypeFound(funcEA, argIdx, argTinfo)
        return argTinfo
    else:
        return None

#PERSIST_TAG_OF_CALLGRAPH = "callGraph_FuncEA2Calls"
PERSIST_TAG_OF_VARTYPES_FUNCARGS = "varTypes_FuncEA2Args"
PERSIST_TAG_OF_VARTYPES_FUNCRET = "varTypes_FuncEA2Ret"
PERSIST_TAG_OF_SMETHODS_METHODDISATCH = "sMethods_MethodDispatch"
PERSIST_TAG_OF_SMETHODS_METHOD = "sMethods_Method"


def loadAnalysisResults():
    #stored_callGraph_FuncEA2Calls   = getPersistData(PERSIST_TAG_OF_CALLGRAPH, PERSIST_NODE_NAME_ANALYSIS)
    #stored_varTinfos_FuncEA2Args     = getPersistData(PERSIST_TAG_OF_VARTYPES_FUNCARGS, PERSIST_NODE_NAME_ANALYSIS)
    #stored_varTinfos_FuncEA2Ret     = getPersistData(PERSIST_TAG_OF_VARTYPES_FUNCRET, PERSIST_NODE_NAME_ANALYSIS)
    stored_sMethods_MethodDispatch  = getPersistData(PERSIST_TAG_OF_SMETHODS_METHODDISATCH, PERSIST_NODE_NAME_ANALYSIS)
    stored_sMethods_Method          = getPersistData(PERSIST_TAG_OF_SMETHODS_METHOD, PERSIST_NODE_NAME_ANALYSIS)
    
    #callGraph_FuncEA2Calls.update(stored_callGraph_FuncEA2Calls )
    #varTinfos_FuncEA2Args.update(stored_varTinfo_FuncEA2Args)
    #varTinfos_FuncEA2Ret.update(stored_varTinfos_FuncEA2Ret)   
    className2SMethods_MethodDispatch.update(stored_sMethods_MethodDispatch)
    className2SMethods_Method.update(stored_sMethods_Method)        



def storeAnalysisResults():
    #setPersistData(PERSIST_TAG_OF_CALLGRAPH, callGraph_FuncEA2Calls, PERSIST_NODE_NAME_ANALYSIS)
    #setPersistData(PERSIST_TAG_OF_VARTYPES_FUNCARGS, varTinfos_FuncEA2Args, PERSIST_NODE_NAME_ANALYSIS)
    #setPersistData(PERSIST_TAG_OF_VARTYPES_FUNCRET, varTinfos_FuncEA2Ret, PERSIST_NODE_NAME_ANALYSIS)
    setPersistData(PERSIST_TAG_OF_SMETHODS_METHODDISATCH, className2SMethods_MethodDispatch, PERSIST_NODE_NAME_ANALYSIS)
    setPersistData(PERSIST_TAG_OF_SMETHODS_METHOD, className2SMethods_Method, PERSIST_NODE_NAME_ANALYSIS)

def popSelectionWidget(selections):
    for selectName in selections:
        None
    None

def setNameOfClassesFirstMember():
    for sidx, sid, sname in Structs():
        if not (sname.startswith("vtable_") or sname.startswith("whole_vtable_")):
            struct = get_struc(sid)
            member = get_member(struct, 0)
            #if not None is member:
            #    memberType = GetType(member.id)
            #    memberName = ida_struct.get_member_name(member.id)
            #    if (not None is memberName) and memberName.startswith("vtable_"):
            if sname in classNameToVTableAddrMap or sname in kernelClassNameSet:
                ida_struct.set_member_name(struct, 0, "vtable")
                SetType(member.id, "vtable_" + sname + "*")

def recoverClassMemebers():
    allClassNames = getAllClassNames()
    for className in allClassNames:
        print "[+] recoverClassMemebers {}".format(className)
        sid = GetStrucIdByName(className)
        struct = get_struc(sid)
        structSize = get_struc_size(sid)
        for offset in range(0, structSize, 8):
            member = ida_struct.get_member(struct, offset)
            memberName = ida_struct.get_member_name(member.id)
            if offset == 0:
                ida_struct.set_member_name(struct, 0, "vtable")
                SetType(member.id, "vtable_" + className + "*")
            elif offset > 0x8000:
                break
            elif memberName != "member" + str(offset/8):
                ida_struct.set_member_name(struct, offset, "member" + str(offset/8))
                SetType(member.id, "")

def findUserClientClassesForKEXT(kextPrefix):
    userClientClasses = []
    if not kextPrefix in moduleNameToClassNamesMap:
        return []
    for className in moduleNameToClassNamesMap[kextPrefix]:
        if isClassDescendantOfClass(className,"IOUserClient"):
            userClientClasses.append(className)
    return userClientClasses


def findUserClientClasses():
    userClientClasses = []
    if isBinaryArm64():
        for className in classNameToModuleNameMap.keys():
            if isClassDescendantOfClass(className,"IOUserClient"):
                userClientClasses.append(className)
    elif isBinaryX86_64():
        for className in classNameToVTableAddrMap.keys():
            if isClassDescendantOfClass(className,"IOUserClient"):
                userClientClasses.append(className)
    return userClientClasses
    
UCMethodCBNames = ["externalMethod", "getTargetAndMethodForIndex", "getTargetAndTrapForIndex"]
UCCallableCBNames = ["externalMethod", "getTargetAndMethodForIndex", "getTargetAndTrapForIndex", "clientClose", "clientMemoryForType", "registerNotificationPort"]

def findSMethodsForUCClassInfo(ucInfo):
    callbacks = ucInfo.callBacks
    for name in UCMethodCBNames:
        if name in callbacks:
            cbEA = callbacks[name]
            #print "[++] SMethods find for {} at 0x{:016X}".format(getName(cbEA), cbEA)
            result = None
            try:
                result = sMethodAnalysisInMethodCB_byTriton(cbEA, name!="externalMethod")
            except Exception:
                print "[!] sMethodAnalysisInMethodCB_byTriton failed at {:016X}".format(cbEA)
                traceback.print_exc()

            if (not None is result) and (not None is result[-1]) :
                foundSMethodsEAs = result[-1]
                for foundSMethodsEA in foundSMethodsEAs:
                    parseSMethodArrayAtAddr(foundSMethodsEA, -1, ucInfo.className, name =="externalMethod")
                    #print "[oo] For {}, found sMethod array {} at 0x{:016X}".format(getName(cbEA), getName(foundSMethodsEA), foundSMethodsEA)

def getUCInfoOfUCClass(className):
    ucInfo = UserClientInfo(className)
    vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
    IOServiceVTSId = GetStrucIdByName("vtable_IOService") 
    IOUserClientVTSId = GetStrucIdByName("vtable_IOUserClient") 
    if IOServiceVTSId == BADADDR or IOUserClientVTSId == BADADDR:
        return ucInfo
    IOServiceVTSize = get_struc_size(IOServiceVTSId)
    IOUserClientVTSize = get_struc_size(IOUserClientVTSId)
    if vtableStartEA != BADADDR:
        currentEA = vtableStartEA
        #for currentEA in range(vtableStartEA+IOServiceVTSize, vtableStartEA+IOUserClientVTSize, 8):
        for currentEA in range(vtableStartEA, vtableStartEA+IOUserClientVTSize, 8):
            vfuncEA = Qword(currentEA)
            vfuncDeName = getDeFuncNameAtEA(vfuncEA)
            if not None is vfuncDeName and vfuncDeName.startswith(className + "::"):
                ucInfo.addCallBack(vfuncDeName[len(className)+2:], vfuncEA)

    findSMethodsForUCClassInfo(ucInfo)

    if className in className2SMethods_MethodDispatch:
        sMethods = className2SMethods_MethodDispatch[className]
        for sMethodStructEA in sMethods:
            sMethodEA = Qword(sMethodStructEA)
            if sMethodEA != 0:
                ucInfo.addSMethod(sMethodEA, True)
    if className in className2SMethods_Method:
        sMethods = className2SMethods_Method[className]
        for sMethodStructEA in sMethods:
            sMethodEA = Qword(sMethodStructEA+8)
            if sMethodEA != 0:
                if is_func(GetFlags(sMethodEA)):
                    ucInfo.addSMethod(sMethodEA, False)
                else:
                    # TODO TODO TODO Most ergent todo !
                    #vtableStartEA, vtableEndEA = getVTableAddrOfClass(className)
                    #if vtableStartEA != BADADDR :
                    #    sMethodEA = Qword(vtableStartEA)
                    None
    return ucInfo

def isClassInKernel(className):
    return className in kernelClassNameSet

def isClassInKEXTs(className):
    return className in classNameToModuleNameMap

def isFuncNameGate(funcName):
    gateFuncNames = ["__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_", "__ZN13IOCommandGate9runActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_"]
    for name in gateFuncNames:
        if funcName.startswith(name):
            return True
    return False

def isFuncNameLock(funcName):
    demangledFuncName = getDeFuncNameOfName(funcName)
    if not None is demangledFuncName and (demangledFuncName.endswith("::lock") or demangledFuncName.endswith("::Lock")):
        return True
    lockFuncNames = ["_IOLockLock", "_lck_mtx_lock", "_IOLockTryLock", "_lck_mtx_try_lock", "_IORecursiveLockLock", "_IORWLockRead", "_IORWLockWrite", "_IOSimpleLockLock", "_lck_spin_lock", "_IOSimpleLockTryLock", "_lck_spin_try_lock", "__ZN15IOConditionLock4lockEv", "_OSSpinLockTry", "__ZN10IOWorkLoop9closeGateEv"] 
    for name in lockFuncNames:
        if funcName.startswith(name):
            return True
    return False

def isFuncNameUnlock(funcName):
    demangledFuncName = getDeFuncNameOfName(funcName)
    if not None is demangledFuncName and (demangledFuncName.endswith("::unlock") or demangledFuncName.endswith("::Unlock")):
        return True
    unlockFuncNames = ["_IOLockUnlock", "_lck_mtx_unlock", "_IOLockTryUnlock", "_lck_mtx_try_unlock", "_IORecursiveLockUnlock", "_IORWLockUnlock", "_IOSimpleLockUnlock", "_lck_spin_unlock", "_IOSimpleLockTryUnlock", "_lck_spin_try_unlock", "__ZN15IOConditionLock6unlockEv", "_OSSpinLockUnlock", "__ZN10IOWorkLoop8openGateEv"]
    for name in unlockFuncNames:
        if funcName.startswith(name):
            return True
    return False

def copyMemberTypeAndNameToChildren(className):
    childClassNames = getDescendantsForClass(className)
    childClassStructIds = {}
    childClassStructs = {}
    for name in childClassNames:
        sid = GetStrucIdByName(name)
        childClassStructIds[name] = sid
        childClassStructs[name] = get_struc(sid)
    classStrucId = GetStrucIdByName(className)
    classStruct = get_struc(classStrucId)
    classSize = get_struc_size(classStrucId)
    for off in range(0, classSize, 8):
        member = idaapi.get_member(classStruct, off)
        memberTinfo = tinfo_t()
        ret = ida_struct.get_member_tinfo(memberTinfo, member)
        if isTinfoInterested(memberTinfo):
            for s in childClassStructs.values():
                childMember = idaapi.get_member(s, off)
                childMemberTinfo = tinfo_t()
                ret = ida_struct.get_member_tinfo(childMemberTinfo, childMember)
                if isTinfoInterested(childMemberTinfo):
                    setTypeForMemeber(s.id, off, str(memberTinfo))


binaryMinEA = idc.get_inf_attr(INF_MIN_EA)
binaryMaxEA = idc.get_inf_attr(INF_MAX_EA)


def getCapDisasmInsnsOfFuncAtEA(funcEA):
    arch = None
    mode = None
    if isBinaryArm64():
        arch = CS_ARCH_ARM64
        mode = CS_MODE_ARM
    elif isBinaryX86_64():
        arch = CS_ARCH_X86
        mode = CS_MODE_64
    if not (None is arch and None is mode):
        capstoneEngine = Cs(arch, mode)
        capstoneEngine.detail = True
        func = get_func(funcEA)
        if None is func:
            print "[!] Func None at {:016X}".format(funcStartEA)
            return []
        funcCode = getBytesOfFunc(func)
        insnList = list(capstoneEngine.disasm(funcCode, func.startEA))
        insnMap = {}
        for insn in insnList:
            insnMap[insn.address] = insn
        #if len(insns) != (func.endEA - func.startEA)/4:
        #    print "[?] Number of capstone disasm insns incorrect at {:016X}".format(func.startEA)
        return insnList, insnMap
    return None, None

def getCapDisasmInsnAtEA(ea):
    if isBinaryArm64():
        arch = CS_ARCH_ARM64
        mode = CS_MODE_ARM
    elif isBinaryX86_64():
        arch = CS_ARCH_X86
        mode = CS_MODE_64
    capstoneEngine = Cs(arch, mode)
    capstoneEngine.detail = True
    code = ""
    insnLen = next_head(ea) - ea
    for byte in idc.GetManyBytes(ea, insnLen):
        code += byte
    return capstoneEngine.disasm(code, 0).next()


def getSegName(seg):
    #print type(seg), seg
    if isinstance(seg, (int , long)):
        return get_segm_name(seg)
    else:
        return ida_segment.get_segm_name(seg)

def isFuncNonSense(funcEA):
    funcName = getName(funcEA)
    return ((None is funcName) or funcName == "___cxa_pure_virtual" or funcName.startswith("nullsub_"))

def isInt(s):
    try:
        return int(s, 0)
    except ValueError as e:
        return None

def convertRegToRegIdx(reg):
    if isBinaryArm64():
        regIdx = None
        if isinstance(reg, (str, unicode)):
            if reg[0] in ('W', 'X', 'D', 'B'):
                try:
                    return int(reg[1:])
                except ValueError as e:
                    return None
            else:
                regIdx = str2reg(reg)
        elif isinstance(reg, (int, long)):
            regIdx = reg
        if not None is regIdx:
            if regIdx >= 61:
                regIdx -= 61
            elif regIdx >= 129:
                regIdx -= 129
            return regIdx
    elif isBinaryX86_64():
        regIdx = None
        if isinstance(reg, (str, unicode)):
            regIdx = str2reg(reg)
        elif isinstance(reg, (int, long)):
            regIdx = reg
        if not None is regIdx:
            if regIdx >= 16:
                regIdx -= 16
            return regIdx
    return None

def getBPSPDistanceOfFunc(func):
    if func.startEA in funcEA2BPOffsetAndFuncHeadEndMap:
        return funcEA2BPOffsetAndFuncHeadEndMap[func.startEA]
    bp_sp_distance = 0
    bp_set_found = False
    sp_set_found = False
    func_head_end_ea = func.startEA # func_head_end_ea is the first insnEA not deal with stack
    if isBinaryArm64():
        for insnEA in range(func.startEA, func.endEA, 4):
            if GetMnem_wrapper(insnEA) == "ADD" and GetOpnd(insnEA, 0) == "X29" and GetOpnd(insnEA, 1) == "SP":
                bp_sp_distance = GetOperandValue(insnEA, 2)
                bp_set_found = True
            elif GetMnem_wrapper(insnEA) == "MOV" and GetOpnd(insnEA, 0) == "X29" and GetOpnd(insnEA, 1) == "SP":
                bp_sp_distance = 0
                bp_set_found = True
            elif GetMnem_wrapper(insnEA) == "SUB" and GetOpnd(insnEA, 0) == "SP" and GetOpnd(insnEA, 1) == "SP":
                sp_set_found = True
                sp_size = GetOperandValue(insnEA, 2)
                bp_sp_distance += sp_size
            if bp_set_found and sp_set_found:
                func_head_end_ea = insnEA
                break
        if not None is bp_sp_distance:
            funcEA2BPOffsetAndFuncHeadEndMap[func.startEA] = (bp_sp_distance, func_head_end_ea)
    elif isBinaryX86_64():
        for insnEA in Heads(func.startEA, func.endEA):
            mnem = GetMnem_wrapper(insnEA)
            if mnem == "MOV":
                src = GetOpnd(insnEA, 1)
                dst = GetOpnd(insnEA, 0)
                if dst == "rbp" and src == "rsp":
                    bp_sp_distance = 0
                else:
                    func_head_end_ea = insnEA
                    break
            elif mnem == "SUB":
                dst = GetOpnd(insnEA, 0)
                imm = GetOperandValue(insnEA, 1)
                if dst == "rsp":
                    bp_sp_distance += imm
                else:
                    func_head_end_ea = insnEA
                    break
            elif mnem == "PUSH":
                bp_sp_distance += 8
            else:
                func_head_end_ea = insnEA
                break
    return bp_sp_distance, func_head_end_ea


import triton
def getTritonRegIdxByRegName(regName):
    if isBinaryArm64():
        return getattr(triton.REG.AARCH64, regName.upper())
    elif isBinaryX86_64():
        return getattr(triton.REG.X86_64, regName.upper())
    return None

def backwardResolveInHeads_arm64(heads, ind, reg, visited_bbs=None):
    resultLowIsSet = False
    resultHighIsSet = False
    result = 0
    
    if ind <= len(heads) and ind >= 0:
        i = ind-1
        while i >= 0:
            insnEA = heads[i]
            opertor = GetMnem(insnEA)
            opnd0 = GetOpnd(insnEA, 0)
            opnd1 = GetOpnd(insnEA, 1)
            if opertor == "MOV":
                if opnd0 == reg or opnd0.replace("W", "X") == reg or opnd0.replace("B", "X") == reg:
                    opnd1Value = GetOperandValue(insnEA, 1)
                    if opnd1.startswith("#"):
                        return opnd1Value, reg
                    else:
                        #return backwardResolveInHeads_arm64(heads, i, opnd1), reg
                        #return backwardResolveAtEA(insnEA, opnd1), reg
                        reg = opnd1

            elif (opertor == "BL" or opertor == "BLR") and reg == "X0":
                return None, reg
    
            elif opertor == "ADD" and opnd0 == reg :
                if opnd1 == reg:
                    opnd2Value = GetOperandValue(insnEA, 2)
                    result = result + opnd2Value
                    #resultLowIsSet = True
                    #if resultLowIsSet and resultHighIsSet:
                    #    return result, reg
                else:
                    opnd2Value = GetOperandValue(insnEA, 2)
                    result += opnd2Value
                    reg = opnd1
                    #addValue = backwardResolveAtEA(insnEA, opnd1)
                    #if not None is addValue:
                    #    result += addValue
                    #    result += opnd2Value
                    #    return result, reg
                    #else:
                    #    print "[!] Error resolving {} at {:016X}".format(opnd1, insnEA)
                    #    return None, reg

            elif ((opertor == "LDR" or opertor == "LDUR") and opnd0 == reg) or (opertor == "LDP" and (opnd0 == reg or opnd1 == reg) ) :
                source_reg, source_offset, source_reg_shift = getBaseRegAndImmOfLDRAndSTRInsn(insnEA)
                if (None is source_reg) :
                    if (source_offset != BADADDR):
                        result = result + source_offset
                        if opertor == "LDP" and opnd1 == reg:
                            result += 8
                        if Qword(result) != BADADDR:
                            return Qword(result), reg
                if opertor == "LDP" and opnd1 == reg:
                    source_offset += 8
                resultOfLoadSource = None
                if source_reg == "SP":
                    source_sp_off = source_offset
                    storeEA, storeSource = backwardFindLocalVarStore(insnEA, source_sp_off, None)
                    return backwardResolveAtEA(storeEA, storeSource, visited_bbs=visited_bbs), reg
                elif source_reg == "X29":
                    source_bp_off = source_offset
                    storeEA, storeSource = backwardFindLocalVarStore(insnEA, None, source_bp_off)
                    return backwardResolveAtEA(storeEA, storeSource, visited_bbs=visited_bbs), reg
                else:
                    #resultOfLoadSource = backwardResolveInHeads_arm64(heads, i, source_reg)
                    resultOfLoadSource = backwardResolveAtEA(insnEA, source_reg, visited_bbs=visited_bbs)
                    if None is resultOfLoadSource:
                        print "[!] Error resolving {} at {:016X}".format(source_reg, insnEA)
                    else:
                        return Qword(resultOfLoadSource + source_offset), reg
                #resultLowIsSet = True
                #if resultLowIsSet and resultHighIsSet:
                #    return Qword(result), reg
            elif opertor == "ADRP" and opnd0 == reg:
                opnd1Value = GetOperandValue(insnEA, 1)
                result = result + opnd1Value
                return result, reg
                #resultHighIsSet = True
                #if resultLowIsSet and resultHighIsSet:
                #    return result, reg

            elif opertor == "ADR" and opnd0 == reg:
                opnd1Value = GetOperandValue(insnEA, 1)
                return opnd1Value, reg

            i -= 1
    return None, reg

def isEAValid(ea):
    return (not None is ea) and (ea>=binaryMinEA) and (ea<=binaryMaxEA) and (ea!=BADADDR)
    #return (not None is ea) and (ea>0xffffff8000000000) and (ea!=BADADDR)

def backwardResolveInHeads(heads, ind, reg, visited_bbs=None):
    if isBinaryArm64():
        return backwardResolveInHeads_arm64(heads, ind, reg, visited_bbs)
    elif isBinaryX86_64():
        return backwardResolveInHeads_x64(heads, ind, reg, visited_bbs)
    return None, reg

def backwardResolveAtEA(ea, reg, bb=None, visited_bbs=None):
    ''' Backword resolve should only be used to find symbols ! 
        isEAValid() restricts that the return value should be in the kernel space !
    '''
    if not (isBinaryArm64() or isBinaryX86_64()):
        print "[!] Not arm64 or x64"
        return None
    bbWasNone = False
    if None is bb:
        # This may be called by backwardResolveInHeads
        bbWasNone = True
        bb = getBBAtEA(ea)
    if None is visited_bbs:
        visited_bbs = set()
    if (bb.startEA in visited_bbs) and not bbWasNone:
        return None
    visited_bbs.add(bb.startEA)
    #print "backwardResolveAtEA 0x{:016X} {}".format(bb.startEA, visited_bbs)
    heads = list(Heads(bb.startEA, bb.endEA))
    if ea == bb.endEA:
        index = len(heads)
    else:
        index = heads.index(ea)
    #index = (ea-bb.startEA)/4 # in arm64, every instruction is 4 byte
    resolveResult, newreg = backwardResolveInHeads(heads, index, reg, visited_bbs)

    if isEAValid(resolveResult):
    #if not None is resolveResult:
        return resolveResult
    else:
        for bb_pred in bb.preds():
            ''' Current solution is not complete yet 
                if adrp in a previous bb and add in a next bb, that will miss 
                but I think this situation is not common    
            '''
            resolveResult = backwardResolveAtEA(bb_pred.endEA, newreg, bb_pred, visited_bbs)
            if isEAValid(resolveResult) :
            #if not None is resolveResult:
                return resolveResult
    return None

def backwardResolveInHeads_x64_simple(heads, ind, reg):
    if ind < len(heads) and ind >= 0:
        i = ind-1
        while i >= 0:
            insnEA = heads[i]
            opertor = GetMnem(insnEA)
            opnd0 = GetOpnd(insnEA, 0)
            opnd1 = GetOpnd(insnEA, 1)
            if opertor == "mov":
                src_opnd_type = get_operand_type(insnEA, 1)
                dst_opnd_type = get_operand_type(insnEA, 1)
                if opnd0 == reg:
                    opnd1Value = GetOperandValue(insnEA, 1)
                    if opnd1Value <= 0x20:
                        return backwardResolveInHeads_x64_simple(heads, i, opnd1)
                        None
                    else:
                        return opnd1Value
    
            elif opertor == "lea" and opnd0 == reg:
                opnd1Value = GetOperandValue(insnEA, 1)
                return opnd1Value
            i -= 1
    return None

def getBaseRegAndImmOfLDRAndSTRInsn(insnEA):
    offset = BADADDR
    Reg = None
    RegOpnd = None
    mnem = GetMnem(insnEA)
    reg_shift = 0

    if mnem.startswith("LD") or mnem.startswith("ST"):
        is_third_opnd_exist = (get_operand_type(insnEA, 2) != 0)
        if is_third_opnd_exist:
            if get_operand_type(insnEA, 2) == 4:
                RegOpnd = GetOpnd(insnEA, 2)
                offset = GetOperandValue(insnEA, 2)
            elif get_operand_type(insnEA, 2) == 2:
                offset = GetOperandValue(insnEA, 2)
                return None, offset, reg_shift
        else:
            if get_operand_type(insnEA, 1) == 4:
                RegOpnd = GetOpnd(insnEA, 1)
                offset = GetOperandValue(insnEA, 1)
            elif get_operand_type(insnEA, 1) == 2:
                offset = GetOperandValue(insnEA, 1)
                return None, offset, reg_shift
    '''
    if mnem == "LDR" or mnem == "LDUR":
        if get_operand_type(insnEA, 1) == 4:
            RegOpnd = GetOpnd(insnEA, 1)
            offset = GetOperandValue(insnEA, 1)
        elif get_operand_type(insnEA, 1) == 2:
            offset = GetOperandValue(insnEA, 1)
            return None, offset, reg_shift
    elif mnem == "LDP" or mnem == "LDXR":
        if get_operand_type(insnEA, 2) == 4:
            RegOpnd = GetOpnd(insnEA, 2)
            offset = GetOperandValue(insnEA, 2)
        elif get_operand_type(insnEA, 2) == 2:
            offset = GetOperandValue(insnEA, 2)
            return None, offset, reg_shift
    elif mnem == "STR" or mnem == "STUR":
        if get_operand_type(insnEA, 1) == 4:
            RegOpnd = GetOpnd(insnEA, 1)
            offset = GetOperandValue(insnEA, 1)
    elif mnem == "STP" or mnem == "STXR" or mnem == "STLXR":
        if get_operand_type(insnEA, 2) == 4:
            RegOpnd = GetOpnd(insnEA, 2)
            offset = GetOperandValue(insnEA, 2)
    '''

    if offset > 0x7fffffffffffffff:
        offset = offset - 0x10000000000000000L

    if not None is RegOpnd:
        if RegOpnd[-1] == "!":
            RegOpnd = RegOpnd[:-1]
            reg_shift = offset
        if RegOpnd[0] == "[" and RegOpnd[-1] == "]":
            Reg = RegOpnd[1:RegOpnd.find(",")]
        else:
            if "+" in RegOpnd:
                Reg = RegOpnd[1:RegOpnd.find("+")]
                reg_shift = offset
                offset = 0
            elif "]" in RegOpnd:
                Reg = RegOpnd[1:RegOpnd.find("]")]
                reg_shift = offset
                offset = 0
            else:
                print "Incorrect {} at {:016X}".format(mnem, insnEA)
    return Reg, offset, reg_shift

import re
def getBaseRegAndImmOfIndirectMemoryOperand(insnEA, opndIdx):
    inMemOpnd = GetOpnd(insnEA, opndIdx)
    operand_type = get_operand_type(insnEA, opndIdx)
    if operand_type == 4 or operand_type == 3:
        opndExpr = inMemOpnd[inMemOpnd.find("[")+1:inMemOpnd.rfind("]")]
        baseRegLastPos = opndExpr[opndExpr.find("+")]
        
        opndExprParts = re.split('\+|-|,', opndExpr)
        baseReg = opndExprParts[0]
        middle = None
        imm = 0
        if len(opndExprParts) > 1:
            if not "*" in opndExpr:
                imm = GetOperandValue(insnEA, opndIdx)
                if imm > 0x7fffffffffffffff:
                    imm = imm - 0x10000000000000000L
            else:
                middle_part = opndExprParts[1]
                middleReg = middle_part[:middle_part.find("*")]
                middleMul = middle_part[middle_part.find("*")+1:]
                middle = [middleReg, int(middleMul)]
                if len(opndExprParts) == 3:
                    imm = GetOperandValue(insnEA, opndIdx)
                    if imm > 0x7fffffffffffffff:
                        imm = imm - 0x10000000000000000L
                elif len(opndExprParts) > 3:
                    print "[?] Unknown number of reg parts in {} at {:016X}".format(opndExpr, insnEA)
                
        elif "(" in inMemOpnd[:inMemOpnd.find("[")]:
            imm = GetOperandValue(insnEA, opndIdx)
            if imm > 0x7fffffffffffffff:
                imm = imm - 0x10000000000000000L
        return baseReg, imm, middle

    return None, None, None

def backwardResolveInHeads_x64(heads, ind, reg, visited_bbs=None):
    if ind <= len(heads) and ind >= 0:
        i = ind-1
        while i >= 0:
            insnEA = heads[i]
            opertor = GetMnem(insnEA)
            opnd0 = GetOpnd(insnEA, 0)
            opnd1 = GetOpnd(insnEA, 1)
            if opertor == "mov":
                src_opnd_type = get_operand_type(insnEA, 1)
                dst_opnd_type = get_operand_type(insnEA, 0)
                src = opnd1
                dst = opnd0
                if dst == reg and dst_opnd_type == 1:
                    if src_opnd_type == 1:
                        reg = src
                    else:
                        if src_opnd_type == 2 or src_opnd_type == 5:
                            return GetOperandValue(insnEA, 1), reg
                        elif src_opnd_type == 4 or src_opnd_type == 3:
                            baseReg, imm, _ = getBaseRegAndImmOfIndirectMemoryOperand(insnEA, 1)
                            baseRegResolveResult = backwardResolveAtEA(insnEA, baseReg, visited_bbs=visited_bbs)
                            if not None is baseRegResolveResult:
                                return Qword(baseRegResolveResult+imm), reg
                        print "Unknown mov source at {:016X}".format(insnEA)
                        return None, reg
    
            elif opertor == "lea" and opnd0 == reg:
                opnd1Value = GetOperandValue(insnEA, 1)
                return opnd1Value, reg
            i -= 1
    return None, reg

class TritonContextInitArgs():
    def __init__(self, concrete_regs=None, symbolic_regs=None, concrete_mems=None, symbolic_mems=None):
        self.concrete_regs = concrete_regs if concrete_regs else {}
        self.symbolic_regs = symbolic_regs if symbolic_regs else {}
        self.concrete_mems = concrete_mems if concrete_mems else {}
        self.symbolic_mems = symbolic_mems if symbolic_mems else {}
        self.concrete_regs_values = concrete_regs
        self.symbolic_regs_symvars = {}
        self.concrete_mems_values = concrete_mems
        self.symbolic_mems_symvars = {}


def getTritonReg(ctx, reg):
    if isinstance(reg, (int, long)):
        return ctx.getRegister(reg)
    elif isinstance(reg, str):
        return ctx.getRegister(getTritonRegIdxByRegName(reg))
    return None


def initTritonContextWithArgs(ctx, args):
    for reg in args.concrete_regs:
        concrete_value = args.concrete_regs[reg]
        reg_triton = getTritonReg(ctx, reg)
        if None is reg_triton:
            continue
        ctx.setConcreteRegisterValue(reg_triton, concrete_value)

    for reg in args.symbolic_regs:
        symbol_comment = args.concrete_regs[reg]
        reg_triton = getTritonReg(ctx, reg)
        if None is reg:
            continue        
        sym_var = ctx.symbolizeRegister(reg_triton, symbol_comment)
        args.symbolic_regs_symvars[reg] = sym_var

    for addr in args.concrete_mems:
        (size, value) = args.concrete_mems[addr]
        for off in range(0, size, 4):
            ctx.setConcreteMemoryValue(triton.MemoryAccess(addr+off, triton.CPUSIZE.DWORD), value)

    for addr in args.symbolic_mems:
        (size, comment) = args.symbolic_mems[addr]
        for off in range(0, size, 4):
            sym_var = ctx.symbolizeMemory(triton.MemoryAccess(addr+off, triton.CPUSIZE.DWORD), comment)
            args.symbolic_mems_symvars[addr+off] = sym_var


def newTritonContext(new_context_args = None):
    arch = None
    if isBinaryArm64():
        arch = triton.ARCH.AARCH64
    else:
        arch = triton.ARCH.X86_64
    if None is arch:
        return None
    ctx = triton.TritonContext()

    ctx.setArchitecture(arch)
    ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

    if not None is new_context_args:
        initTritonContextWithArgs(ctx, new_context_args)
        
    return ctx

CONST_MEMACCESS_OBJ = triton.MemoryAccess(0, 8)

def copyTritonContext(dst, src):
    if None is dst or None is src:
        return
    for reg in src.getAllRegisters():
        dst.setConcreteRegisterValue(reg, src.getConcreteRegisterValue(reg))

    sym_exprs = src.getSymbolicExpressions()
    for sym_id in sym_exprs:
        sym_expr = sym_exprs[sym_id]
        origin = sym_expr.getOrigin()
        if origin.__class__.__name__ == "MemoryAccess":
            dst.assignSymbolicExpressionToMemory(sym_expr, origin)
        elif origin.__class__.__name__ == "Register":
            dst.assignSymbolicExpressionToRegister(sym_expr, origin)
        else:
            # Most of this situation is CMP/TEST instructions, who has no origin
            # We ignore these instructions during copy
            None
            #print "[?] Unknown origin of expr {}, whose class is {}".format(sym_expr, origin.__class__.__name__)


def getTritonInsnAtEA(insnEA):
    instruction = triton.Instruction()
    instruction.setAddress(insnEA)
    opcode = GetManyBytes(insnEA, ItemSize(insnEA)) # Disassemble with IDA Pro
    instruction.setOpcode(opcode)
    return instruction


def forwardTaint_byTriton(funcStartEA, targetRegName, targetEA=None):
    ctx = newTritonContext()
    ast_ctx = ctx.getAstContext()
    
    targetTritonRegIdx = getTritonRegIdxByRegName(targetRegName)
    #ctx.convertRegisterToSymbolicVariable(targetTritonRegIdx)
    ctx.taintRegister(ctx.getRegister(targetTritonRegIdx))
    var = ctx.symbolizeRegister(ctx.getRegister(targetTritonRegIdx))    
    
    instruction = None
    taintedInsns = []
    if None is targetEA:
        targetEA = get_func(funcStartEA).endEA

    for insnEA in Heads(funcStartEA, targetEA):
        instruction = getTritonInsnAtEA(insnEA)
        ctx.processing(instruction) # Emulate instruction without Pintool
        if instruction.isTainted():
            taintedInsns.append(instruction)
    return ctx, taintedInsns, var

def symbolExec_byTriton(funcStartEA):
    func = get_func(funcStartEA)
    funcStartEA = func.startEA
    funcEndEA = func.endEA
    ctx = newTritonContext()
    #ctx.setMode(triton.MODE.ONLY_ON_SYMBOLIZED, True)
    user_input_addr = 0x80000000
    ctx.setConcreteRegisterValue(ctx.getRegister(getTritonRegIdxByRegName("rcx")), user_input_addr)
    #ctx.symbolizeMemory(triton.MemoryAccess(user_input_addr, triton.CPUSIZE.DWORD))
    #ctx.symbolizeMemory(triton.MemoryAccess(user_input_addr+4, triton.CPUSIZE.DWORD))
    for offset in range(0, 0x100, 4):
        ctx.symbolizeMemory(triton.MemoryAccess(user_input_addr+offset, triton.CPUSIZE.DWORD))
    ctx.taintMemory(triton.MemoryAccess(user_input_addr+8, triton.CPUSIZE.DWORD))
    #ctx.symbolizeMemory(triton.MemoryAccess(user_input_addr+8, triton.CPUSIZE.DWORD))
    ctx.setConcreteRegisterValue(ctx.getRegister(getTritonRegIdxByRegName("rdi")), 0x30000)
    #ctx.symbolizeRegister(ctx.getRegister(getTritonRegIdxByRegName("rdi")))
    #ctx.symbolizeRegister(ctx.getRegister(getTritonRegIdxByRegName("rsi")))
    #ctx.symbolizeRegister(ctx.getRegister(getTritonRegIdxByRegName("rdx")))
    taintedInsns = []
    insnEA = funcStartEA
    ctx.setConcreteRegisterValue(ctx.getRegister(getTritonRegIdxByRegName("rip")), funcStartEA+ItemSize(funcStartEA))
    while insnEA != 0:
    #for insnEA in Heads(funcStartEA, funcEndEA):
        instruction = triton.Instruction()
        instruction.setAddress(insnEA)
        opcode = GetManyBytes(insnEA, ItemSize(insnEA)) # Disassemble with IDA Pro
        instruction.setOpcode(opcode)
        ctx.processing(instruction) # Emulate instruction without Pintool
        if instruction.isTainted():
            taintedInsns.append(instruction)

        if len(instruction.getSymbolicExpressions()) > 0:
        
            print hex(insnEA)
            # Display symbolic expressions
            for expr in instruction.getSymbolicExpressions():
                print(expr)
        insnEA = ctx.getRegisterAst(ctx.getRegister(getTritonRegIdxByRegName("rip"))).evaluate()
        #insnEA = next_head(insnEA)
        print hex(insnEA)
    print taintedInsns



def isFuncCalledInFunc(func, target):
    if isinstance(func, (int, long)):
        func = get_func(func)
    if None is func or not isinstance(func, ida_funcs.func_t):
        return False
    for insnEA in Heads(func.startEA, func.endEA):
        callTargets = getTargetsOfCallAtEA(insnEA)
        if isinstance(target, (long, int)):
            return target in callTargets
        elif isinstance(target, (str, unicode)):
            for ea in callTargets:
                if getName(ea) == target:
                    return True
                elif not None is getDeNameAtEA(ea) and \
                    "::{}(".format(target) in getDeNameAtEA(ea):
                    return True
    return False

def sMethodAnalysisInMethodCB_byTriton(funcStartEA, isReturn=False):
    print "sMethodAnalysisInMethodCB_byTriton: {:016X}".format(funcStartEA)
    #finalEA = None
    finalEAs = set()
    func = get_func(funcStartEA)
    funcEndEA = func.endEA
    foundSMethodsEAs = set()
    calledFuncs = set()
    for insnEA in Heads(func.startEA, func.endEA):
        if not isReturn:
            callTargets = getTargetsOfCallAtEA(insnEA)
            calledFuncs.update(callTargets)
            
            for ea in callTargets:
                if getName(ea) == "__ZN12IOUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv":
                    #finalEA = insnEA
                    finalEAs.add(insnEA)
                    #break
                elif not None is getDeNameAtEA(ea) and "::externalMethod(" in getDeNameAtEA(ea):
                    finalEAs.add(insnEA)
            #if not None is finalEA:
            #    break
        else:
            mnem = GetMnem(insnEA)
            if mnem.startswith("ret") or mnem.startswith("RET"):
                #finalEA = insnEA
                finalEAs.add(insnEA)
                #break

    #if (None is finalEA) and (isReturn) :
    #    finalEA = func.endEA
    #if finalEA == None:
    #    return None
    if (len(finalEAs) == 0) and (isReturn) :
        finalEAs.add(func.endEA)
    if len(finalEAs) == 0:
        if not isReturn:
            for calledFuncEA in calledFuncs:
                if (not isFuncInKernel(calledFuncEA)) and \
                    isFuncCalledInFunc(calledFuncEA, "__ZN12IOUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv"):
                    ret = sMethodAnalysisInMethodCB_byTriton(calledFuncEA)
                    if not None is ret:
                        foundSMethodsEAs.update(ret[-1])

            if len(foundSMethodsEAs) > 0:
                print "foundSMethodsEA array:", foundSMethodsEAs
                return None, foundSMethodsEAs

        return None
    arch = None
    if isBinaryArm64():
        arch = triton.ARCH.AARCH64
        selectorArgName_extern = "W1"
        selectorArgName_gettarget = "W2"
    else:
        arch = triton.ARCH.X86_64
        selectorArgName_extern = "esi"
        selectorArgName_gettarget = "edx"
    if None is arch:
        return None
    ctx = triton.TritonContext()
    
    selectorArgIdx_extern = getTritonRegIdxByRegName(selectorArgName_extern)
    selectorArgIdx_gettarget = getTritonRegIdxByRegName(selectorArgName_gettarget)
    thisArgIdx = getTritonRegIdxByRegName(convertArgIdxToRegName(0))
    dispatchArgIdx = getTritonRegIdxByRegName(convertArgIdxToRegName(3))
    ctx.setArchitecture(arch)
    ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)
    #ctx.convertRegisterToSymbolicVariable(targetTritonRegIdx)
    ctx.setConcreteRegisterValue(ctx.getRegister(dispatchArgIdx), 0)
    if not isReturn:
        selectorArgSym = ctx.symbolizeRegister(ctx.getRegister(selectorArgIdx_extern))
    else:
        selectorArgSym = ctx.symbolizeRegister(ctx.getRegister(selectorArgIdx_gettarget))
    #rdiSym = ctx.symbolizeRegister(ctx.getRegister(thisArgIdx))
    #ctx.registers.rdi = rdiSym
    #ctx.setConcreteRegisterValue(ctx.registers.rip, funcStartEA)
    ast_ctx = ctx.getAstContext()
    for insnEA in Heads(funcStartEA, funcEndEA):
        instruction = triton.Instruction()
        instruction.setAddress(insnEA)
        opcode = GetManyBytes(insnEA, ItemSize(insnEA)) # Disassemble with IDA Pro
        #print hex(insnEA)
        instruction.setOpcode(opcode)
        try:
            ctx.processing(instruction) # Emulate instruction without Pintool
        except Exception:
            print "[!] Trtion failed to process insn at {:016X}".format(insnEA)
            traceback.print_exc()
        for se in instruction.getSymbolicExpressions():
            se.setComment(str(insnEA))
            #se.setComment(str(instruction))

        if insnEA in finalEAs:
            if isReturn:
                if isBinaryX86_64():
                    slicingRegIdx = getTritonRegIdxByRegName("rax")
                else:
                    slicingRegIdx = getTritonRegIdxByRegName("X0")
            else:
                slicingRegIdx = getTritonRegIdxByRegName(convertArgIdxToRegName(3))
            regs = ctx.getSymbolicRegisters()
            if slicingRegIdx in regs:
                Expr = regs[slicingRegIdx]
                slicing = ctx.sliceExpressions(Expr)
                #print slicing
                foundSMethodsEA = None
                for k, v in sorted(slicing.items()):
                    if not v.isSymbolized():
                        insnEA = int(v.getComment())
                        mnem = GetMnem(insnEA)
                        if isBinaryX86_64():
                            if mnem == "lea":
                                src_type = get_operand_type(insnEA, 1)
                                if src_type == 2:
                                    foundSMethodsEA = ctx.evaluateAstViaZ3(v.getAst())  
                                    foundSMethodsEAs.add(foundSMethodsEA)
                        else:
                            if (GetMnem(insnEA-4) == "ADRP" and mnem == "ADD") or mnem == "ADR":
                                foundSMethodsEA = ctx.evaluateAstViaZ3(v.getAst())
                                foundSMethodsEAs.add(foundSMethodsEA)
            #print v.getComment()
    if len(foundSMethodsEAs) > 0:
        print "foundSMethodsEA array:", foundSMethodsEAs
        return ctx, foundSMethodsEAs
        #return ctx, slicing, foundSMethodsEA
    else:
        return None


def backwardSlicingAtEA_byTriton(funcStartEA, targetEA, targetReg):
    arch = None
    if isBinaryArm64():
        arch = triton.ARCH.AARCH64
    else:
        arch = triton.ARCH.X86_64
    if None is arch:
        return None
    ctx = triton.TritonContext()
    targetTritonRegIdx = getTritonRegIdxByRegName(targetReg)
    ctx.setArchitecture(arch)
    ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)
    #ctx.convertRegisterToSymbolicVariable(targetTritonRegIdx)
    ast_ctx = ctx.getAstContext()
    for insnEA in Heads(funcStartEA, targetEA):
        instruction = triton.Instruction()
        instruction.setAddress(insnEA)
        opcode = GetManyBytes(insnEA, ItemSize(insnEA)) # Disassemble with IDA Pro
        instruction.setOpcode(opcode)
        ctx.processing(instruction) # Emulate instruction without Pintool
        for se in instruction.getSymbolicExpressions():
            se.setComment(str(instruction))
        
    
    Expr = ctx.getSymbolicRegisters()[targetTritonRegIdx]
    slicing = ctx.sliceExpressions(Expr)
    for k, v in sorted(slicing.items()):
        print v.getComment()
    return ctx, slicing

def forwardExec_byTriton(funcStartEA, targetEA, targetReg):
    arch = None
    if isBinaryArm64():
        arch = triton.ARCH.AARCH64
    else:
        arch = triton.ARCH.X86_64
    if None is arch:
        return None
    ctx = triton.TritonContext()
    targetTritonRegIdx = getTritonRegIdxByRegName(targetReg)
    ctx.setArchitecture(arch)
    ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)
    #ctx.convertRegisterToSymbolicVariable(targetTritonRegIdx)
    ast_ctx = ctx.getAstContext()
    instruction = None
    targetEA = next_head(targetEA)
    for insnEA in Heads(funcStartEA, targetEA):
        instruction = triton.Instruction()
        instruction.setAddress(insnEA)
        opcode = GetManyBytes(insnEA, ItemSize(insnEA)) # Disassemble with IDA Pro
        instruction.setOpcode(opcode)
        ctx.processing(instruction) # Emulate instruction without Pintool
        for se in instruction.getSymbolicExpressions():
            se.setComment(str(instruction))
    return ctx, instruction


def convertArgIdxToRegName(argIdx):
    if isBinaryArm64():
        return "X" + str(argIdx)
    elif isBinaryX86_64():
        if argIdx == 0:
            return "rdi"
        elif argIdx == 1:
            return "rsi"
        elif argIdx == 2:
            return "rdx"
        elif argIdx == 3:
            return "rcx"
        elif argIdx == 4:
            return "r8"
        elif argIdx == 5:
            return "r9"
        return None
    return None

def calculateSPOff(imm, bp_sp_distance, isBP):
    if isBP:
        if imm > 0:
            sp_off = bp_sp_distance + imm - 0x10000000000000000L
        else:
            sp_off = bp_sp_distance + imm 
    else:
        sp_off = imm
    return sp_off

def getVFuncAddrByClassNameAndOff(className, offset):
    vtStartEA, vtEndEA = getVTableAddrOfClass(className)
    if vtStartEA == BADADDR:
        vt_sid = getVTableStructIdOfClass(className)
        vfunc_mid = GetMemberId(vt_sid, offset)
        if vfunc_mid == -1:
            return BADADDR
        return vfunc_mid
    return Qword(vtStartEA+offset)


def getMemberInfoFromHostInfoAndOff(currentEA, srcRegTinfo, imm):
    isInVTS = False
    if not None is srcRegTinfo:
        if srcRegTinfo.is_ptr():
            pointed_obj_tinfo = srcRegTinfo.get_pointed_object()
            if pointed_obj_tinfo.is_struct():
                pointed_obj_typestr = str(pointed_obj_tinfo).strip()
                if pointed_obj_typestr.startswith("struct "):
                    pointed_obj_typestr = pointed_obj_typestr[7:].strip()
                struct_id = GetStrucIdByName(pointed_obj_typestr)
                struct = get_struc(struct_id)
                member_id = GetMemberId(struct_id, imm)
                member = ida_struct.get_member(struct, imm)
                memberTinfo = tinfo_t()
                ret = ida_struct.get_member_tinfo(memberTinfo, member)
                if pointed_obj_typestr.startswith("vtable_") or pointed_obj_typestr.startswith("whole_vtable_"):
                    isInVTS = True
                    
                    return (isInVTS, pointed_obj_tinfo, memberTinfo)
                if ret:
                    if not None is currentEA:
                        addXref(currentEA, member_id, 1, False)
                    return (isInVTS, memberTinfo)
            elif imm == 0:
                ''' the ldr src is purely a pointer ''' 
                return (isInVTS, pointed_obj_tinfo)
    return None

def setMemberTinfoForStoreDst(currentEA, dstRegTinfo, imm, tinfoToSet):
    #print "setMemberTinfoForStoreDst {:016X}: {} -> {} + {:X} ".format(currentEA, tinfoToSet, dstRegTinfo, imm)
    if (str(tinfoToSet).startswith("vtable_") or str(tinfoToSet).startswith("whole_vtable_")):
        return
    if not None is dstRegTinfo:
        if dstRegTinfo.is_ptr():
            pointed_obj_tinfo = dstRegTinfo.get_pointed_object()
            if pointed_obj_tinfo.is_struct():
                structName = str(pointed_obj_tinfo)
                if len(classNameToModuleNameMap) > 0 and not isClassInKEXTs(structName):
                    return
                if structName.startswith("vtable_") or structName.startswith("whole_vtable_"):
                    return
                if not structName in classNameToVTableAddrMap and not structName in classNameToParentClassNameMap:
                    return
                if imm == 0: # do not change vtable
                    return
                struct_id = GetStrucIdByName(str(pointed_obj_tinfo))
                member_id = GetMemberId(struct_id, imm)
                addXref(currentEA, member_id, 1, False)
                setTypeForMemeber(struct_id, imm, str(tinfoToSet))

#====================== process vfunc args ===========================

def guessArgNumberForFuncAtEA_arm64(funcStartEA):
    arch = CS_ARCH_ARM64
    mode = CS_MODE_ARM
    capstoneEngine = Cs(arch, mode)
    capstoneEngine.detail = True
    if None is capstoneEngine:
        print "[!] guessArgNumberForFuncAtEA_arm64 requires capstoneEngine which is not created"
        return
    funcName = getName(funcStartEA)
    if funcName.startswith("__"):
        # No need to guess in this case
        return -1

    func = get_func(funcStartEA)
    if None is func:
        print "[!] Func None at {:016X}".format(funcStartEA)
        return 0

    funcCode = getBytesOfFunc(func)

    regsReadSet = set()
    regsWriteSet = set()
    regsWriteBeforeReadSet = set()
    regsReadBeforeWriteSet = set()
    for insn in capstoneEngine.disasm(funcCode, func.startEA):
        regs_read, regs_write = insn.regs_access()
        for reg in regs_read:
            regName = insn.reg_name(reg)
            regsReadSet.add(regName)
            if not regName in regsWriteSet:
                regsReadBeforeWriteSet.add(regName)
        for reg in regs_write:
            regName = insn.reg_name(reg)
            regsWriteSet.add(regName)
            if not regName in regsReadSet:
                regsWriteBeforeReadSet.add(regName)
    smallestRegNumWBR = 64
    largestRegNumRBW = -1
    for regName in regsWriteBeforeReadSet:
        try:
            regNum = int(regName[1:])
            if regNum < 8 and regNum < smallestRegNumWBR:
                smallestRegNumWBR = regNum
        except ValueError as e:
            None
    for regName in regsReadBeforeWriteSet:
        try:
            regNum = int(regName[1:])
            if regNum < 8 and regNum > largestRegNumRBW :
                largestRegNumRBW = regNum
        except ValueError as e:
            None
    #print largestRegNumRBW, smallestRegNumWBR
    resultArgNum = -1
    if smallestRegNumWBR >= 8:
        if largestRegNumRBW < 8 and largestRegNumRBW > 0:
            resultArgNum = largestRegNumRBW
    else:
        if largestRegNumRBW >= 8 or largestRegNumRBW < 0:
            resultArgNum = smallestRegNumWBR
        else:
            resultArgNum = largestRegNumRBW if largestRegNumRBW > smallestRegNumWBR else smallestRegNumWBR
    return resultArgNum + 1

def getTargetAndGOTOfStubsFuncAtEA_arm64(stubsFuncEA):
    targetEA = None
    gotItemEA = None
    if GetMnem(stubsFuncEA) == "ADRP" and GetMnem(stubsFuncEA+4) == "LDR" and GetMnem(stubsFuncEA+8) == "BR":
        gotItemEA = GetOperandValue(stubsFuncEA, 1) + GetOperandValue(stubsFuncEA+4, 1) 
        targetEA = Qword(gotItemEA)
    return targetEA, gotItemEA

def isFuncInKernel(funcEA):
    # This is only useful for iOS
    segName = get_segm_name(funcEA)
    if isBinaryArm64():
        if kernelcache_status.isMerged:
            kernel_start, kernel_end = findKernelTextAreaForMergedKC()
            return funcEA >= kernel_start and funcEA < kernel_end
                
        else:   
            if segName == "__TEXT_EXEC:__text" or segName == "__TEXT:__text":
                return True
            if segName.endswith("__stubs"):
                targetFuncEA, gotItemEA = getTargetAndGOTOfStubsFuncAtEA_arm64(funcEA)
                if not None is targetFuncEA:
                    return isFuncInKernel(targetFuncEA)

    elif isBinaryX86_64():
        return segName == "UNDEF"

    return False

def processFuncArgs(funcEA, isNonStatic, className, parentFuncEA):
    #print "processFuncArgs {:016X} {}".format(funcEA, className)
    if  funcEA in confirmedFuncTypes:
        return
    if isBinaryArm64() and isFuncInKernel(funcEA):
        return
    funcName = getName(funcEA)
    if isFuncNonSense(funcEA):
        return
    deName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
    deFuncName = getDeFuncNameAtEA(funcEA)
    arglist = []
    classNameInFuncName = None
    if deName != None:
        classNameInFuncName, pureFuncName, arglist = parseFuncProtoWORet(deName, isNonStatic, className)
    else:
        if isBinaryX86_64():
            # No need to process func args if it is macOS and deName is None
            return 
        oldFuncType = GetType(funcEA)
        if not None is oldFuncType:
            oldFuncType = oldFuncType.replace("__cdecl", "")
            oldFuncType = oldFuncType.replace("__fastcall", "")
            oldFuncType = oldFuncType.strip()
            oldFuncProto = getName(funcEA) + oldFuncType[oldFuncType.find("("):]
            classNameInFuncName, pureFuncName, arglist = parseFuncProtoWORet(oldFuncProto, isNonStatic, className)            
        else:
            argNum = guessArgNumberForFuncAtEA_arm64(funcEA)
            if isNonStatic:
                arglist.append(className + "*this")
            for argCnt in range(0, argNum):
                arglist.append("uint64_t")
    if (None is className) and (not None is classNameInFuncName):
        className = classNameInFuncName
    returnType = "uint64_t"
    currentRetTinfo = getRetTinfoOfFuncAtEA(funcEA, False)
    if funcName.endswith("12getMetaClassEv"):
        returnType = className + "::MetaClass *"
    elif funcName.endswith("9MetaClass5allocEv"):
        returnType = className[:-11] + "*"
    elif not None is deFuncName:
        if isBinaryArm64() and deFuncName.endswith("::start") and \
            isClassDescendantOfClass(className, "IOService"):
            arglist = []
            print "start classname {}".format(className)
            arglist.append("{} *".format(className))
            arglist.append("IOService *")
    elif parentFuncEA != None and not isFuncNonSense(parentFuncEA):
        parentFuncRetTinfo = getRetTinfoOfFuncAtEA(parentFuncEA, False)
        if not None is parentFuncRetTinfo:
            returnType = str(parentFuncRetTinfo)
    elif (not None is currentRetTinfo) and (not str(currentRetTinfo) in ["__int64", "uint64_t"]):
        returnType = str(currentRetTinfo)

    if None is className or not className.endswith("::MetaClass"):
        for i in range(0, len(arglist)):
            arg_type = arglist[i]
            arg_tinfo = getTinfoForTypeStr(arg_type)
            if isTinfoInterested(arg_tinfo):
                if arg_tinfo.is_ptr():
                    pointed_arg_tinfo = arg_tinfo.get_pointed_object()
                    if isClassDefined(str(pointed_arg_tinfo)) or \
                        (not GetStrucIdByName("vtable_{}".format(str(pointed_arg_tinfo))) in [BADADDR, -1]):
                        recordFoundObjType(funcEA, "arg{}".format(i), arg_tinfo, ObjTypeSrcType.CALLBACK_ARG)

    funcType = composeFuncType(arglist, funcName, returnType)
    #funcTypeTinfo = getTinfoForTypeStr(funcType)
    #print "{} is_func {}".format(funcType, funcTypeTinfo.is_func())
    funcType += ";"
    setTypeRet = setFuncType(funcEA, funcType)
    #setTypeRet = setFuncType(funcEA, funcType)
    if not setTypeRet:
        print "[!] setFuncType Failed: {:016X} {} {}".format(funcEA, funcName, funcType)
    return funcType

def isClassDefined(className):
    return className in classNameToVTableAddrMap

def isCallAtEA(currentEA):
    mnem = GetMnem(currentEA)
    return isDirectCallAtEA(currentEA) or isIndirectCallAtEA(currentEA)

def isDirectCallForJumpAtEA(currentEA):
    mnem = GetMnem(currentEA)
    isJump = False
    if isBinaryArm64() and (mnem == "B" or mnem.startswith("B.")):
        isJump = True
    elif isBinaryX86_64() and (mnem == "jmp" and get_operand_type(currentEA, 0) == 7):
        isJump = True
    if isJump:
        return is_func(GetFlags(GetOperandValue(currentEA, 0)))
    return False

def isDirectCallAtEA(insnEA):
    mnem = GetMnem(insnEA)
    if isBinaryArm64():
        return mnem == "BL" or isDirectCallForJumpAtEA(insnEA)
        '''
        whether a BR forms a call is hard to identify.
        as a result, we identify it specially in AnalysisUtils during type propagation
        '''
        '''
        if mnem == "BR":
            #bb = getBBAtEA(currentEA)
            #if ((not None is func) and (currentEA == func.endEA-4)) or \
            #        (not None is bb and len(list(bb.succs())) == 0):
            if isFuncEnd(currentEA):
                return True
        '''
    elif isBinaryX86_64():
        if mnem == "call" and get_operand_type(insnEA, 0) == 7:
            return True
        elif isDirectCallForJumpAtEA(insnEA):
            return True
    return False

def isIndirectCallAtEA(currentEA):
    mnem = GetMnem(currentEA)
    if isBinaryArm64():
        func = get_func(currentEA)
        if mnem == "BLR":
            return True

    elif isBinaryX86_64():
        if mnem == "call" or mnem == "jmp":
            op_type = get_operand_type(currentEA, 0)
            if op_type in [1,3,4]:
                reg, imm, _ = getBaseRegAndImmOfIndirectMemoryOperand(currentEA, 0)
                if reg in ["rbp", "rsp"]:
                    return False
                if mnem == "call":
                    return True
                else:
                    func = get_func(currentEA)
                    if None is func:
                        return False
                    if isFuncEnd(currentEA):
                        return True

    return False

def changeVTSAbstractFuncNamesForAll():
    for className in classNameToVTableAddrMap:
        changeVTSAbstractFuncNamesForClass(className)

def changeVTSAbstractFuncNamesForClass(parentClassName):
    parentVTSName = "vtable_" + parentClassName
    parentVTSId = GetStrucIdByName(parentVTSName)
    parentVTS = get_struc(parentVTSId)
    vfuncTotal = parentVTS.memqty
    for idx in range(0, vfuncTotal):
        vfuncMember = parentVTS.get_member(idx)
        vfuncName = ida_struct.get_member_name(vfuncMember.id)
        if vfuncName.startswith("___cxa_pure_virtual") or vfuncName.startswith("member"):
            childFuncEAs = getChildFuncEAsForClassAtVTOff(parentClassName, vfuncMember.soff)
            for funcEA in childFuncEAs:
                childFuncName = getName(funcEA)
                if (not None is childFuncName) and (not childFuncName.startswith("___cxa_pure_virtual")):
                    parentFuncName = replaceClassInMangledName(childFuncName, parentClassName)
                    SetOrAddMemberName(parentVTSId, vfuncMember.soff, parentFuncName)
                    break

def isX64BinaryKernel():
    return (not None is get_segm_by_name("__bootPT"))

def getTargetsOfCallAtEA(callEA, callGraph=None):
    # Return empty set is no targets have been resolved
    mnem = GetMnem(callEA)
    callGraph_selected = callGraph_FuncEA2Calls if None is callGraph else callGraph
    calledTargets = set()
    if isDirectCallAtEA(callEA):
        calledTargets = set([GetOperandValue(callEA, 0)])
    else:
        funcStartEA = get_fchunk_attr(callEA, FUNCATTR_START)
        if (funcStartEA in callGraph_selected) and (callEA in callGraph_selected[funcStartEA]):
            calledTargets = callGraph_selected[funcStartEA][callEA]
        #else:
        #    branched_ea = GetOperandValue(callEA, 0)
        #    if is_func(GetFlags(branched_ea)):
        #        calledTargets = [branched_ea]
    if not None is calledTargets:
        calledTargets.discard(int(BADADDR))
        calledTargets.discard(long(BADADDR))
        calledTargets.discard(int(-1))
        calledTargets.discard(long(-1))
        calledTargets.discard(int(0))
        calledTargets.discard(long(0))
    return calledTargets

import datetime
def getNowDateStr():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d-%H-%M-%S")

def getOriginalBinaryPath():
    return idaapi.get_input_file_path()
BinaryPath = getOriginalBinaryPath()

def getUCInfosForKEXT(kextPrefix):
    result = {}
    ucClassNames = findUserClientClassesForKEXT(kextPrefix)
    for className in ucClassNames:
        info = getUCInfoOfUCClass(className)
        result[className] = info
    return result

def getAllUCInfos():
    result = {}
    ucClassNames = findUserClientClasses()
    for className in ucClassNames:
        info = getUCInfoOfUCClass(className)
        result[className] = info
    if isBinaryX86_64():
        for className in classNameToVTableAddrMap:
            if className in result:
                continue
            vtStartEA, vtEndEA = classNameToVTableAddrMap[className]
            isUCClass = False
            for ea in range(vtStartEA, vtEndEA, 8):
                vfuncEA = Qword(ea)
                vfuncDeName = getDeFuncNameAtEA(vfuncEA)
                if not None is vfuncDeName:
                    for name in UCMethodCBNames:
                        if "::{}".format(name) in vfuncDeName:
                            isUCClass = True
                            break
                    if isUCClass:
                        info = getUCInfoOfUCClass(className)
                        result[className] = info
                        break
    return result

def isStoreAtEA(currentEA):
    mnem = GetMnem(currentEA)
    if isBinaryX86_64():
        if mnem == "mov":
            opnd0_type = get_operand_type(currentEA, 0)
            return opnd0_type in [3,4]
    elif isBinaryArm64():
        return mnem == "STR" or mnem == "STUR" or mnem == "STP"
    return False

def isLoadAtEA(currentEA):
    mnem = GetMnem(currentEA)
    if isBinaryX86_64():
        if mnem == "mov":
            opnd1_type = get_operand_type(currentEA, 1)
            return opnd1_type in [3,4]
    elif isBinaryArm64():
        return mnem == "LDR" or mnem == "LDUR" or mnem == "LDP"
    return False

def getStoreSrcAndDstAtEA(currentEA):
    result = []
    if not isStoreAtEA(currentEA):
        return None
    mnem = GetMnem(currentEA)
    if isBinaryX86_64():
        if mnem == "mov":
            opnd1_type = get_operand_type(currentEA, 1)
            dst, imm, _ = getBaseRegAndImmOfIndirectMemoryOperand(currentEA, 0)
            src = GetOpnd(currentEA, 1)
            if opnd1_type == 1:
                return [(src, dst, imm)]
            elif opnd1_type in [2,5]:
                src = GetOperandValue(currentEA, 1)
                return [(src, dst, imm)]
    elif isBinaryArm64():
        if mnem == "STR" or mnem == "STUR":
            src = GetOpnd(currentEA, 0)
            dst, imm, dst_shift = getBaseRegAndImmOfLDRAndSTRInsn(currentEA)
            return [(src, dst, imm)]
        elif mnem == "STP":
            src0 = GetOpnd(currentEA, 0)
            src1 = GetOpnd(currentEA, 1)
            dst, imm, dst_shift = getBaseRegAndImmOfLDRAndSTRInsn(currentEA)
            return [(src0, dst, imm), (src1, dst, imm+8)]
    return None

def isTinfoClass(tinfo):
    if argPointedTinfo.is_struct():
        argPointedType = str(argPointedTinfo)[len("struct "):]
        vtStartEA, vtEndEA = getVTableAddrOfClass(argPointedType)

def isFuncContainObjArg(funcEA):
    arglist = getArgListForFuncAtEA(funcEA)
    for argType in arglist:
        argTinfo = getTinfoForTypeStr(argType)
        if (not None is argTinfo) and argTinfo.is_ptr():
            argPointedTinfo = argTinfo.get_pointed_object()
            if argPointedTinfo.is_struct():
                return True
    return False

def backwardFindInsn_recur(ea, bb, visited_bbs, end_ea, insnCheckCB, **kwargs):
    if ea <= end_ea:
        return None
    if bb.startEA in visited_bbs:
        return None
    visited_bbs.append(bb.startEA)
    currentEA = ea
    while currentEA >= bb.startEA and currentEA > end_ea:
        checkRet = insnCheckCB(currentEA, **kwargs)
        if not None is checkRet:
            return currentEA, checkRet
        currentEA -= 4
    for bb_pred in bb.preds():
        predFindResult = backwardFindInsn_recur(bb_pred.endEA-4, bb_pred, visited_bbs, end_ea, insnCheckCB, **kwargs)
        if not None is predFindResult:
            return predFindResult
    return None

def backwardFindInsn_linear(ea, end_ea, insnCheckCB, **kwargs):
    func = get_func(ea)
    currentEA = ea
    while currentEA >= func.startEA and currentEA > end_ea:
        checkRet = insnCheckCB(currentEA, **kwargs)
        if not None is checkRet:
            return currentEA, checkRet
        currentEA -= 4
    return None


def compareStoreAndGetSource(insnEA, func, target_sp_off, bp_sp_distance):
    mnem = GetMnem(insnEA)
    found_sp_off = None
    found_source = None
    if mnem == "STR" or mnem == "STUR":
        opnd0 = GetOpnd(insnEA, 0)
        opnd1 = GetOpnd(insnEA, 1)
        if opnd1.startswith("[SP,"):
            found_sp_off = GetOperandValue(insnEA, 1)
        elif opnd1.startswith("[X29,"):
            opnd1_value = GetOperandValue(insnEA, 1)
            found_sp_off = bp_sp_distance + opnd1_value - 0x10000000000000000L
        #print found_sp_off, target_sp_off
        if not None is found_sp_off and found_sp_off == target_sp_off:
            return opnd0
    elif mnem == "STP":
        opnd0 = GetOpnd(insnEA, 0)
        opnd1 = GetOpnd(insnEA, 1)
        opnd2 = GetOpnd(insnEA, 2)
        if opnd2.startswith("[SP,"):
            found_sp_off = GetOperandValue(insnEA, 2)
        elif opnd2.startswith("[X29,"):
            opnd2_value = GetOperandValue(insnEA, 2)
            found_sp_off = bp_sp_distance + opnd2_value - 0x10000000000000000L
        if not None is found_sp_off:
            if found_sp_off == target_sp_off:
                return opnd0
            elif found_sp_off + 8 == target_sp_off:
                return opnd1
    return None

def backwardFindLocalVarStore(ea, target_sp_off=None, target_bp_off=None):
    func = get_func(ea)
    bp_sp_distance, func_head_end_ea = getBPSPDistanceOfFunc(func)
    if None is target_sp_off:
        if not None is target_bp_off:
            target_sp_off = bp_sp_distance + target_bp_off
        else:
            return None
        
    bb = getBBAtEA(ea)
    return backwardFindInsn_linear(ea, func_head_end_ea, compareStoreAndGetSource, func=func, target_sp_off=target_sp_off, bp_sp_distance=bp_sp_distance)

import ctypes

def extract_vtable_pac_codes(vtable_ea):
    pac_codes = []
    # Open the file.
    path = idc.get_input_file_path()
    with open(path, "rb") as kernelcache_file:
        # Seek to the offset of the vtable.
        offset = idaapi.get_fileregion_offset(vtable_ea)
        kernelcache_file.seek(offset)
        # Loop over each entry in the vtable.
        ea = vtable_ea
        while True:
            # Break if we've reached the end of the vtable.
            vmethod = idc.get_qword(ea)
            if vmethod == 0:
                break
            # Get the original value from the original file.
            original = kernelcache_file.read(8)
            value, = struct.unpack("<Q", original)
            # Extract the type code and add it to the list.
            pac_code = (value & 0x0000ffff00000000) >> 32
            pac_codes.append(pac_code)
            # Advance.
            ea += 8
    return pac_codes

def getDefinedClasses():
    return classNameToVTableAddrMap.keys()

def findDirectCallsInFunc(func):
    directCalls = []
    if not None is func:
        for insnEA in Heads(func.startEA, func.endEA):
            if isDirectCallAtEA(insnEA):
                directCalls.append((insnEA, GetOperandValue(insnEA, 0)))
    return directCalls

def getSelfDefinedVFuncStartOffsetOfClass(className):
    parentClassName = getParentClassNameOfClass(className)
    parentVTStartEA, parentVTEndEA = getVTableAddrOfClass(parentClassName)
    if parentVTStartEA == BADADDR:
        return None

    parentVTSize = parentVTEndEA-parentVTStartEA
    return parentVTSize
    None

def getClassListInModInitFunc(modInitFuncEA, depth=0):
    if depth > 10:
        return []
    if isFuncInKernel(modInitFuncEA) and depth > 2:
        return []
    classList = getClassListInModInitFunc_NoReEnter(modInitFuncEA)
    if len(classList) == 0:
        modInitFunc = get_func(modInitFuncEA)
        directCalls = findDirectCallsInFunc(modInitFunc)
        # Resolve directly called mod_init_func
        for (callEA, calledEA) in directCalls:
            calledFuncName = getName(calledEA)
            gMetaClassAddr = None
            if calledFuncName.endswith("9MetaClassC2Ev") or calledFuncName.endswith("9MetaClassC1Ev"):
                gMetaClassAddr = backwardResolveAtEA(callEA, convertArgIdxToRegName(0))
            # Do not go in several times
            if isInSameKEXT(calledEA, modInitFuncEA):
                classListInCalledFunc = getClassListInModInitFunc(calledEA, depth=depth+1)
                for i in range(0, len(classListInCalledFunc)):
                    if classListInCalledFunc[i][0] == None and gMetaClassAddr != None:
                        classListInCalledFunc[i][0] = gMetaClassAddr

                classList.extend(classListInCalledFunc)

    return classList

def getClassListInModInitFunc_NoReEnter(modInitFuncEA):
    classList = []
    className = None
    classSize = 0
    parentMetaClassName = None
    parentClassName = None
    metaClassAddr = None
    parentMetaClassAddr = None
    for (startea, endea) in Chunks(modInitFuncEA):
        heads = list(Heads(startea, endea))
        for i in range(0, len(heads)):
            insnEA = heads[i]
            opnd0 = GetOpnd(insnEA, 0)
            opertor = GetMnem(insnEA)
            if isDirectCallAtEA(insnEA) and opnd0.startswith("__ZN11OSMetaClassC2EPKcPKS_j"):
                value, newreg = backwardResolveInHeads(heads, i, convertArgIdxToRegName(0))
                if value != None:
                    metaClassAddr = value
                value, newreg = backwardResolveInHeads(heads, i, convertArgIdxToRegName(1))
                if value != None:
                    className = GetString(value)
                value, newreg = backwardResolveInHeads(heads, i, convertArgIdxToRegName(3))
                if value != None:
                    classSize = value 
                value, newreg = backwardResolveInHeads(heads, i, convertArgIdxToRegName(2))
                if value != None:
                    parentMetaClassAddr = value
                    ''' is it ok to comment out these ?
                    segName = getSegName(parentMetaClassAddr)
                    if segName.endswith("__got"):
                        parentMetaClassAddr = Qword(parentMetaClassAddr) 
                    '''
                    valueName = getName(parentMetaClassAddr)
                    #if valueName.startswith("off_"):
                    #    parentMetaClassAddr = Qword(value)
                    #    valueName = getName(parentMetaClassAddr)
                    if (valueName is not None) and not valueName.startswith("unk_"):
                        parentMetaClassName =  Demangle(valueName, GetLongPrm(INF_SHORT_DN))
                        if parentMetaClassName != None:
                            parentClassName = parentMetaClassName[:parentMetaClassName.rfind("::")]

                # get metaclass vtable addr from next instruction
                nextInsnEA = heads[i+1]
                xrefAddr = get_first_dref_from(nextInsnEA)
                metaClassVTableAddr = xrefAddr
                if Qword(metaClassVTableAddr) == 0 and Qword(metaClassVTableAddr+8) == 0:
                    metaClassVTableAddr += 0x10

                classList.append([metaClassAddr, className, parentMetaClassAddr, parentClassName, classSize, metaClassVTableAddr])
                #print "metaClassAddr: " + hex(metaClassAddr) + ", " + "class: "+ str(className) + ", " + "parent: " + str(parentClassName) + ", " + "size: " + hex(classSize)
    return classList

def processVTableConstSeg(segStartEA):
    constSegEA = segStartEA
    constSegStartEA = SegStart(constSegEA)
    constSegEndEA = SegEnd(constSegEA)
    constSegName = SegName(constSegStartEA)
    currentEA = constSegStartEA
    while currentEA < constSegEndEA:
        value = Qword(currentEA)
        thisType = GetType(currentEA)
        if thisType is not None:
            thisType = thisType.strip()
            if thisType.startswith("vtable_") and not thisType.endswith("*"):
                None
        if value != 0:
            op_plain_offset(currentEA, 0, 0)
            valueSegName = getSegName(value)
            if not None is valueSegName and valueSegName.endswith("__text"):
                forceFunction(value)
        else:
            None
        currentEA += 0x8

def processVTableConstForKEXT(kextPrefix=None):
    if None is kextPrefix:
        segName = "__mod_term_func"
        constSegName = "__const"
    else:
        segName = kextPrefix + ":__mod_term_func"
        constSegName = kextPrefix + ":__const"
    seg = get_segm_by_name(segName)
    if not None is seg:
        nextSegName = segName
        nextSegStartEA = seg.startEA
        found = False
        while nextSegName != constSegName: 
            nextSeg = ida_segment.get_next_seg(nextSegStartEA)
            nextSegStartEA = nextSeg.startEA
            nextSegName = get_segm_name(nextSegStartEA)
            found = True
        if found:
            processVTableConstSeg(nextSegStartEA)


def containsUserClient():
    return get_name_ea(0, "__ZN12IOUserClient22_RESERVEDIOUserClient0Ev") != BADADDR or get_name_ea(0, "__ZN12IOUserClient23_RESERVEDIOUserClient15Ev") != BADADDR


def DefinedFunctions(kextPrefix=None):
    if None is kextPrefix:
        for segStartEA in Segments():
            segName = get_segm_name(segStartEA)
            segEndEA = SegEnd(segStartEA)
            if segName.endswith("__text"):
                for funcEA in Functions(segStartEA, segEndEA):
                    yield funcEA
    else:
        startea, endea = getTextAreaForKEXT(kextPrefix)
        if startea != BADADDR:
            for funcEA in Functions(startea, endea):
                yield funcEA


def DefinedUserEntries(kext=None):
    if None is kext:
        allUCInfos = getAllUCInfos()
    else:
        allUCInfos = getUCInfosForKEXT(kext)
    for className in allUCInfos:
        ucInfo = allUCInfos[className]
        entryEAs = ucInfo.getCallableUserEntryEAs()
        for funcEA,entryType in entryEAs:
            yield className, funcEA, entryType


def isFuncEnd(ea):
    mnem = GetMnem(ea)
    if mnem == "ret" or mnem == "RET":
        return True
    else:
        func = get_func(ea)
        bb = getBBAtEA(ea)
        if (not None is func):
            if ea == func.endEA and isDirectCallForJumpAtEA(ea):
                return True
            if (next_head(ea) == func.endEA):
                return True
            if (not None is bb):
                for bbsucc in bb.succs():
                    if bbsucc.startEA >= func.startEA and bbsucc.startEA < func.endEA:
                        return False
                return True
    return False

def isFuncStart(ea):
    return is_func(GetFlags(ea))

from ida_kernwin import Form, Choose, ask_str

def calcNonConstructorClass():
    vtClassNames = set()
    constructorClassNames = set()
    for ea, name in Names():
        deFuncName = getDeFuncNameOfName(name)
        if name.startswith("__ZTV"):
            #print name, deName
            deName = getDeNameOfName(name)
            if not None is deName:
                className = deName[len("`vtable for'"):]
                vtClassNames.add(className)
        elif not None is deFuncName and "::" in deFuncName and \
            deFuncName[:deFuncName.find("::")] == deFuncName[deFuncName.find("::")+2:]:
            className = deFuncName[:deFuncName.find("::")]
            constructorClassNames.add(className)
    print constructorClassNames
    noConClassNames =  vtClassNames-constructorClassNames
    print len(noConClassNames), len(vtClassNames), len(noConClassNames)*1.0/len(vtClassNames)

class EntryPointType(Enum):
    type1_externalMethod=0
    type1_getTargetAndMethodForIndex=1
    type1_getAsyncTargetAndMethodForIndex=2
    type1_getTargetAndTrapForIndex=3
    type2_externalMethod = 4
    type2_getTargetAndMethodForIndex=5
    type2_getAsyncTargetAndMethodForIndex=6
    type2_getTargetAndTrapForIndex=7

def getSegByName(segName):
    SegSelector = SegByName(segName)
    if SegSelector == BADADDR:
        return None
    SegEA = SegByBase(SegSelector)
    return getseg(SegEA)

def getCheckerIdx():
    checkerIdx = 0
    checkerResultFileName = None
    #print idc.ARGV
    if len(idc.ARGV) > 0:
        if len(idc.ARGV) > 1:
            arg = idc.ARGV[1]
            if arg.startswith("checker"):
                args = arg.split("_")
                checkerIdx = int(args[1])
                checkerResultFileName = "_".join(args[2:])
                #checkerResultFileName = args[2]
    else:
        checkerIdx = ask_long(0, "checker index")
    if None is checkerIdx:
        checkerIdx = 0

    return checkerIdx, checkerResultFileName


def concurrentProcess(handler):
    None

from pymongo import MongoClient
def getPerfDBCollect():
    osname = idbFilePath.split(os.sep)[-2].replace(".", "_")
    db_name = "iDEAPerf_{}".format("arm64" if isBinaryArm64() else "x86_64")
    client = MongoClient()
    db = client[db_name]
    binBasics = db.binBasics
    binBasics.update({"os": osname}, {"$set": {"os": osname, "path": idbFilePath}}, upsert=True)
    collect = db[osname]
    return collect

def getResultDBCollect():
    osname = idbFilePath.split(os.sep)[-2].replace(".", "_")
    db_name = "iDEAResult_{}".format("arm64" if isBinaryArm64() else "x86_64")
    client = MongoClient()
    db = client[db_name]
    binBasics = db.binBasics
    binBasics.update({"os": osname}, {"$set": {"os": osname, "path": idbFilePath}}, upsert=True)
    collect = db[osname]
    return collect
    None

def get_mod_init_seg_of_kext(kextPrefix=None):
    ''' In merged KC, the first __mod_init_func lists kernel initfuncs, the first __kmod_init lists kexts' initfuncs '''
    if None is kextPrefix:
        return get_segm_by_name("__mod_init_func")
    segname = kextPrefix + ":__mod_init_func"
    seg = get_segm_by_name(segname)
    if None is seg:
        segname = kextPrefix + ":__kmod_init"
        seg = get_segm_by_name(segname)
    return seg

def iterate_mod_init_segs(kextPrefix=None):
    for segea in Segments():
        segname = getSegName(segea)
        if segname.endswith("__mod_init_func") or segname.endswith("__kmod_init"):
            if (not None is kextPrefix and segname.startswith(kextPrefix)) or \
                    (None is kextPrefix):
                seg = getseg(segea)
                yield seg


def getFuncName(funcEA):
    funcName = getName(funcEA)
    if funcName.startswith("_"):
        return funcName
    segname = getSegName(funcEA)
    if segname.endswith("__stubs"):
        if isBinaryArm64():
            gotEA = GetOperandValue(funcEA, 1) + GetOperandValue(next_head(funcEA), 1)
            targetName = getName(Qword(gotEA))
            if None is targetName:
                print "None name gotEA {:016X} for {:016X}".format(gotEA, funcEA)
            if targetName.startswith("_"):
                return targetName
    return funcName
            

def is_metaclass_init_func(func, visited):
    if None is func:
        return False
    if func.startEA in visited:
        return False
    visited.add(func.startEA)
    for insn_ea in Heads(func.startEA, func.endEA):
        if isDirectCallAtEA(insn_ea):
            '''
            This relies on that the kernel has symbols (be careful on unnamed iOS KCs) 
            and kexts' got has been processed (be careful on calling processGOTSegForKEXT)
            '''
            called_funcname = getFuncName(GetOperandValue(insn_ea, 0))
            if None is called_funcname:
                print "[!] is_metaclass_init_func None called_funcname at {:016X}".format(insn_ea)
            if called_funcname.startswith("__ZN11OSMetaClassC"):
                return True
            else:
                called_funcea = GetOperandValue(insn_ea, 0)
                ret = is_metaclass_init_func(get_func(called_funcea), visited)
                if ret:
                    return True
    return False
    
def get_metaclass_init_funcs_mod_init_segs_(kextPrefix):
    None

def check_mod_init_segs_have_metaclass_init_funcs(kextPrefix=None):
    if isBinaryArm64() and kernelcache_status.isMerged:
        return True

    segs = iterate_mod_init_segs(kextPrefix)
    #return len(list(segs)) > 0
        
    for seg in segs:
        if None is seg:
            continue
        for ea in range(seg.startEA, seg.endEA, 8):
            funcea = Qword(ea)
            func = get_func(funcea)
            if is_metaclass_init_func(func, set()):
                return True
    print "[!] No metaclass init funcs in kext {}".format(kextPrefix)
    return False


def getSizeOfKEXT(kextPrefix):
    kextSize = 0
    segSizeMap = {}
    if isBinaryArm64():
        if None is kextPrefix:
            return kextSize, segSizeMap
        if not kernelcache_status.isMerged:
            for segEA in Segments():
                segName = getSegName(segEA)
                if segName.endswith("GAP_hidden"):
                    continue
                if segName.startswith(kextPrefix + ":"):
                    segStartEA = segEA
                    segSize = SegEnd(segEA) - segStartEA
                    segSizeMap[segName[len(kextPrefix)+1:]] = segSize
                    kextSize +=  segSize
        else:
            # For merged kernelcache, we can only calculate the size of text section
            textareas = getKEXTTextAreas()
            if kextPrefix in textareas:
                startea, endea = textareas[kextPrefix]
                textsize = endea-startea
                kextSize = textsize
                segSizeMap["__text"] = textsize

    elif isBinaryX86_64():
        for segEA in Segments():
            segName = getSegName(segEA)
            if segName == "UNDEF":
                continue
            segStartEA = segEA
            segSize = SegEnd(segEA) - segStartEA
            segSizeMap[segName] = segSize
            kextSize +=  segSize
    return kextSize, segSizeMap

def get_op_num(ea):
    for i in range(0, 0x10):
        if get_operand_type(ea, i) == 0:
            break
    if i == 0x10:
        print "[?] Op Num at {:016X} exceed 16?".format(ea)
    return i

import subprocess
    
def analysis_stages_go(analyze_stages, kextPrefix=None):
    if isBinaryX86_64():
        kextPrefix = None
    if not None is kernelcache_status and kernelcache_status.isMerged:
        pass
    elif not check_mod_init_segs_have_metaclass_init_funcs(kextPrefix):
        return
    
    kextSize, segSizes = getSizeOfKEXT(kextPrefix)

    perf_record = {"size_total": kextSize}

    for segname in segSizes:
        perf_record["segsize_{}".format(segname)] = segSizes[segname]

    if isBinaryArm64():
        perf_record["kext"] = kextPrefix
    elif isBinaryX86_64():
        perf_record["kext"] = modulename

    total_time = 0
    global wait_for_analysis_time
    for i in range(0, len(analyze_stages)):
        stage = analyze_stages[i]
        stage_func = stage[0]
        stage_label = stage[1]

        wait_for_analysis_time = 0

        stage_starttime = time.time()
        if isBinaryArm64():
            stage_func(kextPrefix)
        elif isBinaryX86_64():
            stage_func()
        stage_endtime = time.time()

        stage_dur = stage_endtime - stage_starttime - wait_for_analysis_time
        total_time += stage_dur
        perf_record["time_{}".format(stage_label)] = stage_dur
        print "time of {}: {} (excluded wait_for_analysis_time: {})".format(stage_label, stage_dur, wait_for_analysis_time)

    perf_record["time_total"] = total_time

    collect = getPerfDBCollect()
    collect.update_one({"kext": str(kextPrefix)}, {"$set": perf_record}, upsert=True)
    print "total time: {}".format(total_time)

    #markPhaseDone("ReadyForChecker_{}".format(kextPrefix))

def getKEXTNameForTextEA(textea):
    kextareas = getKEXTTextAreas()
    for kext in kextareas:
        startea, endea = kextareas[kext]
        if textea >= startea and textea < endea:
            return kext
    return None


def isInSameKEXT(addr0, addr1):
    if isBinaryX86_64():
        return True
    elif (not kernelcache_status.isMerged):
        segname0 = getSegName(addr0)
        segname1 = getSegName(addr1)
        if ":" in segname0 and ":" in segname1:
            return segname0[:segname0.find(":")] == segname1[:segname1.find(":")]
        elif ":" in segname0 or ":" in segname1:
            return False
    else:
        if getSegName(addr0).endswith("__text") and getSegName(addr1).endswith("__text"):
            segname0 = getKEXTNameForTextEA(addr0)
            segname1 = getKEXTNameForTextEA(addr1)
            return segname0 == segname1
        else:
            return True


    return True

import subprocess
class iOSKCStatus:
    def __init__(self):
        import kernel
        if not isBinaryArm64():
            return
        self.isMerged = kernel.kernelcache_format == kernel.KC_12_MERGED 
        try:
            nm_result_lines = subprocess.check_output(["nm", "-a", getOriginalBinaryPath()]).splitlines()
            self.isKernelSymbolic = len(nm_result_lines) > 10
        except subprocess.CalledProcessError:
            self.isKernelSymbolic = False

kernelcache_status = None
if isBinaryArm64():
    kernelcache_status = iOSKCStatus()

def findKEXTTextAreasForMergedKC():
    if None is kernelcache_status or not kernelcache_status.isMerged:
        return None
    kmodstartseg = get_segm_by_name("__kmod_start")
    kmodinfoseg = get_segm_by_name("__kmod_info")
    kmods = {}
    kmodnames = []
    if None is kmodstartseg or None is kmodinfoseg:
        print "[!] No __kmod_start seg"
        return None
    first_kmod_start = Qword(kmodstartseg.startEA)
    last_kmod_start = Qword(kmodstartseg.endEA-8)
    for ea in range(kmodinfoseg.startEA, kmodinfoseg.endEA, 8):
        kmodinfoea = Qword(ea)
        kmodname = GetString(kmodinfoea+0x10)
        #if None is kmodname or not kmodname.startswith("com.apple."):
        #    print "[?] kmodname {} at {:016X}".format(kmodname, kmodinfoea+0x10)
        if kmodname in kmodnames:
            kmodname += "_1"
        kmodnames.append(kmodname)
    kmodstart_entries =[Qword(ea) for ea in range(kmodstartseg.startEA, kmodstartseg.endEA, 8)]
    for i in range(0, len(kmodstart_entries)):
        entry = kmodstart_entries[i]
        kmodstart = Qword(entry+0x88)
        if i != len(kmodstart_entries)-1:
            kmodend = kmodstart_entries[i+1]
        else:
            kmodend = getseg(entry).endEA
        if kmodend < kmodstart or kmodstart < entry:
            print "[?] wrong kmodstart {:016X} for {:016X}".format(kmodstart, entry)
        if i < len(kmodnames):
            kmods[kmodnames[i]] = (kmodstart, kmodend)

    return kmods

def getKernelTextArea():
    if (not None is kernelcache_status) and kernelcache_status.isMerged:
        return findKernelTextAreaForMergedKC()
    kseg = get_segm_by_name("__TEXT_EXEC:__text")
    if not None is kseg:
        return kseg.startEA, kseg.endEA
    kseg = get_segm_by_name("__TEXT:__text")
    if not None is kseg:
        return kseg.startEA, kseg.endEA
    return None, None

def findKernelTextAreaForMergedKC():
    if None is kernelcache_status or not kernelcache_status.isMerged:
        return None, None
    textseg = get_segm_by_name("__text")
    kmodstartseg = get_segm_by_name("__kmod_start")
    kmodinfoseg = get_segm_by_name("__kmod_info")
    if None is kmodstartseg:
        print "[!] No __kmod_start seg"
        return None, None
    first_kmod_start = Qword(kmodstartseg.startEA)
    last_kmod_start = Qword(kmodstartseg.endEA-8)

    if textseg.startEA < first_kmod_start:
        return textseg.startEA, first_kmod_start
    return None, None

KEXTAreas = {}
def getKEXTTextAreas():
    global KEXTAreas
    if len(KEXTAreas) != 0:
        return KEXTAreas
    if kernelcache_status.isMerged:
        #KEXTAreas = findKEXTTextAreasForMergedKC()
        return findKEXTTextAreasForMergedKC()
    else:
        for segEA in Segments():
            segname = getSegName(segEA)
            if segname.endswith(":__text"):
                prefix = segname[:-7]
                if prefix in ["__TEXT_EXEC", "__TEXT", "__PLK_TEXT_EXEC"]:
                    continue
                elif prefix in KEXTAreas and \
                    KEXTAreas[prefix][0] != seg.startEA:
                    print "[!] Dup {}:__text, only the first is used".format(prefix)
                    continue
                    
                seg = getseg(segEA)
                KEXTAreas[prefix] = (seg.startEA, seg.endEA)
    return KEXTAreas

def getTextAreaForKEXT(kextPrefix):
    if isBinaryX86_64():
        textseg = get_segm_by_name("__text")
        if not None is textseg:
            return textseg.startEA, textseg.endEA
        else:
            return BADADDR, BADADDR
    areas = getKEXTTextAreas()
    if kextPrefix == "kernel":
        return getKernelTextArea()
    elif kextPrefix in areas:
        return areas[kextPrefix]
    else:
        return BADADDR, BADADDR



def getSegsByName(name):
    for segea in Segments():
        segName = getSegName(segea)
        if segName == name:
            yield getseg(segea)


class ObjTypeSrcType(Enum):
    FAILED = -1
    UNKNOWN = 0 
    ALLOC_CLASS_WITH_NAME = 1
    START_ARG_PASSED = 2
    START_CONFIG_FILE = 3
    CAST = 4
    CALLBACK_ARG = 5
    KERNEL_RET = 6
    CONSTRUCTOR = 7
    

def recordFoundObjType(ea, objname, objtinfo, srctype):
    #print "recordFoundObjType {:016X} {} {} {}".format(ea, objname, str(objtinfo), srctype)
    global OBJ_TYPES_REC
    func = get_func(ea)
    funcea = func.startEA
    if not funcea in OBJ_TYPES_REC:
        OBJ_TYPES_REC[funcea] = {}
    if isinstance(srctype, (str, unicode)):
        if str(srctype) ==  "__ZN11OSMetaClass18allocClassWithNameEPKc":
            srctype = ObjTypeSrcType.ALLOC_CLASS_WITH_NAME
        elif str(srctype) in ["__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass", \
            "__ZNK15OSMetaClassBase8metaCastEPKc"]:
            srctype = ObjTypeSrcType.CAST
        else:
            srctype == ObjTypeSrcType.UNKNOWN
    if not ea in OBJ_TYPES_REC[funcea]:
        OBJ_TYPES_REC[funcea][ea] = {}
    OBJ_TYPES_REC[funcea][ea][objname] = (objtinfo, srctype)



def getProviderRelFromInfo(info):
    if "IOKitPersonalities" in info:
        provider_rel = {}
        person = info["IOKitPersonalities"]
        for k in person:
            v =  person[k]
            if "IOClass" in v and "IOProviderClass" in v:
                provider_rel[v["IOClass"]] = v["IOProviderClass"]
            if "IOClass" in v and "IOUserClientClass" in v:
                provider_rel[v["IOUserClientClass"]] = v["IOClass"]
        return provider_rel
    else:
        return None





