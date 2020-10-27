# Copyright (C) 2020 Alibaba Group Holding Limited

from HelperUtils import *
idaapi.require("HelperUtils")
import json
import kernel

def exportToFile(filePath):
    all_struct_json_dict = {}
    all_vtable_json_dict = {}
    result = {}
    definedClasses = getDefinedClasses()
    for className in definedClasses:
        structId = GetStrucIdByName(className)
        struct_json_dict = {}
        if structId != BADADDR and structId != -1:
            struct = get_struc(structId)
            struct_json_dict = getJsonDictForStruct(struct)
        vtableStructId = GetStrucIdByName("vtable_" + className)
        vtable_struct_json_dict = {}
        if vtableStructId != BADADDR and vtableStructId != -1:
            vtableStruct = get_struc(vtableStructId)
            vtable_struct_json_dict = getJsonDictForStruct(vtableStruct)
        vtStartEA, vtEndEA = getVTableAddrOfClass(className)
        vtable_json_list = []
        if vtStartEA != BADADDR:
            vtable_json_list = getJsonListForVTable(vtStartEA, vtEndEA)
        result[className] = {"struct": struct_json_dict, "vtable": vtable_json_list, "vtable_struct": vtable_struct_json_dict}

    with open(filePath, "w") as fp:
        json.dump(result, fp)

def createStructByJsonDict(struct_name, struct_json_dict, excludeFirst=False):
    struct_size = struct_json_dict["size"]
    struct_id = createClassStruct(struct_name, struct_size)
    struct_members = struct_json_dict["members"]
    for i in range(0, len(struct_members)):
        if excludeFirst and i == 0:
            continue
        member = struct_members[i]
        SetMemberName(struct_id, member["soff"], member["name"])
        if not None is member["type"]:
            memberId = GetMemberId(struct_id, member["soff"])
            SetType(memberId, member["type"])
    return struct_id


def importFromFile(filePath):
    all_class_json_dict = None
    with open(filePath, "r") as fp:
        all_class_json_dict = byteify_noignoredict(json.load(fp))
    if not None is all_class_json_dict:
        #print all_class_json_dict.keys()
        for className in all_class_json_dict:
            if className.endswith("::MetaClass"):
                # no need to import metaclass vtables 
                continue
            struct_json_dict = all_class_json_dict[className]["struct"]
            classStructId = GetStrucIdByName(className)
            alreadyExist = (classStructId != BADADDR and classStructId != -1)
            if not alreadyExist:
                 classStructId = createStructByJsonDict(className, struct_json_dict, True)
            vtStartEA, vtEndEA = getVTableAddrOfClass(className)
            if vtStartEA != BADADDR:
                vtable_json_list = all_class_json_dict[className]["vtable"]
                parentClassName = getParentClassNameOfClass(className)
                if not parentClassName in all_class_json_dict:
                    print "[!] {}'s parent {} is not in json dict".format(className, parentClassName)
                    continue
                parent_vtable_json_list = all_class_json_dict[parentClassName]["vtable"]
                selfDefVFuncStartOff = getSelfDefinedVFuncStartOffsetOfClass(className)
                if None is selfDefVFuncStartOff:
                    continue

                if (vtEndEA-vtStartEA)/8 != len(vtable_json_list) and (len(vtable_json_list) - len(parent_vtable_json_list)) != (vtEndEA-vtStartEA-selfDefVFuncStartOff)/8 :
                    print "[!] {} VTable size inconsisitent. here: {} import: {}".format(className, (vtEndEA-vtStartEA-selfDefVFuncStartOff)/8 , (len(vtable_json_list) - len(parent_vtable_json_list)))
                    continue
                
                #for currentEA in range(vtStartEA, vtEndEA, 8):
                for currentEA in range(vtEndEA-8, vtStartEA+selfDefVFuncStartOff-16, -8):
                    funcEA = Qword(currentEA)
                    funcName = getName(funcEA)
                    if isEAValid(funcEA) and (not funcName.startswith("__")):
                        #funcIdx = (currentEA - vtStartEA)/8 
                        funcIdx =  (currentEA - vtEndEA)/8
                        vfunc_json_info = vtable_json_list[funcIdx]
                        newFuncName = vfunc_json_info["name"]
                        if (not newFuncName.startswith("__")) or newFuncName.startswith("___cxa_pure_virtual"):
                            continue
                        set_name(funcEA, newFuncName)
                        funcType = vfunc_json_info["type"]
                        if not None is funcType:
                            funcType = funcType[:funcType.find("(")] + newFuncName + funcType[funcType.find("(")]
                            SetType(funcEA, funcType)
                keepCon_VTAndVTS_ForClass(className)
            else:
                vtable_struct_json_dict = all_class_json_dict[className]["vtable_struct"]
                createStructByJsonDict("vtable_" + className, vtable_struct_json_dict)
                createWholeVTableStructForClass(className)
            if not alreadyExist:
                SetMemberName(classStructId, 0, "vtable")
                memberId = GetMemberId(classStructId, 0)
                SetType(memberId, "vtable_" + className + "*")
            

def getJsonDictForStruct(struct):
    memqty = struct.memqty
    struct_members_json_list = []
    for i in range(0, memqty):
        member = struct.get_member(memqty)
        member_json = {}
        member_json["name"] = ida_struct.get_member_name(member.id)
        member_json["soff"] = member.soff
        member_json["eoff"] = member.eoff
        #member_json["size"] = member.size
        member_json["type"] = GetType(member.id)
        struct_members_json_list.append(member_json)
    struct_json_dict = {}
    struct_json_dict["name"] = get_struc_name(struct.id)
    struct_json_dict["size"] = get_struc_size(struct.id)
    struct_json_dict["members"] = struct_members_json_list
    return struct_json_dict

def getJsonListForVTable(vtStartEA, vtEndEA):
    if vtStartEA == BADADDR:
        return None
    result = []
    for ea in range(vtStartEA, vtEndEA, 8):
        vfuncEA = Qword(ea)
        vfuncName = getName(vfuncEA)
        vfuncType = GetType(vfuncEA)
        result.append({"name": vfuncName, "type": vfuncType})
    return result
