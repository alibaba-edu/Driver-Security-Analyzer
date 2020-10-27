
# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
from idaapi import *
from idc import *

from HelperUtils import *
idaapi.require("HelperUtils")

# Stunned panda face icon data.
icon_data = "".join([
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF\x61\x00\x00\x02\xCA\x49\x44\x41\x54\x78\x5E\x65",
        "\x53\x6D\x48\x53\x6F\x14\x3F\xBA\xB5\xB7\xA0\x8D\x20\x41\xF2\xBA\x5D\xB6\x0F\x56\xF4\x41\xA2\xC0\x9C\xE9\xB4\x29\x4A\x7D\xB0\x22\x7A\x11\x02\x23\x48\x2A\xD4\x74\x53\x33\x3F\xD4",
        "\x3E\x4A\x50\x19\xE4\xB0\xD0\x22\xCD\x44\x45\x4A\x31\x8C\x92\xA2\x3E\x65\x0A\x4D\xCB\x96\x7E\xE8\xD5\x97\xCC\xFE\xFE\x37\xA7\x77\xDB\xBD\xA7\xE7\x3C\xBE\x05\x9E\xED\xB7\xB3\xF3",
        "\x7B\x39\xF7\xEE\x19\x17\xA8\xAC\x56\xDB\x54\x82\x60\x41\xB3\x59\xBC\xFF\xAC\xF9\xCA\xB5\xAE\x86\xCA\xF9\x4E\xAF\x1B\x3B\xEA\x5D\x48\x9D\x66\xE2\x49\x27\x9F\xD5\x66\x9B\xA2\x1C",
        "\x22\x02\xD0\x40\xE4\x81\x6C\x3B\x76\x37\x56\xE3\x37\x5F\x2F\x62\xE8\x0B\xD3\x66\x19\x7E\x53\xA7\x99\x78\xAE\x1F\x64\x3E\x21\x71\x69\x09\x5F\x20\x98\x2D\x58\x70\x24\x07\x07\x7B",
        "\x6F\xB0\x79\x82\x61\x81\x21\xCC\xDE\x21\x54\x16\x02\xD4\x69\x26\x9E\x74\xEE\xCB\xCF\x4D\xC7\x44\xB3\x88\x7C\x81\xC5\x22\xFE\x6C\xB9\xE9\x46\x67\x46\x1A\x8A\x16\x2B\x0A\x5B\x05",
        "\x74\x66\x65\xE1\x98\x6F\x00\x31\x32\x87\x9F\x59\x77\x66\x66\x61\x42\xBC\xC0\xF5\x6C\x47\x1A\x36\xD7\xB9\x51\x14\xC5\x1E\xBE\xA0\xC3\x5B\xD9\x98\x99\xE1\xC0\xCE\xBE\x57\x48\xD7",
        "\x9A\x63\x68\xEA\x7C\x8A\xF6\x14\x3B\x9F\xF6\xA6\xA4\x60\xEB\xE3\x3E\x9C\x5F\xD6\x5A\x7A\xFA\x71\xBF\xC3\x81\x3D\x4D\x35\x0D\x7C\xC1\xF3\x87\x57\x43\xF9\x87\x8F\x21\x95\x5E\xAB",
        "\x41\x83\x4E\x83\x54\xDB\x92\x76\x20\xCA\xBF\xD0\x99\x9D\xBB\x4E\xDB\xBD\xC7\x8E\x2F\x5A\x3D\x74\x3D\x50\x03\x80\x7E\x7A\x7A\x06\x46\x47\xFD\xA0\x33\x6C\x84\x18\x46\x0C\xBD\x1F",
        "\x86\x2D\x71\x71\x00\x52\x10\x16\x17\xE6\xC1\xE7\x1B\x61\x9A\x81\x69\x31\x30\xFC\x61\x14\xB4\x3A\x3D\x20\x82\x1E\x58\xA9\x15\x05\x41\x14\x05\xB8\x58\xEE\x82\x7D\xE9\x99\x20\xCB",
        "\x32\x94\x95\x95\xC3\xA5\xD2\x53\x00\x51\x09\xAA\x4B\x0B\xA1\xB8\xA4\x0C\x52\x53\x33\x40\xA5\x52\x81\xDB\x5D\x01\xA2\x45\x00\x45\x51\x80\x2A\x36\x12\x8D\x42\x49\x51\x01\x44\xE5",
        "\x18\x90\x22\x0A\x98\x8C\x46\xF0\x54\x14\x42\x6D\x7D\x3B\xE4\x1C\x75\x41\xAD\xB7\x1D\x3C\x55\x85\x60\x32\x19\x41\x8A\x2A\xDC\x57\x5C\x74\x12\x28\x47\xA5\x8E\x44\xE4\xF0\x76\x5B",
        "\x82\xA6\xCD\x5B\x0D\xB2\x12\xE6\xE4\x06\xB5\x1A\x66\xA7\x26\x41\x92\xC2\xA0\xD5\x6A\x60\x67\x92\x19\xAE\x7B\xCE\x70\x4D\x15\xAB\x01\xAD\xC1\x08\x3F\x46\x64\x6E\x8E\x9D\xF9\x13",
        "\xE8\x1A\xFF\xE4\x63\x8A\x0E\xE6\x02\x41\xF8\x3F\x18\x82\x40\x28\x04\xFD\xDD\x75\xF0\xB6\xFF\x2E\x75\x9A\x89\x27\x9D\xFB\xC8\x4F\x39\xBE\xE0\xB4\xAB\xCE\x35\xFE\x71\x00\x16\x17",
        "\x25\x76\x50\x26\x76\x6B\x61\x86\x08\xE4\x1D\xAF\x81\xBC\x13\x97\xA9\xD3\x4C\x3C\xE9\xDC\x47\x7E\xCA\xF1\x05\x0C\x5F\x7D\xFE\xEF\x35\x03\xAF\x9F\x00\xB0\x73\x30\x9A\xE2\x81\x0E",
        "\xF6\xC1\xED\x52\xB8\x77\xAB\x98\x3A\xCD\xC4\x73\x9D\x7C\x6F\xDE\xF9\xCF\x53\x0E\xFE\xA9\xCD\xAE\xB3\x87\xCE\x75\x35\x54\xE1\xD0\xCB\x47\x38\x39\x36\x88\xFF\x4D\xF8\x57\x41\x33",
        "\xF1\xA4\x93\x0F\x00\x36\xAD\x3E\x4C\x6B\xC5\xC9\x5D\x77\x6A\x2F\xB4\x31\xA3\xC4\x40\x4F\x21\x0F\xD1\x4C\x3C\xE9\x2B\xE1\xF5\x0B\xD6\x90\xC8\x90\x4C\xE6\x35\xD0\xCC\x79\x5E\xFF",
        "\x2E\xF8\x0B\x2F\x3D\xE5\xC3\x97\x06\xCF\xCF\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82"])

act_icon = load_custom_icon(data=icon_data, format="png")
act_name_struct = "idea:act_iDEA_in_struct"
act_name_pseucode = "idea:act_iDEA_in_pseucode"

hooks = None

class GoToItsFuncForVTableStructMember(action_handler_t):
    def __init__(self, message):
        action_handler_t.__init__(self)
        self.message = message
    def activate(self, ctx):
        #print "Hi, %s" % (self.message)
        #print ctx, ctx.cur_ea, ctx.cur_strmem, ctx.cur_struc, ctx.cur_extracted_ea
        if not None is ctx.cur_strmem and not None is ctx.cur_struc:
            member = ctx.cur_strmem
            struc = ctx.cur_struc
            memberId = member.id
            strucId = struc.id
            structName = get_struc_name(strucId)
            if structName.startswith("vtable_"):
                funcEA = getFuncEAForVTableMember(member)
                open_pseudocode(funcEA, False)
        return 1
    def update(self, ctx):
        #return AST_ENABLE_FOR_WIDGET if ctx.widget_type == BWN_STRUCTS else AST_DISABLE_FOR_WIDGET
        return AST_ENABLE if ctx.form_type == BWN_STRUCTS else AST_DISABLE

class PopupItemForChildFunc(action_handler_t):
    def __init__(self, funcEA):
        action_handler_t.__init__(self)
        self.funcEA = funcEA 

    def activate(self, ctx):
        #print "activate", ctx, ctx.cur_ea, ctx.cur_strmem, ctx.cur_struc, ctx.cur_extracted_ea
        open_pseudocode(self.funcEA, False)
        return 1

    def update(self, ctx):
        #print "update", ctx, ctx.cur_ea, ctx.cur_strmem, ctx.cur_struc, ctx.cur_extracted_ea
        return AST_ENABLE_FOR_WIDGET if ctx.widget_type == BWN_PSEUDOCODE else AST_DISABLE_FOR_WIDGET


class childFunc_chooser_handler_t(idaapi.action_handler_t):
    def __init__(self, thing):
        idaapi.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        sel = []
        for idx in ctx.chooser_selection:
            sel.append(str(idx))
        print "command %s selected @ %s" % (self.thing, ", ".join(sel))

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET \
            if idaapi.is_chooser_widget(ctx.widget_type) \
          else idaapi.AST_DISABLE_FOR_WIDGET


class ChooserToShowChildFuncs(Choose if isVersion70() else Choose2):

    def __init__(self, title, childFuncList, flags = 0,
                 modal = False,
                 embedded = False, width = None, height = None):
        if isVersion70():
            Choose.__init__(
                self,
                title,
                [ ["Address", 10], ["Name", 30] ],
                flags = flags | Choose.CH_CAN_REFRESH,
                embedded = embedded,
                width = width,
                height = height)
        else:
            Choose2.__init__(
                self,
                title,
                [ ["Address", 10], ["Name", 30] ],
                flags = flags ,
                embedded = embedded,
                width = width,
                height = height)

        print childFuncList        
        self.n = 0
        self.items = childFuncList
        self.icon = 5
        self.selcount = 0
        self.modal = modal
        #self.popup_names = ["Inzert", "Del leet", "Ehdeet", "Ree frech"]

    def OnInit(self):
        #print "inited", str(self)
        return True

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnSelectLine(self, n):
        #self.selcount += 1
        #warning("[%02d] selectline '%d'" % (self.selcount, n))
        funcEA = int(self.items[n][0], 0)
        print "OnSelectLine", funcEA
        open_pseudocode(funcEA, False)
        return 0 #(Choose.NOTHING_CHANGED, )

    def OnClose(self):
        None
        #print "closed", str(self)

    def show(self):
        return self.Show(self.modal) >= 0



# -----------------------------------------------------------------------
def child_func_choose(modal = True, childFuncList = []):
    global c
    c = ChooserToShowChildFuncs("Choose - Child Funcs", childFuncList = childFuncList, modal = modal)
    c.show()


# IDB Hooks to process change func type or name
class HooksToChangeFuncTypeOrName(IDB_Hooks):
    # type changed
    def ti_changed(self, ea, *args):
        #print "ti_changed", hex(ea)
        func = get_func(ea)
        # change member type when its func type changed, not vice verse
        if not None is func:
            funcStartEA = func.startEA
            if ea == funcStartEA:
                funcName = HelperUtils.getName(ea)
                demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
                funcType = GetType(ea)
                funcTypeArgStartLoc = funcType.find("(")
                funcPTRType = funcType[:funcTypeArgStartLoc] + "(*)" +  funcType[funcTypeArgStartLoc:]
                vtableMemberList = getVTableMemberListForFuncEA(funcStartEA)
                for vtableMember in vtableMemberList:
                    # vtableMemberFullName = get_member_fullname(vtableMember.id)
                    # keep consistency between func and vtable struct member, can also call keepCon_FuncAndStructsMember here
                    ret = SetType(vtableMember.id, funcPTRType)
                offset = -1
                if len(vtableMemberList) > 0:
                    offset = vtableMemberList[0].soff
                className = None
                if not None is demangledFuncName:
                    className = demangledFuncName[:demangledFuncName.rfind("::")]
                elif "::" in funcName:
                    className = funcName[:funcName.rfind("::")]

                if className != None:
                    keepCon_ParentAndChildrenVTableAtOffset(className, funcStartEA, offset, False, True)
        return 0

    def renamed(self, ea, new_name, local_name):
        #print "renamed", hex(ea), new_name, local_name
        func = get_func(ea)
        # change member type when its func type changed, not vice verse
        if not None is func:
            funcStartEA = func.startEA
            if ea == funcStartEA:
                funcName = HelperUtils.getName(ea)
                demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
                vtableMemberList = getVTableMemberListForFuncEA(funcStartEA)
                offset = -1
                if len(vtableMemberList) > 0:
                    offset = vtableMemberList[0].soff
                for vtableMember in vtableMemberList:
                    vtableMemberFullName = get_member_fullname(vtableMember.id)
                    vtableStruct = get_member_struc(vtableMemberFullName)
                    if vtableStruct != None:
                        # keep consistency between func and vtable struct member, can also call keepCon_FuncAndStructsMember here
                        SetMemberName(vtableStruct.id, vtableMember.soff, new_name)
                className = None
                if not None is demangledFuncName:
                    className = demangledFuncName[:demangledFuncName.rfind("::")]
                elif "::" in funcName:
                    className = funcName[:funcName.rfind("::")]
                keepCon_ParentAndChildrenVTableAtOffset(className, funcStartEA, offset, True, False)
        return 0

def getMemberByMemberId(memberId):
    member = get_member_by_id(memberId)
    if type(member) == list: # In IDA Pro 7, the return value is a list
        member = member[0]
    return member

def getVTableMemberListForFuncEA(funcEA):
    vtableMemberList = []
    xref = get_first_dref_to(funcEA)
    while xref != BADADDR:
        member = getMemberByMemberId(xref)
        if not None is member:
            vtableMemberList.append(member)
        xref = get_next_dref_to(funcEA, xref)
    return vtableMemberList


def getFuncEAForVTableMember(member):
    funcEA = None
    memberId = member.id
    memberOff = member.soff
    memberFullName = idaapi.get_member_fullname(memberId)
    memberName = idaapi.get_member_name(memberId)
    structName = memberFullName[:-len(memberName)]
    xref = get_first_dref_from(memberId)
    if structName.startswith("vtable_"):
        className = structName[len("vtable_"):]
        funcEA = xref
        if xref == None:
            if className in classNameToVTableAddrMap:
                vtableStartEA, vtableEndEA = classNameToVTableAddrMap[className]
                funcEA = Qword(vtableStartEA + memberOff)
            else:
                if className.endswith("::MetaClass"):
                    hostClassName = className[:-len("::MetaClass")]
                    vtableName = "__ZTVN" + str(len(hostClassName)) + hostClassName + "9MetaClassE"
                else:
                    vtableName = "__ZTV" + str(len(className)) + className
                vtableEA = get_name_ea(0, vtableName)
                if vtableEA != BADADDR:
                    funcEA = Qword(vtableEA + 0x10 + memberOff)
    return funcEA


def hexraysCallBackToProcessPseucodeAction(event, *args):
    if event == hxe_right_click:
        #print "rightclick",event,args[0].item.get_memptr().id
        None
    elif event == hxe_populating_popup:
        #print "popup", event, args
        widget = args[0]
        popup = args[1]
        member = args[2].item.get_memptr()
        #print args[1]
        if not None is member:
            memberId = member.id
            memberOff = member.soff
            memberFullName = idaapi.get_member_fullname(memberId)
            struct = get_member_struc(memberFullName)
            structName = get_struc_name(struct.id)
            childFuncEAList = []
            if structName.startswith("vtable_"):
                funcEA = getFuncEAForVTableMember(member)
                className = structName[len("vtable_"):]
                childVirtualFuncEAToClassNameMap = getAllChildVirtualFuncAtOffset(className, funcEA, memberOff)
                keys = childVirtualFuncEAToClassNameMap.keys()
                keys.sort()
                count = 0
                while count < len(keys):
                    funcEA = keys[count]
                    funcName = HelperUtils.getName(funcEA)
                    demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
                    if demangledFuncName != None:
                        funcName = demangledFuncName
                    #add_custom_viewer_popup_item(args[0].ct, funcName, str(count+1), open_pseudocode, funcEA)
                    desc = action_desc_t(act_name_pseucode + str(count+1), funcName, PopupItemForChildFunc(funcEA), str(count+1))
                    attach_dynamic_action_to_popup(widget, popup, desc)
                    count += 1
        None
    elif event == hxe_double_click:
        member = args[0].item.get_memptr()
        if not None is member:
            memberId = member.id
            memberOff = member.soff
            memberFullName = idaapi.get_member_fullname(memberId)
            struct = get_member_struc(memberFullName)
            structName = get_struc_name(struct.id)
            childFuncEAList = []
            if structName.startswith("vtable_"):
                funcEA = getFuncEAForVTableMember(member)
                if funcEA != None:
                    open_pseudocode(funcEA, False)
        #print "doubleclick",event,args[0].item
    elif event == hxe_keyboard:
        #print hex(args[0].item.get_ea())
        if args[1] == 84: # 84 = "T"
            member = args[0].item.get_memptr()
            if not None is member:
                memberId = member.id
                memberOff = member.soff
                memberFullName = idaapi.get_member_fullname(memberId)
                struct = get_member_struc(memberFullName)
                structName = get_struc_name(struct.id)
                childFuncEAList = []
                if structName.startswith("vtable_"):
                    funcEA = getFuncEAForVTableMember(member)
                    className = structName[len("vtable_"):]
                    childVirtualFuncEAToClassNameMap = getAllChildVirtualFuncAtOffset(className, funcEA, memberOff)
                    if not className in predefinedClassNameSet:
                        #if args[1] > 48 and args[1]-49<len(childVirtualFuncEAToClassNameMap) : # 48 = "0"
                        #    keys = childVirtualFuncEAToClassNameMap.keys()
                        #    keys.sort()
                        #    funcEA = keys[args[1] - 49]
                        #    open_pseudocode(funcEA, False)
                        if len(childVirtualFuncEAToClassNameMap) > 0: # 84 = "T"
                            keys = childVirtualFuncEAToClassNameMap.keys()
                            keys.sort()
                            childFuncList = []
                            for funcEA in keys:
                                funcName = HelperUtils.getName(funcEA)
                                demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
                                if demangledFuncName != None:
                                    funcName = demangledFuncName
                                childFuncList.append([hex(funcEA), funcName])
                            child_func_choose(True, childFuncList)
            elif isEAFuncStart(args[0].item.get_ea()):
                funcEA = args[0].item.get_ea()
                if  isFuncVirtual(funcEA):
                    className = getClassNameFromFuncStartEA(funcEA)
                    if className != None and not className in predefinedClassNameSet:
                        #print "func child?"
                        offset = getFuncVirtualOffset(funcEA, className)
                        childVirtualFuncEAToClassNameMap = getAllChildVirtualFuncAtOffset(className, funcEA, offset)
                        if  len(childVirtualFuncEAToClassNameMap) > 0: 
                            keys = childVirtualFuncEAToClassNameMap.keys()
                            keys.sort()
                            childFuncList = []
                            for funcEA in keys:
                                funcName = HelperUtils.getName(funcEA)
                                demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
                                if demangledFuncName != None:
                                    funcName = demangledFuncName
                                childFuncList.append([hex(funcEA), funcName])
                            child_func_choose(True, childFuncList)
    return 0

def getFuncVirtualOffset(funcEA, className):
    xref = get_first_dref_to(funcEA)
    member = None
    memberOff = -1 
    while xref != BADADDR:
        member = getMemberByMemberId(xref)
        if not None is member:
            break
        get_next_dref_to(funcEA, xref)
    if not None is member:
        memberOff = member.soff
    elif not None is className:
        vtableStartEA = None
        vtableEndEA = None
        if className in classNameToVTableAddrMap:
            vtableStartEA, vtableEndEA = classNameToVTableAddrMap[className]
            funcEA = Qword(vtableStartEA + memberOff)
        else:
            if className.endswith("::MetaClass"):
                hostClassName = className[:-len("::MetaClass")]
                vtableName = "__ZTVN" + str(len(hostClassName)) + hostClassName + "9MetaClassE"
            else:
                vtableName = "__ZTV" + str(len(className)) + className
            vtableStartEA = get_name_ea(0, vtableName)
            if vtableStartEA != BADADDR:
                vtableStartEA = vtableStartEA + 0x10
                vtableEA = vtableStartEA
                currentFuncEA = Qword(vtableEA)
                while currentFuncEA != 0:
                    if currentFuncEA == funcEA:
                        return (vtableEA - vtableStartEA)/8
        if vtableStartEA != None and vtableEndEA != None:
            for currenetEA in range(vtableStartEA, vtableEndEA, 8):
                if Qword(currenetEA) == funcEA:
                    return (currenetEA - vtableStartEA)/8
    return memberOff


def getClassNameFromFuncStartEA(funcEA):
    funcName = HelperUtils.getName(funcEA)
    demangledFuncName = Demangle(funcName, GetLongPrm(INF_LONG_DN))
    className = None
    if not None is demangledFuncName:
        className = demangledFuncName[:demangledFuncName.rfind("::")]
    elif "::" in funcName:
        className = funcName[:funcName.rfind("::")]
    return className
    None

def isEAFuncStart(ea):
    result = False
    func = get_func(ea)
    if not None is func:
        funcStartEA = func.startEA
        if ea == funcStartEA:
            result = True
    return result
    None

#HelperUtils.rebuildAllInternalDataWOParseModInitFunc()
HelperUtils.loadNecessaryDataFromPersistNode()
#HelperUtils.ensureAllNecessaryDataPreparedAndStored()

# Hexray callback to process pseucode double click
install_hexrays_callback(hexraysCallBackToProcessPseucodeAction)

# UI Hooks to process vtable struct goto
if register_action(action_desc_t(
    act_name_struct,           # Name. Acts as an ID. Must be unique.
    "GoToItsFuncForVTableStructMember",          # Label. That's what users see.
    GoToItsFuncForVTableStructMember("developer"), # Handler. Called when activated, and for updating
    "Ctrl+H",         # Shortcut (optional)
    "Go to the virtual func",  # Tooltip (optional)
    act_icon)):          # Icon ID (optional)
    print "Action registered. Attaching to menu."

    class Hooks(UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            # We'll add our action to all "Pseudocode-A*"s.
            # If we wanted to add it only to "Pseudocode-A", we could
            # also discriminate on the widget's title:
            #
            #  if get_widget_title(widget) == "Pseudocode-A":
            #      ...
            #
            print widget, popup
            if get_widget_type(widget) == BWN_STRUCTS:
                attach_action_to_popup(widget, popup, act_name_struct, None)
    hooks = Hooks()
    hooks.hook()
else:
    #print "Action found; unregistering."
    # No need to call detach_action_from_menu(); it'll be
    # done automatically on destruction of the action.
    if unregister_action(act_name_struct):
        print "Unregistered."
    else:
        print "Failed to unregister action."
    if hooks is not None:
        hooks.unhook()
        hooks = None

