# Copyright (C) 2020 Alibaba Group Holding Limited

from Arm64Utils import *
idaapi.require("Arm64Utils")
import tagged_pointers

def untagAllPointers():
    tagged_pointers.untag_pointers()

def healFunctionsInTextSeg(segStartEA):
    textSegEA = segStartEA
    textSegStartEA = SegStart(textSegEA)
    textSegEndEA = SegEnd(textSegEA)
    currentEA = textSegEndEA
    while currentEA >= textSegStartEA:
        None

def checkIfAllFuncsCreateCorrect():
    for kextPrefix in getAllKEXTPrefixes():
        startea, endea = getTextAreaForKEXT(kextPrefix)
        checkIfFuncCreateCorrectInSeg(startea, endea)

def checkIfFuncCreateCorrectInSeg(textSegStartEA, textSegEndEA ):
    funcEAs = Functions(textSegStartEA, textSegEndEA)
    for funcEA in funcEAs:
        xrefs = getXRefsTo(funcEA)
        if len(xrefs) == 0:
            print "[!] Func created at {:016X} has no xrefs".format(funcEA)


def checkIfFuncCreatedInSeg(segStartEA):
    textSegEA = segStartEA
    textSegStartEA = SegStart(textSegEA)
    textSegEndEA = SegEnd(textSegEA)
    currentEA = textSegStartEA
    while currentEA < textSegEndEA:
        if Dword(currentEA) > 0xFFFF0000:
            currentEA += 4
            continue
        if Qword(currentEA) > 0xFFFFFFF000000000 or Qword(currentEA) == 0:
            ''' This is a jump table '''
            currentEA += 0x8
            continue
        func = get_func(currentEA)
        if not isCode(GetFlags(currentEA)) or None is func :
            print "[!] Func not created at {}".format(hex(currentEA))
            return
        else:
            if currentEA < func.startEA or currentEA >= func.endEA:
                print "[!] Not a continous func at {}".format(hex(currentEA))
                return
            else:
                currentEA = func.endEA

def isStackPushAtEA(ea):
    return GetMnem(ea) == "STP" and GetOpnd(ea, 2).startswith("[SP,")

def isX29X30PushAtEA(ea):
    return GetMnem(ea) == "STP" and GetOpnd(ea, 2).startswith("[SP,") and GetOpnd(ea, 0) == "X29" and GetOpnd(ea, 1) == "X30"

def isBPSet(ea):
    return (GetMnem(ea) == "ADD" and GetOpnd(ea, 1) == "SP" and GetOpnd(ea, 0) == "X29") or (GetMnem(ea) == "MOV" and GetOpnd(ea, 1) == "SP" and GetOpnd(ea, 0) == "X29")

def isSPSubAtEA(ea):
    return GetMnem(ea) == "SUB" and GetOpnd(ea, 1) == "SP" and GetOpnd(ea, 0) == "SP"



def checkIfFuncHeadAtEA(ea):
    currentEA = ea
    isStackPushFound = False
    isX29X30PushFound = False
    while True:
        if isSPSubAtEA(currentEA):
            currentEA += 4
            continue
        if isStackPushAtEA(currentEA):
            isStackPushFound = True
        if not isStackPushAtEA(currentEA):
            break
        isStackPushFound = True
        currentEA += 4
    if isStackPushFound and isBPSet(currentEA) and isX29X30PushAtEA:
        prev_mnem = GetMnem(ea-4)
        if prev_mnem == "B" or prev_mnem == "RET":
            return True, currentEA
    return False, ea

def splitFuncIfNewHeadFound(funcEA):
    func = get_func(funcEA)
    funcStartEA = func.startEA
    funcEndEA = func.endEA
    currentEA = funcStartEA
    while currentEA < funcEndEA:
        if GetMnem(currentEA) == "BL":
            targetEA = GetOperandValue(currentEA, 0)
            if not isFuncStart(targetEA):
                ida_utilities.force_function(targetEA)
        else:
            isFuncHead, funcHeadEndEA = checkIfFuncHeadAtEA(currentEA)
            if isFuncHead:
                ida_utilities.force_function(currentEA)
                currentEA = funcHeadEndEA
        currentEA += 4

def splitFuncsIfNewHeadFoundForKext(kextPrefix):
    textSegStartEA, textSegEndEA = getTextAreaForKEXT(kextPrefix)
    for funcEA in Functions(textSegStartEA, textSegEndEA):
        splitFuncIfNewHeadFound(funcEA)

def splitFuncsIfNewHeadFoundForAll():
    for kextPrefix in getAllKEXTPrefixes():
        splitFuncsIfNewHeadFoundForKext(kextPrefix)


def makeCodeInAllText():
    for kextPrefix in getAllKEXTPrefixes():
        makeCodeInTextForKext(kextPrefix)

def makeCodeInTextForKext(kextPrefix):
    textSegStartEA, textSegEndEA = getTextAreaForKEXT(kextPrefix)
    currentEA = textSegStartEA
    while currentEA < textSegEndEA:
        if Dword(currentEA) > 0xFFFF0000:
            currentEA += 4
            continue
        if Qword(currentEA) > 0xFFFFFFF000000000 or Qword(currentEA) == 0:
            ''' This is a jump table '''
            currentEA += 0x8
            continue
        if not isCode(GetFlags(currentEA)):
            MakeCode(currentEA)

        currentEA += 4

def createFuncAtEA(ea):
    while not isCode(GetFlags(ea)):
        ret = MakeCode(ea)
        if ret == 0:
            ea += 4
        else:
            break
    func = get_func(ea)
    if None is func :
        ida_utilities.force_function(ea)
        func = get_func(ea)
    elif ea < func.startEA or ea >= func.endEA:
        ida_utilities.force_function(ea)
        func = get_func(ea)
    funcName = getName(ea)
    # Below is not necessary, since we now have solve variable types
    if funcName.startswith("sub_"):
        argNum = guessArgNumberForFuncAtEA_arm64(ea)
        if argNum > 0:
            SetType(ea, "uint64_t " + funcName + "(" + "uint64_t,"*(argNum-1) + "uint64_t)")
    return func

def createFunctionsForTextSeg(textSegStartEA, textSegEndEA):
    currentEA = textSegStartEA
    while currentEA < textSegEndEA:
        if (Dword(currentEA) > 0xFFFF0000):
            currentEA += 4
            continue
        if (Qword(currentEA) > 0xFFFFFFF000000000):
            ''' This is a jump table '''
            currentEA += 0x8
            continue
        func = createFuncAtEA(currentEA)
        if None is func:
            print "[!] Still not succeed in create func at {}.".format(hex(currentEA))
            currentEA = ida_funcs.get_next_fchunk(currentEA).startEA
        else:
            currentEA = func.endEA
        

def createFunctionsForKEXT(kextPrefix):
    makeCodeInTextForKext(kextPrefix)
    startea, endea = getTextAreaForKEXT(kextPrefix)
    if startea != BADADDR:
        createFunctionsForTextSeg(startea, endea)
    splitFuncsIfNewHeadFoundForKext(kextPrefix)

def createAllFunctions():
    phase = "createAllFunctions"
    if checkPhaseDone(phase):
        return
    print "[+] Create All Functions"
    makeCodeInAllText()
    for segStartEA in Segments():
        segName = get_segm_name(segStartEA)
        if segName.endswith("__text") and segName != "__PLK_TEXT_EXEC:__text":
            #print segName
            seg = getseg(segStartEA)
            createFunctionsForTextSeg(seg.startEA, seg.endEA)
    splitFuncsIfNewHeadFoundForAll()
    markPhaseDone(phase)


def importKnownStructsFromHeader():
    knownStructsHeaderDirPath = ""
    knownStructsHeaderFilePath = os.path.join(knownStructsHeaderDirPath, "Kernel_mine.h")
    knownStructsHeaderFile = open(knownStructsHeaderFilePath, "r")


def renameKnownFuncsForKEXT(kextPrefix):
    seg = get_segm_by_name(kextPrefix + ':__stubs')
    if not None is seg:
        current_ea = seg.start_ea
        while current_ea < seg.end_ea:
            ida_utilities.force_function(current_ea)
            rename_stub(current_ea)
            current_ea += 12
        '''
        func = ida_funcs.get_func(seg.start_ea)
        if func is None:
            func = ida_funcs.get_next_func(seg.start_ea)
        while func and func.start_ea < seg.end_ea:
            rename_stub(func.start_ea)
            func = ida_funcs.get_next_func(func.start_ea)
        '''

def renameAllKnownFuncs():
    phase = "renameAllKnownFuncs"
    if checkPhaseDone(phase):
        return
    print "[+] Rename functions referenced to kernel functions"
    for n in xrange(get_segm_qty()):
        seg = getnseg(n)

        segname = get_segm_name(seg.startEA)
        # The __stubs segments contain the jump tables
        if not segname.endswith('__stubs'):
            continue

        current_ea = seg.start_ea
        while current_ea < seg.end_ea:
            ida_utilities.force_function(current_ea)
            rename_stub(current_ea)
            current_ea += 12

    markPhaseDone(phase)

def fixIDAProMistakes():
    fixWrongGAPHidden()
    wait_for_analysis_to_finish()

def fixWrongGAPHidden():
    for segStartEA in Segments():
        segName = SegName(segStartEA)
        if segName.endswith(":GAP_hidden"):
            segEndEA = SegEnd(segStartEA)
            isWrongGAPHidden = False
            for ea in range(segStartEA, segEndEA, 4):
                content = Dword(ea)
                if ea + 3 >= segEndEA:
                    break
                if content != 0:
                    print "[!] Non-Zero at {:016X}".format(ea)
                    isWrongGAPHidden = True
                    break
            if isWrongGAPHidden:
                print "[!] Wrong GAP_hidden at {:016X}".format(segStartEA)
                prevseg = get_prev_seg(segStartEA)
                prevseg_startea = prevseg.startEA
                del_segm(segStartEA, 2)
                set_segm_end(prevseg_startea, segEndEA, 6)

print "[+] Arm64Preprocessor loaded"
