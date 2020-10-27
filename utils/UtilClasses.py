# Copyright (C) 2020 Alibaba Group Holding Limited

from enum import Enum

class FuncInfo():
    def __init__(self, mangledName, className, funcName, argList, returnType, isStatic, isVirtual, isConst):
        self.mangledName = str(mangledName)
        self.className = str(className)
        self.funcName = str(funcName)
        self.argList = argList
        self.returnType = str(returnType)
        self.isStatic = isStatic
        self.isVirtual = isVirtual
        self.isConst = isConst

    def __iter__(self):
        for attr, value in self.__dict__.iteritems():
            if attr == "argList":
                argDictList = []
                for arg in value:
                    argDict = dict(arg)
                    argDictList.append(argDict)
                yield attr, argDictList
            else:
                yield attr, value

    def getFuncTypeToSet(self, isFuncPtr=False):
        hasThis = not self.className is None and not self.isStatic
        if hasThis:
            argString = self.className + "* this"
            if len(self.argList) > 0:
                argString = argString + ", "
        else:
            argString = ""
        argString = "(" + argString + ", ".join([str(arg).replace("[]", "*") for arg in self.argList]) + ")"
        typeToSet = " ".join([self.returnType, self.mangledName if not isFuncPtr else "(*" + self.mangledName + ")", argString])  
        return typeToSet

    def __str__(self):
        return self.getFuncTypeToSet()


class ArgInfo():
    def __init__(self, argType, argName):
        self.argType = str(argType)
        self.argName = str(argName)
    def __iter__(self):
        for attr, value in self.__dict__.iteritems():
            yield attr, value
    def __str__(self):
        funcPtrPos = self.argType.find("(*)")
        if funcPtrPos == -1: # it is not a function pointer
            return self.argType + " " + self.argName
        else:
            return self.argType[:funcPtrPos] + "(*" + self.argName + ")" + self.argType[funcPtrPos+3:]


class UserClientInfo():
    def __init__(self, className):
        self.className = className
        self.sMethods_DispatchMethod = []
        self.sMethods_Method = []
        self.callBacks = {}
        self.callableCallBacks = {}
        self.callableCallBackNames = ["externalMethod", \
            "getTargetAndMethodForIndex", \
            "getAsyncTargetAndMethodForIndex", \
            "getTargetAndTrapForIndex", \
            "clientClose", "clientMemoryForType", \
            "registerNotificationPort", "setProperties"]
        #self.externalMethodCB = None
        #self.targetMethodCB = None
        #self.targetTrapCB = None
    
    def addSMethod(self, sMethodEA, isDispatch):
        if isDispatch:
            self.sMethods_DispatchMethod.append(sMethodEA)
        else:
            self.sMethods_Method.append(sMethodEA)

    def addCallBack(self, callBackName, callBackEA):
        self.callBacks[callBackName] = callBackEA
        if callBackName in self.callableCallBackNames:
            self.callableCallBacks[callBackName] = callBackEA

    def getCallBackEA(self, callBackName):
        if callBackName in self.callBacks:
            return self.callBacks[callBackName]
        return BADADDR 

    def getAllUserEntryEAs(self):
        userEntries = []
        userEntries.extend(self.sMethods_DispatchMethod)
        userEntries.extend(self.sMethods_Method)
        userEntries.extend(self.callBacks.values())
        return userEntries

    def getCallableUserEntryEAs(self):
        userEntries = []
        for ea in self.sMethods_DispatchMethod:
            userEntries.append((ea, EntryType.DISPATCHMETHOD))
        for ea in self.sMethods_Method:
            userEntries.append((ea, EntryType.METHOD))
        #userEntries.extend(self.sMethods_DispatchMethod)
        #userEntries.extend(self.sMethods_Method)

        for name in self.callableCallBackNames:
            if name in self.callBacks:
                #userEntries.append(self.callBacks[name])
                if name == "externalMethod":
                    userEntries.append((self.callBacks[name], EntryType.CB_EXTERNALMETHOD))
                else:
                    userEntries.append((self.callBacks[name], EntryType.CALLBACK))
        return userEntries


class EntryType(Enum):
    UNKNOWN=0
    DISPATCHMETHOD=1
    METHOD=2
    CALLBACK=3
    CB_EXTERNALMETHOD=4
    CB_GETTARGET=5
    CB_GETASYNCTARGET=6
    CB_GETTARGETTRAP=7
    


