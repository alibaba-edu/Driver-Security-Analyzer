# Copyright (C) 2020 Alibaba Group Holding Limited

import os
import sys
from clang.cindex import Config
from clang.cindex import Index
from clang.cindex import CursorKind
import traceback
try:
    if None is Config.library_path:
        Config.set_library_path("/usr/local/opt/llvm/lib/")
except Exception as e:
    traceback.print_exc()

from UtilClasses import *
import subprocess
import json

XNU_6153_EXPORT_HDRS_DIRPATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../xnusrc/build-xnu-6153.11.26/xnu-6153.11.26/")

def getDefinedClasses(node, classes):
    try:
        if node.kind == CursorKind.CLASS_DECL and node.is_definition():
            classes.append(node)
        for child in node.get_children():
            getDefinedClasses(child, classes)
    except ValueError as e:
        None


def parseHeaderFileAtPath(headerFilePath, includePaths):
    index = Index.create()
    parseHeaderArgs = []
    for path in includePaths:
        parseHeaderArgs.append('-I{}'.format(path))
    #parseHeaderArgs.extend(["-x", "c++", "-DKERNEL", "-DXNU_KERNEL_PRIVATE", "-DMACH_BSD", "-DCONFIG_MACF", "-DMACH_KERNEL_PRIVATE", "-D__LP64__", "-arch", "x86_64"])
    parseHeaderArgs.extend(["-x", "c++", "-DKERNEL", "-DMACH_BSD", "-DCONFIG_MACF", "-D__LP64__", "-arch", "x86_64"])
    #print parseHeaderArgs
    tu = index.parse(headerFilePath, args=parseHeaderArgs)
    diagnostics = tu.diagnostics
    diagnostics = filter(lambda x:x.severity > 2, diagnostics)
    parseResultOfHeaderFile = {}
    classes = []
    getDefinedClasses(tu.cursor, classes)
    if len(classes) > 0 and len(diagnostics) > 0:
        print "[!] parseHeaderFileAtPath {}:\n {}".format(headerFilePath, \
                "\n".join(["{}:{}".format(x.severity, str(x)) for x in diagnostics]))
        return None
    parseResultOfAllClasses = {}
    for classNode in classes:
        className = classNode.spelling
        parseResultOfClass = parseClass(className, classNode)
        parseResultOfAllClasses[className] = parseResultOfClass
    parseResultOfHeaderFile["classes"] = parseResultOfAllClasses
    # Should also handle structs, etc...
    return parseResultOfHeaderFile 

def parseArgNodes(argNodes):
    argList = []
    for argNode in argNodes:
        argType = argNode.type.get_canonical().spelling
        argName = argNode.spelling
        if argNode.type.get_declaration().kind == CursorKind.TYPEDEF_DECL:
            argType = argNode.type.get_declaration().underlying_typedef_type.spelling
        argInfo = ArgInfo(argType, argName)
        argList.append(argInfo)
    return argList

def parseClass(className, classNode):
    parseResultOfClassFuncs = {}
    for child in classNode.get_children():
        if child.kind == CursorKind.CXX_METHOD:
            funcNode = child
            isStatic = funcNode.is_static_method()
            isVirtual = funcNode.is_virtual_method()
            isConst = funcNode.is_const_method()
            mangledName = funcNode.mangled_name
            funcType = funcNode.type.spelling
            returnType = funcType[:funcType.find("(")]
            funcName = funcNode.spelling
            argList = parseArgNodes(funcNode.get_arguments())
            funcInfo = FuncInfo(mangledName, className, funcName, argList, returnType, isStatic, isVirtual, isConst)
            parseResultOfClassFuncs[mangledName] = funcInfo
        elif child.kind == CursorKind.TYPEDEF_DECL:

            None
    return parseResultOfClassFuncs

def testNode(node):
    #print node.kind, node.is_definition()
    if node.is_static_method():
        print node.type.spelling
        args = node.get_arguments()
        #for arg in args:
        #    print arg.type.spelling
    for child in node.get_children():
        testNode(child)


def parseKernelHeaderFiles(xnu_src_dirpath):
    print "[+] Parse kernel header files at", xnu_src_dirpath
    parseResults = {}
    parseResults["classes"] = {}
    parseResults["structs"] = {}
    #parseResults["cxxfuncs"] = {}
    includepaths = [
        xnu_src_dirpath,
        '{}/libkern/'.format(xnu_src_dirpath),
        '{}/osfmk/'.format(xnu_src_dirpath),
        '{}/iokit/'.format(xnu_src_dirpath),
        '{}/bsd/'.format(xnu_src_dirpath),
        "{}/EXTERNAL_HEADERS/".format(xnu_src_dirpath),
        "{}/BUILD.hdrs/obj/EXPORT_HDRS/".format(xnu_src_dirpath),
        "{}/BUILD.hdrs/obj/EXPORT_HDRS/libkern".format(xnu_src_dirpath),
        "{}/BUILD.hdrs/obj/EXPORT_HDRS/osfmk".format(xnu_src_dirpath),
        "{}/BUILD.hdrs/obj/EXPORT_HDRS/iokit".format(xnu_src_dirpath),
        "{}/BUILD.hdrs/obj/EXPORT_HDRS/bsd".format(xnu_src_dirpath),
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/",
            ]
    search_cxx_headers_dirpath = [
        '{}/libkern/'.format(xnu_src_dirpath),
        '{}/osfmk/'.format(xnu_src_dirpath),
        '{}/iokit/'.format(xnu_src_dirpath),
        '{}/bsd/'.format(xnu_src_dirpath),
        ]
    for dirpath in search_cxx_headers_dirpath:
        for root, dirs, files in os.walk(dirpath):
            for fileName in files:
                if fileName.endswith(".h") or fileName.endswith(".hpp"):
                    filePath = os.path.join(root, fileName)
                    parseResultOfHeaderFile = parseHeaderFileAtPath(filePath, includepaths)
                    if None is parseResultOfHeaderFile:
                        continue
                    parseResults["classes"].update(parseResultOfHeaderFile["classes"])
                    #parseResults["cxxfuncs"].update(parseResultOfHeaderFile["cxxfuncs"])
    return parseResults

KernelHeaderFilesParseResultPath = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../data/KernelHeaderFilesParseResults.json") 

def byteify_noignoredict(data):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ byteify_noignoredict(item) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict):
        return {
            byteify_noignoredict(key): byteify_noignoredict(value)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data

def func_info_decode_hook(data):
    if isinstance(data, dict):
        data = byteify_noignoredict(data)
        if "FuncInfo" in data:
            dct = data
            funcInfo = dct["FuncInfo"]
            argDictList = funcInfo["argList"]
            argList = []
            for item in argDictList:
                argInfo = ArgInfo(item["argType"], item["argName"])
                argList.append(argInfo)
            return FuncInfo(funcInfo["mangledName"], funcInfo["className"], funcInfo["funcName"], argList, funcInfo["returnType"], funcInfo["isStatic"], funcInfo["isVirtual"], funcInfo["isConst"])
    return data

def func_info_encode_hook(obj):
    #print type(obj)
    if isinstance(obj, FuncInfo) or isinstance(obj, FuncInfo) or type(obj) == "instance":
        return {"FuncInfo": dict(obj)}


def loadKernelHeaderFilesParseResult(path=None):
    if None is path:
        path = KernelHeaderFilesParseResultPath
    if not os.path.isfile(path):
        return None
    priorResult = None
    with open(path, "r") as fp:
        priorResult = json.load(fp, object_hook=func_info_decode_hook)
    #print priorResult
    return priorResult

def storeKernelHeaderFilesParseResult(result, path=None):
    if None is path:
        path = KernelHeaderFilesParseResultPath
    with open(path, "w") as fp:
        json.dump(result, fp, default=func_info_encode_hook)

def loadKernelHeaders():
    if os.path.exists(KernelHeaderFilesParseResultPath):
        return loadKernelHeaderFilesParseResult()
    else:
        parseResults = parseKernelHeaderFiles()
        storeKernelHeaderFilesParseResult(parseResults)
        return parseResults

