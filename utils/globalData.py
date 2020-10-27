# Copyright (C) 2020 Alibaba Group Holding Limited

classNameToVTableEAListMap = {}
classNameToParentClassNameMap = {}
classNameToParentMetaClassAddrMap = {}
classNameToVTableAddrMap = {}
classNameToVTableStructIdMap = {}
classNameToClassStructIdMap = {}
predefinedStructNameToIdMap = {}
classNameToVTableFuncEAListMap = {}
virtualFuncEASet = set()
predefinedClassNameSet = set()
classNameToWholeVTableStructIdMap = {}
classNameToChildClassNameSetMap = {}
classNameToVirtualCFuncInfoMap = {}
confirmedFuncTypes = {}
funcEAToCFuncMap = {}
allClassNameSet = set()

builtinTypeSet = set()
builtinTypeSet.add("int")
builtinTypeSet.add("unsigned int")
builtinTypeSet.add("long")
builtinTypeSet.add("unsigned long")
builtinTypeSet.add("long long")
builtinTypeSet.add("unsigned long long")
builtinTypeSet.add("float")
builtinTypeSet.add("double")
builtinTypeSet.add("char")
builtinTypeSet.add("unsigned char")
builtinTypeSet.add("bool")
builtinTypeSet.add("void")
builtinTypeSet.add("task")

allKextPrefixSet = set()
allKextPrefixInDeps = []

moduleNameToClassNamesMap = {}
classNameToModuleNameMap = {}
kernelClassNameSet = set(['IOCommandGate', 'IOFilterInterruptEventSource', 
    'IOPlatformDevice', 'IOSimpleReporter', 'IOServicePM', 'IOUserIterator', 'PMHaltWorker', 
    'OSCollectionIterator', 'IOPMPowerSource', 'IOWorkLoop', 'OSMetaClass', 'IOMultiMemoryDescriptor',
    'IOService', 'IOPlatformExpertDevice', 'OSObject', 'OSSerializer', 'IORTC', 'IOPMCompletionQueue',
    'IOMemoryDescriptor', 'IOInterruptController', 'OSSymbol', 'IOSharedInterruptController',
    'OSString', '_IOServiceNotifier', '_IOConfigThread', 'IONaturalMemoryCursor', 'IOPlatformExpert', 
    'IOInterruptEventSource', 'IOServiceUserNotification', 'IORegistryIterator', 'IOPowerConnection', 
    'IOServiceMessageUserNotification', 'IOSKRegion', 'IOMapper', 'IOPMPowerSourceList', 
    '_IOServiceInterestNotifier', 'IOPMRequest', 'IODMAController', 'IONVRAMController', 
    'IOReportLegend', 'IOUserClient', 'IONotifier', 'IOCommandPool', 'OSCollection', 'IOHistogramReporter',
    '_IOServiceJob', 'IOSKRegionMapper', 'IOEventSource', 'IOPMServiceInterestNotifier', 'IOKitDiagnostics',
    'IORegistryPlane', 'OSBoolean', 'IOPMPowerStateQueue', 'OSSet', 'IOPerfControlClient', 'IORegistryEntry',
    'IOCPUInterruptController', 'IOSKArena', 'IOLittleMemoryCursor', 'IOMachPort', 'IODMACommand', 'IOCPU',
    'IOPMinformeeList', 'IOSKMemoryArray', 'IODataQueue', 'IOSubMemoryDescriptor', 'IOPMWorkQueue', 
    'IOPMinformee', 'PMAssertionsTracker', 'OSIterator', 'IOMemoryMap', 'IORootParent', 'OSNumber', 
    'IOKitDiagnosticsClient', 'IOPolledInterface', 'IOReporter', 'IOWatchDogTimer', '_IOOpenServiceIterator',
    'IOConditionLock', '_IOServiceNullNotifier', 'OSSerialize', 'IOBigMemoryCursor', 'OSDictionary', 'IOMemoryCursor',
    'OSData', 'IODTNVRAM', 'IOSKMapper', 'IOCatalogue', 'IOSharedDataQueue', 'IODTPlatformExpert', 'IOStateReporter',
    'IOPolledFilePollers', 'OSArray', 'IOPMrootDomain', 'IODMAEventSource', 'RootDomainUserClient', 'IOCommand', 
    'IOSKMemoryBuffer', 'IOResources', 'IOTimerEventSource', 'PMSettingHandle', 'OSKext', 'IORangeAllocator',
    'IOGeneralMemoryDescriptor', 'IOPanicPlatform', 'IOUserNotification', 'PMTraceWorker', 'OSOrderedSet',
    'PMSettingObject', 'IOInterleavedMemoryDescriptor', 'IOBufferMemoryDescriptor', 'IOPMRequestQueue'])

callGraph_FuncEA2Calls = {}
varTinfos_FuncEA2Args = {}
varTinfos_FuncEA2Ret = {}

className2SMethods_MethodDispatch = {}
className2SMethods_Method = {}

funcEA2BPOffsetAndFuncHeadEndMap = {}

OBJ_TYPES_REC = {}
