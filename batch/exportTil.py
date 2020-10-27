# Copyright (C) 2020 Alibaba Group Holding Limited

import idaapi
import idc
import shutil
import os

idb_fp = idc.get_idb_path()
modulename = os.path.basename(idb_fp)[:-4]
idb_dirpath = os.path.dirname(idb_fp)
til_dirpath = os.path.join(idb_dirpath, "tils")
if not os.path.isdir(til_dirpath):
    os.makedirs(til_dirpath)
self_til = idaapi.get_idati()
ida_typeinf.compact_til(self_til)
ida_typeinf.store_til(self_til, None, os.path.join(til_dirpath, modulename + ".til"))
#til_fp = modulename + ".til"
#shutil.copy(til_fp, til_fp[:-4]+".exported.til")
idc.Exit(0)
