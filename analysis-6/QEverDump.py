__author__ = 'QEver'

DUMP_FILE_PREFIX = r'd:/'
USER_DEX_FILES_OFFSET = 0x334
LOADED_CLASSES_OFFSET = 0xAC
JAR_NAME_OFFSET = 0x24
SIZE_OF_DEY_HEADER = 0x28
DESC_OFFSET_OF_CLASS_OBJECT = 0x18
METHOD_OFFSET_OF_CLASS_OBJECT = 0x60
SIZE_OF_STRUCT_METHOD = 0x38

import os
import idaapi
import binascii


def read_data(ea, size):
    return idaapi.dbg_read_memory(ea, size)


def read_dword(ea):
    val = int(binascii.hexlify(idaapi.dbg_read_memory(ea, 4)), 16)
    r = (val & 0xff) << 24 | (val & 0xff00) << 8 | (val & 0xff0000) >> 8 | (val & 0xff000000) >> 24
    return r


def read_bool(ea):
    val = int(binascii.hexlify(idaapi.dbg_read_memory(ea, 1)), 16)
    return val


def read_str(ea, max=256):
    c = ''
    while True:
        x = idaapi.dbg_read_memory(ea, 1)
        ea = ea + 1
        max = max - 1
        if x == '\0' or max < 0:
            break
        c += x
    return c


class DvmDex:
    def __init__(self, ea):
        self.ea = ea
        self.pDexFile = read_dword(ea)
        self.baseAddr = read_dword(self.pDexFile + 0x2c)

    def p(self):
        print 'pDexFile = %x' % self.pDexFile
        print 'baseAddr = %x' % self.baseAddr


class ClassObject:
    def __init__(self, ea):
        self.ea = ea
        self.desc_addr = read_dword(ea + DESC_OFFSET_OF_CLASS_OBJECT)

    def get_descriptor(self):
        return read_str(self.desc_addr)


class DexOrJar:
    def __init__(self, ea):
        self.ea = ea
        self.filename = read_dword(ea)
        self.isDex = read_bool(ea + 4)
        self.pRawDexFile = read_dword(ea + 8)
        self.pJarFile = read_dword(ea + 12)

    def get_filename(self):
        if self.isDex == 0:
            return read_str(read_dword(self.pJarFile + JAR_NAME_OFFSET))
        return read_str(self.filename)

    def get_dvmdex(self):
        if self.isDex == 0:
            return read_dword(self.pJarFile + JAR_NAME_OFFSET + 4)
        return read_dword(self.pRawDexFile + 4)

    def p(self):
        print 'filename = %s' % read_str(self.filename)
        print 'isDex = %d' % self.isDex
        print 'pRawDexFile = %x' % self.pRawDexFile
        print 'pJarFile = %x' % self.pJarFile


class HashTable:
    def __init__(self, ea):
        self.ea = ea
        self.tableSize = -1
        self.numEntries = -1
        self.pEntries = None
        self.do_init()

    def do_init(self):
        self.tableSize = read_dword(self.ea)
        self.numEntries = read_dword(self.ea + 4)
        self.pEntries = read_dword(self.ea + 12)

    def get_table_size(self):
        return self.tableSize

    def get_num_entries(self):
        return self.numEntries

    def get_pentries(self):
        return self.pEntries

    def p(self):
        print 'tableSize = %d' % self.tableSize
        print 'numEntries = %d' % self.numEntries
        print 'pEntries = %x' % self.pEntries


class Method:
    def __init__(self, ea):
        self.ea = ea

    def get_name(self):
        addr = self.ea + 0x10
        return read_str(read_dword(addr))

    def get_insns(self):
        addr = self.ea + 0x20
        return read_dword(addr)

    def get_address(self):
        return self.ea


def get_gdvm_address():
    return idaapi.get_debug_name_ea("gDvm")


def dump_all_dex(prefix=DUMP_FILE_PREFIX):
    gdvm = get_gdvm_address()
    print '[*] gDvm = 0x%x' % gdvm
    user_dex_files = read_dword(gdvm + USER_DEX_FILES_OFFSET)
    print '[*] gDvm.user_dex_files = 0x%x' % user_dex_files

    ht = HashTable(user_dex_files)

    max_size = ht.get_table_size()
    size = ht.get_num_entries()
    p = ht.get_pentries()
    print '[*] Found %s items in Dex Table' % size
    for i in range(max_size):
        x = read_dword(p)

        p += 8
        if x == 0:
            continue
        doj = DexOrJar(x)
        print '[*] Dex in Address 0x%x, isDex = %d' % (x, doj.isDex)
        addr = doj.get_dvmdex()
        name = doj.get_filename()
        print '[*] found file : %s , dvmdex = 0x%x' % (name, addr)

        dd = DvmDex(addr)
        addr = dd.baseAddr
        base = addr - SIZE_OF_DEY_HEADER
        size = read_dword(addr + 0x20) + SIZE_OF_DEY_HEADER
        flag = read_str(base, 3)
        if flag != 'dey':
            base = addr
            size = size = read_dword(addr + 0x20)

        print '[*] found odex file = 0x%x <%s>, size = 0x%x' % (base, read_str(base, 7).replace('\n', '.'), size)

        name = os.path.basename(name)
        path = os.path.join(prefix, name)

        print '[*] Write to %s' % path
        data = read_data(base, size)

        f = open(path, 'wb')
        f.write(data)
        f.close()
        print '[*] Finish Write'


def find_class(name):
    gDvm = get_gdvm_address()
    loaded_classes = read_dword(gDvm + LOADED_CLASSES_OFFSET)

    ht = HashTable(loaded_classes)
    max_size = ht.get_table_size()
    size = ht.get_num_entries()
    p = ht.get_pentries() + 4
    print 'Finding for %d items, may take a long time...' % max_size
    for i in range(max_size):
        x = read_dword(p)
        p = p + 8
        if x == 0:
            continue
        c = ClassObject(x)
        s = c.get_descriptor()
        if s == name:
            print '[*] Found Class <%s> : 0x%x' % (name, x)
            return x
        if s.find(name) != -1:
            print '[*] Found Class <%s> : 0x%x' % (s, x)


def list_method(class_addr):
    x = ClassObject(class_addr)
    print '[*] List All Method of %s' % x.get_descriptor()
    m = class_addr + METHOD_OFFSET_OF_CLASS_OBJECT
    directMethodCount = read_dword(m)
    directMethodTable = read_dword(m + 4)
    virtualMethodCount = read_dword(m + 8)
    virtualMethodTable = read_dword(m + 12)

    for i in range(directMethodCount):
        method = Method(directMethodTable)
        directMethodTable = directMethodTable + SIZE_OF_STRUCT_METHOD
        print method.get_name(), hex(method.get_address())

    for i in range(virtualMethodCount):
        method = Method(virtualMethodTable)
        virtualMethodTable = virtualMethodTable + SIZE_OF_STRUCT_METHOD
        print method.get_name()


def list_all_class():
    gDvm = get_gdvm_address()
    loaded_classes = read_dword(gDvm + LOADED_CLASSES_OFFSET)

    ht = HashTable(loaded_classes)
    max_size = ht.get_table_size()
    size = ht.get_num_entries()
    p = ht.get_pentries() + 4
    for i in range(max_size):
        x = read_dword(p)
        p = p + 8
        if x == 0:
            continue
        c = ClassObject(x)
        print c.get_descriptor()

if __name__ == '__main__':
    #list_all_class()
    #find_class('alibaba')
    #list_method(class_addr) 
    dump_all_dex('c:/test/')
