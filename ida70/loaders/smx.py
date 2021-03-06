import ctypes
import zlib

import idaapi
import idc

CODEFLAG_DEBUG = 0x1

def read_struct(bytebuf, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    fit = min(len(bytebuf), slen)
    ctypes.memmove(ctypes.addressof(s), bytebuf, fit)
    return s

def read_string(bytebuf, start, max_end=None):
    try:
        end = bytebuf.index('\x00', start, max_end)
    except ValueError:
        end = max_end
    return bytebuf[start:end]

class sp_file_hdr_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic",       ctypes.c_uint32),
        ("version",     ctypes.c_uint16),
        ("compression", ctypes.c_uint8),
        ("disksize",    ctypes.c_uint32),
        ("imagesize",   ctypes.c_uint32),
        ("sections",    ctypes.c_uint8),
        ("stringtab",   ctypes.c_uint32),
        ("dataoffs",    ctypes.c_uint32),
    ]

class sp_file_section_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("nameoffs",    ctypes.c_uint32),
        ("dataoffs",    ctypes.c_uint32),
        ("size",        ctypes.c_uint32),
    ]

class sp_file_code_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("codesize",    ctypes.c_uint32),
        ("cellsize",    ctypes.c_uint8),
        ("codeversion", ctypes.c_uint8),
        ("flags",       ctypes.c_uint16),
        ("main",        ctypes.c_uint32),
        ("code",        ctypes.c_uint32),
    ]
    
class sp_file_data_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("datasize",    ctypes.c_uint32),
        ("memsize",     ctypes.c_uint32),
        ("data",        ctypes.c_uint32),
    ]
    
class sp_file_publics_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("address",     ctypes.c_uint32),
        ("name",        ctypes.c_uint32),
    ]

class sp_file_pubvars_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("address",     ctypes.c_uint32),
        ("name",        ctypes.c_uint32),
    ]

class sp_file_natives_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("name",        ctypes.c_uint32),
    ]

class SmxConsts(object):
    FILE_MAGIC = 0x53504646
    
    SP1_VERSION_1_0 = 0x0101
    SP1_VERSION_1_1 = 0x0102
    SP1_VERSION_1_7 = 0x0107
    SP1_VERSION_MIN = SP1_VERSION_1_0
    SP1_VERSION_MAX = SP1_VERSION_1_7
    SP2_VERSION_MIN = 0x0200
    SP2_VERSION_MAX = 0x0200
    
    FILE_COMPRESSION_NONE = 0
    FILE_COMPRESSION_GZ = 1
    
    CODE_VERSION_MINIMUM = 9
    CODE_VERSION_SM_LEGACY = 10
    CODE_VERSION_FEATURE_MASK = 13
    CODE_VERSION_CURRENT = CODE_VERSION_FEATURE_MASK
    CODE_VERSION_ALWAYS_REJECT = 0x7f

class SmxSection(object):
    def __init__(self):
        self.dataoffs = None
        self.size = None
        self.name = ""

class SmxBlob(object):
    def __init(self):
        self.hdr = SmxSection()
        self.section = None
        self.blob = None
        self.size = None

class SmxPublic(object):
    def __init__(self):
        self.addr = None
        self.name = ""

class SmxImage(object):
    def __init__(self, buf):
        self.buf = buf

        self.hdr = sp_file_hdr_t()
        self.err = ""
        self.sections = []
        
        self.names = SmxSection()
        self.code = SmxBlob()
        self.data = SmxBlob()
        self.publics = []
        self.pubvars = []
        self.natives = []

    def error(self, err):
        self.err = err
        return False

    def find_section(self, name):
        for section in self.sections:
            if section.name == name:
                return section
            
        return None
    
    def validate_section(self, section):
        if section.dataoffs >= len(self.buf):
            return False
        
        if section.size > (len(self.buf) - section.dataoffs):
            return False
            
        return True
    
    def validate_name(self, offset):
        return offset < self.names.size
    
    def validate(self):
        if len(self.buf) < ctypes.sizeof(sp_file_hdr_t):
            return self.error("bad header")
        
        self.hdr = read_struct(self.buf, sp_file_hdr_t)
        
        if self.hdr.magic != SmxConsts.FILE_MAGIC:
            return self.error("bad header")
            
        if  self.hdr.version != SmxConsts.SP1_VERSION_1_0 \
        and self.hdr.version != SmxConsts.SP1_VERSION_1_1 \
        and self.hdr.version != SmxConsts.SP1_VERSION_1_7:
            return self.error("unsupported version")
            
        if self.hdr.compression == SmxConsts.FILE_COMPRESSION_GZ:
            if self.hdr.disksize > len(self.buf):
                return self.error("illegal disk size")
                
            if self.hdr.disksize < ctypes.sizeof(sp_file_hdr_t):
                return self.error("illegal disk size")
        
            if self.hdr.imagesize < self.hdr.disksize:
                return self.error("illegal image size")
        
            if self.hdr.dataoffs >= self.hdr.disksize:
                return self.error("illegal compressed region")
            
            if self.hdr.dataoffs < ctypes.sizeof(sp_file_hdr_t):
                return self.error("illegal compressed region")
                
            compressed = self.buf[self.hdr.dataoffs:self.hdr.disksize]
            
            self.buf = self.buf[:self.hdr.dataoffs]
            
            try:
                self.buf += zlib.decompress(compressed)
            except zlib.error:
                return self.error("could not decode compressed region")

        elif self.hdr.compression != SmxConsts.FILE_COMPRESSION_NONE:
            return self.error("unknown compression type")
    
        if self.hdr.stringtab >= len(self.buf):
            return self.error("invalid string table")
            
        if (ctypes.sizeof(sp_file_hdr_t) + self.hdr.sections * ctypes.sizeof(sp_file_section_t)) > len(self.buf):
            return self.error("invalid section table")
        
        last_hdr_str = 0
        
        for i in range(0, self.hdr.sections):
            tmp_offset = ctypes.sizeof(sp_file_hdr_t) + i * ctypes.sizeof(sp_file_section_t)
            tmp_section = read_struct(self.buf[tmp_offset:], sp_file_section_t)
            
            if tmp_section.nameoffs >= (len(self.buf) - self.hdr.stringtab):
                return self.error("invalid section name")
                
            if tmp_section.nameoffs > last_hdr_str:
                last_hdr_str = tmp_section.nameoffs
 
            section = SmxSection()
            section.dataoffs = tmp_section.dataoffs
            section.size = tmp_section.size
            section.name = read_string(self.buf, self.hdr.stringtab + tmp_section.nameoffs)
 
            self.sections.append(section)
        
        if self.buf.find('\x00', self.hdr.stringtab + last_hdr_str) == -1:
            return self.error("malformed section names header")

        self.names = self.find_section(".names")

        if self.names is None:
            return self.error("could not find .names section")
            
        if self.validate_section(self.names) is False:
            return self.error("invalid names section")

        if  self.names.size != 0 \
        and self.buf[self.names.dataoffs + self.names.size - 1] != '\x00':
            return self.error("malformed names section")
        
        if self.validate_code() is False:
            return False
            
        if self.validate_data() is False:
            return False
            
        if self.validate_publics() is False:
            return False
            
        if self.validate_pubvars() is False:
            return False
            
        if self.validate_natives() is False:
            return False

        return True
  
    def validate_code(self):
        section = self.find_section(".code")
        
        if section is None:
            return self.error("could not find code")
            
        if self.validate_section(section) is False:
            return self.error("invalid code section")
        
        if section.size < ctypes.sizeof(sp_file_code_t):
            return self.error("invalid code section")
        
        code = read_struct(self.buf[section.dataoffs:], sp_file_code_t)
        
        if code.codeversion < SmxConsts.CODE_VERSION_MINIMUM:
            return self.error("code version is too old, no longer supported")
            
        if code.codeversion > SmxConsts.CODE_VERSION_CURRENT:
            return self.error("code version is too new, not supported")
            
        if code.cellsize != 4:
            return self.error("unsupported cellsize")
            
        if code.flags & ~CODEFLAG_DEBUG:
            return self.error("unsupported code settings")
        
        if code.code >= section.size:
            return self.error("invalid code blob")
        
        if code.codesize > (section.size - code.code):
            return self.error("invalid code blob")
        
        self.code = SmxBlob()
        self.code.hdr = section
        self.code.section = code
        self.code.blob = section.dataoffs + code.code
        self.code.size = code.codesize
        
        return True
        
    def validate_data(self):
        section = self.find_section(".data")
        
        if section is None:
            return self.error("could not find data")
            
        if self.validate_section(section) is False:
            return self.error("invalid data section")
    
        if section.size < ctypes.sizeof(sp_file_data_t):
            return self.error("invalid data section")
    
        data = read_struct(self.buf[section.dataoffs:], sp_file_data_t)
        
        if data.data >= section.size:
            return self.error("invalid data blob")
        
        if data.datasize > (section.size - data.data):
            return self.error("invalid data blob")
            
        self.data = SmxBlob()
        self.data.hdr = section
        self.data.section = data
        self.data.blob = section.dataoffs + data.data
        self.data.size = data.datasize
    
        return True

    def validate_publics(self):
        section = self.find_section(".publics")
        
        if section is None:
            return True
            
        if self.validate_section(section) is False:
            return self.error("invalid .publics section")
            
        if (section.size % ctypes.sizeof(sp_file_publics_t)) != 0:
            return self.error("invalid .publics section")
        
        length = section.size / ctypes.sizeof(sp_file_publics_t)
        
        for i in range(0, length):
            tmp_offset = section.dataoffs + i * ctypes.sizeof(sp_file_publics_t)
            tmp_public = read_struct(self.buf[tmp_offset:], sp_file_publics_t)
            
            if self.validate_name(tmp_public.name) is False:
                return self.error("invalid public name")
            
            name_start = self.names.dataoffs + tmp_public.name
            name_end = self.names.dataoffs + self.names.size
            
            public = SmxPublic()
            public.addr = tmp_public.address
            public.name = read_string(self.buf, name_start, name_end)
            
            self.publics.append(public)
    
        return True
        
    def validate_pubvars(self):
        section = self.find_section(".pubvars")
        
        if section is None:
            return True
            
        if self.validate_section(section) is False:
            return self.error("invalid .pubvars section")
            
        if (section.size % ctypes.sizeof(sp_file_pubvars_t)) != 0:
            return self.error("invalid .pubvars section")
        
        length = section.size / ctypes.sizeof(sp_file_pubvars_t)
        
        for i in range(0, length):
            tmp_offset = section.dataoffs + i * ctypes.sizeof(sp_file_pubvars_t)
            tmp_pubvar = read_struct(self.buf[tmp_offset:], sp_file_pubvars_t)
            
            if self.validate_name(tmp_pubvar.name) is False:
                return self.error("invalid pubvar name")
            
            name_start = self.names.dataoffs + tmp_pubvar.name
            name_end = self.names.dataoffs + self.names.size
            
            pubvar = SmxPublic()
            pubvar.addr = tmp_pubvar.address
            pubvar.name = read_string(self.buf, name_start, name_end)
            
            self.pubvars.append(pubvar)
    
        return True
        
    def validate_natives(self):
        section = self.find_section(".natives")
        
        if section is None:
            return True
            
        if self.validate_section(section) is False:
            return self.error("invalid .natives section")
            
        if (section.size % ctypes.sizeof(sp_file_natives_t)) != 0:
            return self.error("invalid .natives section")
        
        length = section.size / ctypes.sizeof(sp_file_natives_t)
        
        for i in range(0, length):
            tmp_offset = section.dataoffs + i * ctypes.sizeof(sp_file_natives_t)
            tmp_native = read_struct(self.buf[tmp_offset:], sp_file_natives_t)
            
            if self.validate_name(tmp_native.name) is False:
                return self.error("invalid native name")
            
            name_start = self.names.dataoffs + tmp_native.name
            name_end = self.names.dataoffs + self.names.size
            
            self.natives.append(read_string(self.buf, name_start, name_end))
    
        return True

def align_up(val, elsize):
    mask = elsize - 1
    val += mask
    val &= ~mask
    return val

def add_segment(sel, start, end, name, sclass):
    idaapi.set_selector(sel, start >> 4)

    s = idaapi.segment_t()
    s.sel         = sel
    s.start_ea    = start
    s.end_ea      = end
    s.align       = idaapi.saRelPara
    s.comb        = idaapi.scPub
    s.bitness     = 1
    
    idaapi.add_segm_ex(s, name, sclass, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)

def create_section(li, image, section, sel, start, end, name, sclass):
    add_segment(sel, start, end, name, sclass)
    
    compressed = image.hdr.compression != SmxConsts.FILE_COMPRESSION_NONE
    
    if compressed is True:
        blob_start  = section.blob
        blob_end    = blob_start + section.size
        
        idaapi.mem2base(image.buf[blob_start:blob_end], start)
    else:
        li.file2base(section.blob, start, end, 1)

def process_imports(natives, sel, start, end, name, sclass):
    add_segment(sel, start, end, name, sclass)

    ea = start
    for native in natives:
        idc.create_dword(ea)
        idaapi.force_name(ea, native, idaapi.SN_IDBENC)
        ea = ea + ctypes.sizeof(sp_file_natives_t)
        
def process_exports(image, code_ea, data_ea):
    if code_ea != idaapi.BADADDR:
        for public in image.publics:
            entry_ea = code_ea + public.addr
            if entry_ea >= (code_ea + image.code.size):
                continue
            idaapi.add_entry(entry_ea, entry_ea, public.name, 1, idaapi.AEF_IDBENC)

    if data_ea != idaapi.BADADDR:
        for pubvar in image.pubvars:
            entry_ea = data_ea + pubvar.addr
            if entry_ea >= (data_ea + image.data.size):
                continue
            idaapi.add_entry(entry_ea, entry_ea, pubvar.name, 0, idaapi.AEF_IDBENC)

def add_comments(image):
    compressed = image.hdr.compression != SmxConsts.FILE_COMPRESSION_NONE

    idaapi.add_pgm_cmt("Version     : %04X" % image.hdr.version)
    idaapi.add_pgm_cmt("Image Size  : %08X" % image.hdr.imagesize)
    idaapi.add_pgm_cmt("Compression : %02X (%s)" % (image.hdr.compression, ("GZ" if compressed else "None")))
    
    if compressed is True:
        idaapi.add_pgm_cmt("Compressed  : off=%08X, size=%08X" % (image.hdr.dataoffs, (image.hdr.disksize - image.hdr.dataoffs)))

    idaapi.add_pgm_cmt("Code        : off=%08X, size=%08X" % (image.code.blob, image.code.size))
    idaapi.add_pgm_cmt("Data        : off=%08X, size=%08X" % (image.data.blob, image.data.size))
    idaapi.add_pgm_cmt("Heap Size   : %08X" % image.data.section.memsize)
    idaapi.add_pgm_cmt("Cell Size   : %d" % image.code.section.cellsize)
    idaapi.add_pgm_cmt("Code Version: %d" % image.code.section.codeversion)
    idaapi.add_pgm_cmt("Flags       : %04X %s" % (image.code.section.flags, ("(Debug)" if (image.code.section.flags & CODEFLAG_DEBUG) else " ")))
    
def accept_file(li, filename):
    li.seek(0)
    
    if li.size() < ctypes.sizeof(sp_file_hdr_t):
        return 0
    
    buf = li.read(ctypes.sizeof(sp_file_hdr_t))
    hdr = read_struct(buf, sp_file_hdr_t)
    
    if hdr.magic != SmxConsts.FILE_MAGIC:
        return 0
    
    if  hdr.version != SmxConsts.SP1_VERSION_1_0 \
    and hdr.version != SmxConsts.SP1_VERSION_1_1 \
    and hdr.version != SmxConsts.SP1_VERSION_1_7:
        return 0

    return "SMX v1"  

def load_file(li, neflags, format):
    idaapi.set_processor_type("srcpawn", idaapi.SETPROC_LOADER)
    
    li.seek(0)
    buf = li.read(li.size())
    image = SmxImage(buf)
    
    if image.validate() is False:
        idaapi.error(image.err)
    
    idc.set_inf_attr(idc.INF_MAX_EA, 0x10000)
    
    code_ea = idaapi.BADADDR
    data_ea = idaapi.BADADDR
    cs_sel  = idaapi.BADSEL
    ds_sel  = idaapi.BADSEL
    sel     = 1
    
    # load code
    if image.code.size > 0:
        start    = align_up(idc.get_inf_attr(idc.INF_MAX_EA), 16)
        end      = start + image.code.size
        code_ea  = start
        cs_sel   = sel
        create_section(li, image, image.code, sel, start, end, ".code", "CODE")
        sel += 1
    
    # load data
    if image.data.size > 0:
        start    = align_up(idc.get_inf_attr(idc.INF_MAX_EA), 16)
        end      = start + image.data.size
        data_ea  = start
        ds_sel   = sel
        create_section(li, image, image.data, sel, start, end, ".data", "DATA")
        sel += 1
    
    # load natives
    if len(image.natives) > 0:
        start   = align_up(idc.get_inf_attr(idc.INF_MAX_EA), 16)
        end     = start + len(image.natives) * ctypes.sizeof(sp_file_natives_t)
        process_imports(image.natives, sel, start, end, ".natives", "XTRN")
        sel += 1
    
    # add entry points
    process_exports(image, code_ea, data_ea)
    
    idc.set_inf_attr(idc.INF_AF, idc.get_inf_attr(idc.INF_AF) & ~idc.AF_IMMOFF)

    idc.set_inf_attr(idc.INF_START_CS, cs_sel)
    idaapi.set_default_dataseg(ds_sel)
    
    add_comments(image)

    return 1
