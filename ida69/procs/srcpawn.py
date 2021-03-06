import sys
import idaapi
from idaapi import *

o_sysreq = o_idpspec0
o_local  = o_idpspec1

OPTYPE_CODE     = 0
OPTYPE_DATA     = 1
OPTYPE_STACK    = 2
OPTYPE_IMM      = 3
OPTYPE_SYSREQ   = 4

def fix_sign_32(l):
    l &= 0xFFFFFFFF
    if l & 0x80000000:
        l -= 0x100000000
    return l

def is_fixed_spd(ea):
    return (get_aflags(ea) & AFL_FIXEDSPD) != 0

class srcpawn_processor_t(idaapi.processor_t):
    id          = 0x8666
    
    flag        = PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    
    cnbits      = 8
    dnbits      = 8
    
    psnames     = ['srcpawn']
    plnames     = ['SourcePawn']
    
    retcodes    = ['\x30\x00\x00\x00', '\xA6\x00\x00\x00'] 
    
    segreg_size = 0
    tbyte_size  = 0
    
    assembler   = {
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        'uflag' : 0,
        'name': "SourcePawn Assembler",
        'origin': "org",
        'end': "end",
        'cmnt': ";",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': "db",
        'a_byte': "db",
        'a_word': "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        'a_oword': "xmmword",
        'a_float': "dd",
        'a_double': "dq",
        'a_tbyte': "dt",
        'a_dups': "#d dup(#v)",
        'a_bss': "%s dup ?",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': "public",
        'a_weak': "weak",
        'a_extrn': "extrn",
        'a_comdef': "",
        'a_align': "align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
    }

    def create_func_frame(self, func_ea):
        pfn = get_func(func_ea)
        if pfn is not None:
            pfn.flags |= FUNC_FRAME
            return add_frame(pfn, 0, 8, 0)
        
        return False

    def is_sp_based(self, op):
        return OP_FP_BASED

    def notify_get_autocmt(self):
        if 'cmt' in self.instruc[self.cmd.itype]:
            return self.instruc[self.cmd.itype]['cmt']
    
    def get_native_ea(self, index):
        segment = get_segm_by_name(".natives")
        if segment is None:
            return BADADDR
        ea = segment.startEA + index * 4
        if ea >= segment.endEA:
            return BADADDR
        return ea
        
    def add_stkpnt(self, pfn, v):
        if pfn:
            end = self.cmd.ea + self.cmd.size
            if not is_fixed_spd(end):
                add_auto_stkpnt2(pfn, end, fix_sign_32(v))    
        
    def trace_sp(self):
        pfn = get_func(self.cmd.ea)
        if pfn is None:
            return

        delta = 0
        if self.cmd.itype in [
            self.itype_PUSH_PRI,
            self.itype_PUSH_ALT, 
            self.itype_PUSH_C, 
            self.itype_PUSH, 
            self.itype_PUSH_S, 
            self.itype_PUSH_ADR
        ]:
            delta = -4
        
        elif self.cmd.itype in [
            self.itype_POP_PRI, 
            self.itype_POP_ALT
        ]:
            delta = 4
        
        elif self.cmd.itype == self.itype_STACK:
            delta = self.cmd.Op1.value   
        
        elif self.cmd.itype == self.itype_SYSREQ_N:
            delta = self.cmd.Op2.value * 4
        
        elif self.cmd.itype in [ 
            self.itype_PUSH2_C, self.itype_PUSH2, self.itype_PUSH2_S, self.itype_PUSH2_ADR, 
            self.itype_PUSH3_C, self.itype_PUSH3, self.itype_PUSH3_S, self.itype_PUSH3_ADR, 
            self.itype_PUSH4_C, self.itype_PUSH4, self.itype_PUSH4_S, self.itype_PUSH4_ADR, 
            self.itype_PUSH5_C, self.itype_PUSH5, self.itype_PUSH5_S, self.itype_PUSH5_ADR
        ]:
            delta = ((self.cmd.itype - self.itype_CASETBL) / 4) * -4
   
        elif self.cmd.itype in [
            self.itype_GENARRAY, 
            self.itype_GENARRAY_Z
        ]:
            delta = (self.cmd.Op1.value - 1) * 4
   
        elif self.cmd.itype == self.itype_CALL:
            saved_cmd = self.cmd.copy()
            
            uFlag = self.get_uFlag()
            if  isFlow(uFlag) \
            and decode_prev_insn(self.cmd.ea) != BADADDR:

                if self.cmd.itype == self.itype_PUSH_C:
                    delta = (self.cmd.Op1.value * 4) + 4
                    
                elif self.cmd.itype in [
                    self.itype_PUSH2_C, 
                    self.itype_PUSH3_C, 
                    self.itype_PUSH4_C, 
                    self.itype_PUSH5_C
                ]:
                    op_index = (self.cmd.itype - self.itype_NOP) / 4
                    delta = (self.cmd[op_index].value * 4) + 4
                    
            self.cmd.assign(saved_cmd)

        if delta != 0:
            self.add_stkpnt(pfn, delta)

    def handle_operand(self, op, isload):
        optype      = op.type
        uFlag       = self.get_uFlag()
        dref_type   = dr_R if isload else dr_W
        cref_type   = fl_CN if InstrIsSet(self.cmd.itype, CF_CALL) else fl_JN

        if optype == o_imm:
            doImmd(self.cmd.ea)
            if not isDefArg(uFlag, op.n):
                op_num(self.cmd.ea, op.n)
            if op_adds_xrefs(uFlag, op.n):
                ua_add_off_drefs2(op, dr_O, OOF_SIGNED|OOFW_IMM)
                
        elif optype == o_mem:
            ea = toEA(dataSeg(), op.addr)
            ua_dodata2(op.offb, ea, op.dtyp)
            ua_add_dref(op.offb, ea, dref_type)
        
        elif optype == o_near:
            ea = toEA(self.cmd.cs, op.addr)
            ua_add_cref(op.offb, ea, cref_type)
        
        elif optype == o_sysreq:
            ea = self.get_native_ea(op.value)
            if ea != BADADDR:
                ua_add_dref(op.offb, ea, dr_R)
        
        elif optype == o_local:
            if may_create_stkvars():
                pfn = get_func(self.cmd.ea)
                if  pfn is not None \
                and pfn.flags & FUNC_FRAME \
                and ua_stkvar2(op, fix_sign_32(op.addr), STKVAR_VALID_SIZE):
                    op_stkvar(self.cmd.ea, op.n)
    
    def emu(self):
        feature = self.cmd.get_canon_feature()
        
        flow = (feature & CF_STOP) == 0
        
        if feature & CF_USE1: self.handle_operand(self.cmd.Op1, True)
        if feature & CF_USE2: self.handle_operand(self.cmd.Op2, True)
        if feature & CF_USE3: self.handle_operand(self.cmd.Op3, True)
        if feature & CF_USE4: self.handle_operand(self.cmd.Op4, True)
        if feature & CF_USE5: self.handle_operand(self.cmd.Op5, True)

        if feature & CF_CHG1: self.handle_operand(self.cmd.Op1, False)
        if feature & CF_CHG2: self.handle_operand(self.cmd.Op2, False)
        if feature & CF_CHG3: self.handle_operand(self.cmd.Op3, False)
        if feature & CF_CHG4: self.handle_operand(self.cmd.Op4, False)
        if feature & CF_CHG5: self.handle_operand(self.cmd.Op5, False)
        
        if self.cmd.itype == self.itype_CASETBL:
            ncases = self.cmd.Op1.value
            ea = self.cmd.ea + 12
            for i in range(0, ncases):
                addr = toEA(self.cmd.cs, get_long(ea + 4))
                ua_add_cref(0, addr, fl_JN);
                ea = ea + 8
                
        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        if may_trace_sp():
            if flow:
                self.trace_sp()
            else:
                recalc_spd(self.cmd.ea)
        
        return 1

    def out_bad_address(self, addr):
        out_tagon(COLOR_ERROR)
        OutLong(addr, 16)
        out_tagoff(COLOR_ERROR)
        QueueSet(Q_noName, self.cmd.ea)
    
    def outop(self, op):
        optype = op.type

        if optype == o_imm:
            OutValue(op, OOF_SIGNED|OOFW_IMM)
            
        elif optype == o_mem:
            ea = toEA(dataSeg(), op.addr)
            if not out_name_expr(op, ea, BADADDR):
                self.out_bad_address(op.addr)
        
        elif optype == o_near:
            ea = toEA(self.cmd.cs, op.addr)
            if not out_name_expr(op, ea, BADADDR):
                self.out_bad_address(op.addr)
        
        elif optype == o_sysreq:
            ea = self.get_native_ea(op.value)
            if ea == BADADDR \
            or not out_name_expr(op, ea, BADADDR):
                self.out_bad_address(op.value)
        
        elif optype == o_local:
            OutValue(op, OOF_SIGNED|OOF_ADDR)
    
        return True

    def out_casetable(self):
        op = op_t()
        op.n = 0
        op.type = o_imm
        op.flags = OF_SHOW
        op.dtyp = dt_dword

        ncases = self.cmd.Op1.value
        ea = self.cmd.ea + 12
        for i in range(0, ncases):
            buf = idaapi.init_output_buffer(1024)

            out_line('case' + (' ' * 10), COLOR_INSN)

            op.value = get_long(ea)
            OutValue(op, OOF_SIGNED|OOFW_IMM)

            OutChar(' ')
            
            addr = toEA(self.cmd.cs, get_long(ea + 4))
            if not out_name_expr(op, addr, BADADDR):
                self.out_bad_address(addr)

            term_output_buffer()
            MakeLine(buf)

            ea = ea + 8

    def out(self):
        buf = idaapi.init_output_buffer(1024)
        
        OutMnem(14)
        
        if self.cmd.Op1.type != o_void:
            out_one_operand(0)
        
        for i in range(1, UA_MAXOP):
            op = self.cmd[i]
            
            if op.type == o_void:
                break
                
            OutChar(' ')
            out_one_operand(i)

        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)
        
        if self.cmd.itype == self.itype_CASETBL:
            self.out_casetable()
    
    def decode_op_code(self, n):
        self.cmd[n].type = o_near
        self.cmd[n].dtyp = dt_code
        self.cmd[n].addr = ua_next_long()
    
    def decode_op_data(self, n):
        self.cmd[n].type = o_mem
        self.cmd[n].dtyp = dt_dword
        self.cmd[n].addr = ua_next_long()
    
    def decode_op_stack(self, n):
        self.cmd[n].type = o_local
        self.cmd[n].dtyp = dt_dword
        self.cmd[n].addr = ua_next_long()
    
    def decode_op_imm(self, n):
        self.cmd[n].type = o_imm
        self.cmd[n].dtyp = dt_dword
        self.cmd[n].value = ua_next_long()
    
    def decode_op_sysreq(self, n):
        self.cmd[n].type = o_sysreq
        self.cmd[n].dtyp = dt_dword
        self.cmd[n].value = ua_next_long()
    
    def ana(self):
        opcode = ua_next_long()
        
        try:
            ins = self.instruc[opcode]
        except IndexError:
            return 0
        
        if ins['s'] is False:
            return 0
        
        self.cmd.itype = opcode
        
        i = 0
        for optype in ins['optypes']:
            self.decoders[optype](i)
            i += 1

        if self.cmd.itype == self.itype_CASETBL:
            ncases = self.cmd.Op1.value
            for i in range(0, ncases):
                ua_next_long()
                ua_next_long()

        return self.cmd.size
    
    def init_instructions(self):
        self.decoders = [
            self.decode_op_code,
            self.decode_op_data,
            self.decode_op_stack,
            self.decode_op_imm,
            self.decode_op_sysreq
        ]
        
        self.instruc = [
            { 'name': "none",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "load.pri",       'feature': CF_USE1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Load data variable into PRI"},                 
            { 'name': "load.alt",       'feature': CF_USE1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Load data variable into ALT"},                 
            { 'name': "load.s.pri",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Load stack variable into PRI"},                    
            { 'name': "load.s.alt",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Load stack variable into ALT"},                    
            { 'name': "lref.pri",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "lref.alt",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "lref.s.pri",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Load data variable pointed to by stack variable into PRI"},                    
            { 'name': "lref.s.alt",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Load data variable pointed to by stack variable into ALT"},                    
            { 'name': "load.i",         'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Load data variable pointed to by PRI into PRI"},                       
            { 'name': "lodb.i",         'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Load data variable pointed to by PRI into PRI (Zero-Extend)"},                 
            { 'name': "const.pri",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI = IMM"},                   
            { 'name': "const.alt",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "ALT = IMM"},                   
            { 'name': "addr.pri",       'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Load address of stack variable into PRI"},                 
            { 'name': "addr.alt",       'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Load address of stack variable into ALT"},                 
            { 'name': "stor.pri",       'feature': CF_CHG1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Store PRI into data variable"},                    
            { 'name': "stor.alt",       'feature': CF_CHG1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Store ALT into data variable"},                    
            { 'name': "stor.s.pri",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Store PRI into stack variable"},                   
            { 'name': "stor.s.alt",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Store ALT into stack variable"},                   
            { 'name': "sref.pri",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "sref.alt",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "sref.s.pri",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Store PRI into data variable pointed to by stack variable"},                   
            { 'name': "sref.s.alt",     'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Store ALT into data variable pointed to by stack variable"},                   
            { 'name': "stor.i",         'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Store PRI into data variable pointed to by ALT"},                      
            { 'name': "strb.i",         'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Store PRI into data variable pointed to by ALT (Zero-Extend)"},                    
            { 'name': "lidx",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Load data variable into PRI using indexed addressing (ALT + (PRI * 4))"},                       
            { 'name': "lidx.b",         'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Load data variable into PRI using indexed addressing (ALT + (PRI << IMM))"},                  
            { 'name': "idxaddr",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Calculate address using indexing and load into PRI (ALT + (PRI * 4))"},         
            { 'name': "idxaddr.b",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Calculate address using indexing and load into PRI (ALT + (PRI << IMM))"},                    
            { 'name': "align.pri",      'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "align.alt",      'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "lctrl",          'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "sctrl",          'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "move.pri",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = ALT"},                     
            { 'name': "move.alt",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "ALT = PRI"},                     
            { 'name': "xchg",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Exchange PRI and ALT"},                        
            { 'name': "push.pri",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Push PRI on the stack"},                       
            { 'name': "push.alt",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Push ALT on the stack"},                       
            { 'name': "push.r",         'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "push.c",         'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Push immediate value on the stack"},                   
            { 'name': "push",           'feature': CF_USE1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Push data variable on the stack"},                 
            { 'name': "push.s",         'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Push stack variable on the stack"},                    
            { 'name': "pop.pri",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Pop value from the stack and load into PRI"},                      
            { 'name': "pop.alt",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Pop value from the stack and load into ALT"},                      
            { 'name': "stack",          'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Grow stack pointer"},                  
            { 'name': "heap",           'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Allocate memory on the heap and load heap pointer into ALT"},                 
            { 'name': "proc",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Mark function start"},                     
            { 'name': "ret",            'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "retn",           'feature': CF_STOP,                                 'optypes': [],                                                                      's': True,   'cmt': "Return from subroutine"},                  
            { 'name': "call",           'feature': CF_USE1|CF_CALL,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Call subroutine"},         
            { 'name': "call.pri",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "jump",           'feature': CF_USE1|CF_JUMP|CF_STOP,                 'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump unconditionally"},    
            { 'name': "jrel",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "jzer",           'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI == 0"},            
            { 'name': "jnz",            'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI != 0"},            
            { 'name': "jeq",            'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI == ALT"},          
            { 'name': "jneq",           'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI != ALT"},          
            { 'name': "jless",          'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "jleq",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "jgrtr",          'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "jgeq",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "jsless",         'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI < ALT"},           
            { 'name': "jsleq",          'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI <= ALT"},          
            { 'name': "jsgrtr",         'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI > ALT"},           
            { 'name': "jsgeq",          'feature': CF_USE1|CF_JUMP,                         'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump if PRI >= ALT"},          
            { 'name': "shl",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI <<= ALT"},                     
            { 'name': "shr",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI >>= ALT (unsigned shift)"},                        
            { 'name': "sshr",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI >>= ALT (signed shift)"},                      
            { 'name': "shl.c.pri",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI <<= IMM"},                 
            { 'name': "shl.c.alt",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "ALT <<= IMM"},                 
            { 'name': "shr.c.pri",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI >>= IMM"},                 
            { 'name': "shr.c.alt",      'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "ALT >>= IMM"},                 
            { 'name': "smul",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI *= ALT"},                      
            { 'name': "sdiv",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI /= ALT (Load remainder into ALT)"},                        
            { 'name': "sdiv.alt",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = ALT / PRI (Load remainder into ALT)"},                       
            { 'name': "umul",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "udiv",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "udiv.alt",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "add",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI += ALT"},                      
            { 'name': "sub",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI -= ALT"},                      
            { 'name': "sub.alt",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = ALT - PRI"},                     
            { 'name': "and",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI &= ALT"},                      
            { 'name': "or",             'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI |= ALT"},                      
            { 'name': "xor",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI ^= ALT"},                      
            { 'name': "not",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI == 0"},                      
            { 'name': "neg",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = -PRI"},                      
            { 'name': "invert",         'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = ~PRI"},                      
            { 'name': "add.c",          'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI += IMM"},                  
            { 'name': "smul.c",         'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI *= IMM"},                  
            { 'name': "zero.pri",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Zero PRI"},                        
            { 'name': "zero.alt",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Zero ALT"},                        
            { 'name': "zero",           'feature': CF_CHG1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Zero data variable"},                  
            { 'name': "zero.s",         'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Zero stack variable"},                 
            { 'name': "sign.pri",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "sign.alt",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "eq",             'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI == ALT"},                        
            { 'name': "neq",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI != ALT"},                        
            { 'name': "less",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "leq",            'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "grtr",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "geq",            'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                      
            { 'name': "sless",          'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI < ALT"},                     
            { 'name': "sleq",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI <= ALT"},                        
            { 'name': "sgrtr",          'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI > ALT"},                     
            { 'name': "sgeq",           'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "PRI = PRI >= ALT"},                        
            { 'name': "eq.c.pri",       'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI = PRI == IMM"},                    
            { 'name': "eq.c.alt",       'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "PRI = ALT == IMM"},                    
            { 'name': "inc.pri",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Increment PRI"},                       
            { 'name': "inc.alt",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Increment ALT"},                       
            { 'name': "inc",            'feature': CF_CHG1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Increment data variable"},
            { 'name': "inc.s",          'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Increment stack variable"},
            { 'name': "inc.i",          'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Increment data variable pointed to by PRI"},
            { 'name': "dec.pri",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Decrement PRI"},
            { 'name': "dec.alt",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Decrement ALT"},
            { 'name': "dec",            'feature': CF_CHG1,                                 'optypes': [OPTYPE_DATA],                                                           's': True,   'cmt': "Decrement data variable"},
            { 'name': "dec.s",          'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Decrement stack variable"},
            { 'name': "dec.i",          'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Decrement data variable pointed to by PRI"},
            { 'name': "movs",           'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Move bytes pointed to by PRI to location pointed to by ALT"},
            { 'name': "cmps",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "fill",           'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Fill memory cells pointed to by ALT with value in PRI"},
            { 'name': "halt",           'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': None},
            { 'name': "bounds",         'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Check if PRI > IMM then error"},
            { 'name': "sysreq.pri",     'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "sysreq.c",       'feature': CF_USE1,                                 'optypes': [OPTYPE_SYSREQ],                                                         's': True,   'cmt': "Call native function"},
            { 'name': "file",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "line",           'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "symbol",         'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "srange",         'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "jump.pri",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "switch",         'feature': CF_USE1|CF_JUMP|CF_STOP,                 'optypes': [OPTYPE_CODE],                                                           's': True,   'cmt': "Jump to case table"},
            { 'name': "casetbl",        'feature': CF_USE1|CF_USE2|CF_JUMP|CF_STOP,         'optypes': [OPTYPE_IMM, OPTYPE_CODE],                                               's': True,   'cmt': "Compare PRI with values from case table and jump to corresponding address"},
            { 'name': "swap.pri",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Swap value on the stack with PRI"},
            { 'name': "swap.alt",       'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Swap value on the stack with ALT"},
            { 'name': "push.adr",       'feature': CF_USE1,                                 'optypes': [OPTYPE_STACK],                                                          's': True,   'cmt': "Push address of stack variable on the stack"},
            { 'name': "nop",            'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "No operation"},
            { 'name': "sysreq.n",       'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_SYSREQ, OPTYPE_IMM],                                             's': True,   'cmt': "Call native function"},
            { 'name': "symtag",         'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},
            { 'name': "break",          'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Invoke debugger"},
            { 'name': "push2.c",        'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_IMM, OPTYPE_IMM],                                                's': True,   'cmt': "Push immediate values on the stack"},
            { 'name': "push2",          'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_DATA, OPTYPE_DATA],                                              's': True,   'cmt': "Push data variables on the stack"},
            { 'name': "push2.s",        'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_STACK, OPTYPE_STACK],                                            's': True,   'cmt': "Push stack variables on the stack"},
            { 'name': "push2.adr",      'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_STACK, OPTYPE_STACK],                                            's': True,   'cmt': "Push addresses of stack variables on the stack"},
            { 'name': "push3.c",        'feature': CF_USE1|CF_USE2|CF_USE3,                 'optypes': [OPTYPE_IMM, OPTYPE_IMM, OPTYPE_IMM],                                    's': True,   'cmt': "Push immediate values on the stack"},
            { 'name': "push3",          'feature': CF_USE1|CF_USE2|CF_USE3,                 'optypes': [OPTYPE_DATA, OPTYPE_DATA, OPTYPE_DATA],                                 's': True,   'cmt': "Push data variables on the stack"},
            { 'name': "push3.s",        'feature': CF_USE1|CF_USE2|CF_USE3,                 'optypes': [OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK],                              's': True,   'cmt': "Push stack variables on the stack"},
            { 'name': "push3.adr",      'feature': CF_USE1|CF_USE2|CF_USE3,                 'optypes': [OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK],                              's': True,   'cmt': "Push addresses of stack variables on the stack"},
            { 'name': "push4.c",        'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4,         'optypes': [OPTYPE_IMM, OPTYPE_IMM, OPTYPE_IMM, OPTYPE_IMM],                        's': True,   'cmt': "Push immediate values on the stack"},
            { 'name': "push4",          'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4,         'optypes': [OPTYPE_DATA, OPTYPE_DATA, OPTYPE_DATA, OPTYPE_DATA],                    's': True,   'cmt': "Push data variables on the stack"},
            { 'name': "push4.s",        'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4,         'optypes': [OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK],                's': True,   'cmt': "Push stack variables on the stack"},
            { 'name': "push4.adr",      'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4,         'optypes': [OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK],                's': True,   'cmt': "Push addresses of stack variables on the stack"},
            { 'name': "push5.c",        'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5, 'optypes': [OPTYPE_IMM, OPTYPE_IMM, OPTYPE_IMM, OPTYPE_IMM, OPTYPE_IMM],            's': True,   'cmt': "Push immediate values on the stack"},
            { 'name': "push5",          'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5, 'optypes': [OPTYPE_DATA, OPTYPE_DATA, OPTYPE_DATA, OPTYPE_DATA, OPTYPE_DATA],       's': True,   'cmt': "Push data variables on the stack"},
            { 'name': "push5.s",        'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5, 'optypes': [OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK],  's': True,   'cmt': "Push stack variables on the stack"},
            { 'name': "push5.adr",      'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5, 'optypes': [OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK, OPTYPE_STACK],  's': True,   'cmt': "Push addresses of stack variables on the stack"},
            { 'name': "load.both",      'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_DATA, OPTYPE_DATA],                                              's': True,   'cmt': "Load data variables into PRI and ALT"},                            
            { 'name': "load.s.both",    'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_STACK, OPTYPE_STACK],                                            's': True,   'cmt': "Load stack variables into PRI and ALT"},                           
            { 'name': "const",          'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_DATA, OPTYPE_IMM],                                               's': True,   'cmt': "Move immediate value to data variable"},                           
            { 'name': "const.s",        'feature': CF_USE1|CF_USE2,                         'optypes': [OPTYPE_STACK, OPTYPE_IMM],                                              's': True,   'cmt': "Move immediate value to stack variable"},                          
            { 'name': "sysreq.d",       'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                                      
            { 'name': "sysreq.nd",      'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                                      
            { 'name': "trk.push.c",     'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Push tracker on the heap"},                                    
            { 'name': "trk.pop",        'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Pop tracker from the heap and free memory"},                                       
            { 'name': "genarray",       'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Generate dynamic array"},                                  
            { 'name': "genarray.z",     'feature': CF_USE1,                                 'optypes': [OPTYPE_IMM],                                                            's': True,   'cmt': "Generate dynamic array and fill with zeros"},                                  
            { 'name': "stradjust.pri",  'feature': 0,                                       'optypes': [],                                                                      's': True,   'cmt': "Convert bytes to cells for dynamic array and load into PRI ((PRI + 4) / 4)"},                                      
            { 'name': "stackadjust",    'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},                                      
            { 'name': "endproc",        'feature': CF_STOP,                                 'optypes': [],                                                                      's': True,   'cmt': "Mark function end"},                                       
            { 'name': "ldgfn.pri",      'feature': 0,                                       'optypes': [],                                                                      's': False,  'cmt': None},  
            { 'name': "rebase",         'feature': CF_USE1|CF_USE2|CF_USE3,                 'optypes': [OPTYPE_DATA, OPTYPE_IMM, OPTYPE_IMM],                                   's': True,   'cmt': "Rebase dynamic array"},                                            
        ]

        i = 0
        for x in self.instruc:
            setattr(self, 'itype_' + x['name'].replace('.', '_').upper(), i)
            i += 1
        
        self.instruc_start = 0
        
        self.instruc_end = len(self.instruc) + 1

        self.icode_return = self.itype_RETN

    def init_registers(self):
        self.regNames = ["CS", "DS"]

        for i in range(0, len(self.regNames)):
            setattr(self, 'ireg_' + self.regNames[i], i)
        
        self.regFirstSreg = self.ireg_CS
        self.regLastSreg  = self.ireg_DS

        self.regCodeSreg = self.ireg_CS
        self.regDataSreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

def PROCESSOR_ENTRY():
    return srcpawn_processor_t()
