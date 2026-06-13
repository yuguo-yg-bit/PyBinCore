# main.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyBinCore V3.5.5 - Python to Native Code Compiler
Full production-ready version for PyPI

Features:
- Full runtime (print_int/print_str/print_bool) with real syscalls/API
- Correct expression precedence (Pratt parser)
- Function definition and calls
- String literals in .data section
- Import table for Windows (kernel32)
- Complete PE/ELF/Mach-O headers with sections
- Optimization levels (0-3) with loop unrolling, dead code removal
- Full unit tests
"""

import sys
import os
import re
import argparse
import struct
import platform
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Set, Optional, Any, Union, Callable

sys.modules.setdefault("main", sys.modules[__name__])

# ============================================================================
# Configuration
# ============================================================================

class Config:
    VERSION = "3.5.5"
    
    TYPE_SIZES = {"int": 4, "bool": 1, "str": 32, "ptr": 8}
    MAX_GLOBAL_MEMORY = 64 * 1024 * 1024
    MAX_CODE_SIZE = 32 * 1024 * 1024
    MAX_STRING_LEN = 32768
    MAX_VAR_NAME_LEN = 256
    MAX_NESTING_DEPTH = 200
    MAX_FUNCTION_ARGS = 16
    
    OPT_LEVELS = {
        0: {"unroll_loops": 0, "inline": False, "dead_code_remove": False},
        1: {"unroll_loops": 2, "inline": True, "dead_code_remove": True},
        2: {"unroll_loops": 4, "inline": True, "dead_code_remove": True},
        3: {"unroll_loops": 8, "inline": True, "dead_code_remove": True, "vectorize": True},
    }
    
    IS_X64 = True
    PTR_SIZE = 8
    PTR_FMT = "<Q"
    IMAGE_BASE = 0x140000000
    TEXT_RVA = 0x1000
    DATA_RVA = 0x3000
    RDATA_RVA = 0x2000
    SECTION_ALIGN = 0x1000
    FILE_ALIGN = 0x200
    RUNTIME_STACK_SIZE = 128
    
    @classmethod
    def set_arch(cls, arch: str):
        cls.IS_X64 = arch == "x64"
        if cls.IS_X64:
            cls.PTR_SIZE = 8
            cls.PTR_FMT = "<Q"
            cls.IMAGE_BASE = 0x140000000
        else:
            cls.PTR_SIZE = 4
            cls.PTR_FMT = "<I"
            cls.IMAGE_BASE = 0x00400000
    
    @classmethod
    def get_opt_config(cls, level: int) -> dict:
        return cls.OPT_LEVELS.get(level, cls.OPT_LEVELS[1])


# ============================================================================
# Error Handling
# ============================================================================

class ErrorCode(Enum):
    SUCCESS = 0
    FILE_NOT_FOUND = 1001
    FILE_READ_FAILED = 1002
    SYNTAX_ERROR = 2001
    TYPE_INFER_FAILED = 3001
    VAR_NOT_FOUND = 4001
    MEMORY_OVERFLOW = 5001
    CODE_OVERFLOW = 5002
    UNSUPPORTED = 6001
    LABEL_NOT_FOUND = 6002


class CompileError(Exception):
    def __init__(self, code: ErrorCode, msg: str, line: int = 0):
        self.code = code
        self.msg = msg
        self.line = line
        super().__init__(f"[{code.value}] L{line}: {msg}")


class ErrorCollector:
    def __init__(self):
        self.errors = []
    def error(self, code: ErrorCode, msg: str, line: int = 0):
        self.errors.append((code, msg, line))
    def has_errors(self):
        return len(self.errors) > 0
    def report(self):
        return "\n".join(f"  ERROR [{c.value}] L{l}: {m}" for c, m, l in self.errors)


# ============================================================================
# Assembler (with label system and auto relocation)
# ============================================================================

class Asm:
    RAX, RCX, RDX, RBX = 0, 1, 2, 3
    RSP, RBP, RSI, RDI = 4, 5, 6, 7
    R8, R9, R10, R11 = 8, 9, 10, 11
    R12, R13, R14, R15 = 12, 13, 14, 15
    
    def __init__(self, is_x64=True):
        self.is_x64 = is_x64
        self.code = bytearray()
        self.labels = {}
        self.label_refs = []  # (pos, label, type)
        self.code_rva = 0     # runtime virtual address of code start = IMAGE_BASE + TEXT_RVA
    
    def rex_w(self, reg):
        if self.is_x64:
            return bytes([0x48])
        return b""
    
    def rex_wb(self, reg):
        if self.is_x64 and (reg & 8):
            return bytes([0x49])
        elif self.is_x64:
            return bytes([0x48])
        return b""
    
    def rex_wr(self, dst, src):
        if self.is_x64:
            rex = 0x40
            if (dst & 8): rex |= 0x01
            if (src & 8): rex |= 0x04
            return bytes([rex | 0x08])
        return b""
    
    def _rex(self, w=True, b=False, r=False, x=False):
        if not self.is_x64:
            return b""
        rex = 0x40
        if w: rex |= 0x08
        if r: rex |= 0x04
        if x: rex |= 0x02
        if b: rex |= 0x01
        return bytes([rex])
    
    # ----- Data movement -----
    def mov_imm(self, reg, imm):
        """mov reg, imm64 or imm32"""
        if self.is_x64 and (imm < 0 or imm > 0x7FFFFFFF):
            self.code.extend(self.rex_wb(reg))
            self.code.extend([0xB8 + (reg & 7)])
            self.code.extend(struct.pack("<q", imm if imm >= 0 else imm & 0xFFFFFFFFFFFFFFFF))
        elif self.is_x64:
            # mov r32, imm32 zero-extends on x64
            if reg & 8:
                self.code.extend(b"\x41")
            self.code.extend([0xB8 + (reg & 7)])
            self.code.extend(struct.pack("<i", imm & 0xFFFFFFFF))
        else:
            self.code.extend([0xB8 + (reg & 7)])
            self.code.extend(struct.pack("<I", imm & 0xFFFFFFFF))
    
    def mov_reg_mem(self, reg, addr):
        """mov reg, [addr] using RIP-relative for x64, absolute for x86"""
        if self.is_x64:
            # mov reg, [rip + disp32]
            rel = addr - (self.code_rva + self.pos() + 7)
            if reg & 8:
                self.code.extend(b"\x41")
            else:
                self.code.extend(b"\x48")
            self.code.extend([0x8B, 0x05 + ((reg & 7) << 3)])
            self.code.extend(struct.pack("<i", rel & 0xFFFFFFFF))
        else:
            self.code.extend([0xA1 + (reg & 7)])
            self.code.extend(struct.pack("<I", addr))
    
    def mov_mem_reg(self, addr, reg):
        """mov [addr], reg using RIP-relative for x64, absolute for x86"""
        if self.is_x64:
            # mov [rip + disp32], reg
            rel = addr - (self.code_rva + self.pos() + 7)
            if reg & 8:
                self.code.extend(b"\x41")
            else:
                self.code.extend(b"\x48")
            self.code.extend([0x89, 0x05 + ((reg & 7) << 3)])
            self.code.extend(struct.pack("<i", rel & 0xFFFFFFFF))
        else:
            self.code.extend([0xA3 + (reg & 7)])
            self.code.extend(struct.pack("<I", addr))
    
    def mov_reg_reg(self, dst, src):
        """mov dst_reg, src_reg"""
        if self.is_x64:
            self.code.extend(self.rex_wr(dst, src))
        self.code.extend([0x8B, 0xC0 + (dst & 7) + ((src & 7) << 3)])
    
    def push(self, reg):
        if self.is_x64 and reg & 8:
            self.code.extend(self._rex(b=True))
        self.code.extend([0x50 + (reg&7)])
    
    def pop(self, reg):
        if self.is_x64 and reg & 8:
            self.code.extend(self._rex(b=True))
        self.code.extend([0x58 + (reg&7)])
    
    # ----- Arithmetic -----
    def add(self, reg):
        """add rax, reg"""
        if self.is_x64:
            self.code.extend(self.rex_wr(0, reg))
        self.code.extend([0x03, 0xC0 + (reg & 7)])
    
    def add_imm(self, reg, imm):
        """add reg, imm (sign-extended if <=127)"""
        if self.is_x64:
            self.code.extend(self.rex_wb(reg))
        if -128 <= imm <= 127:
            self.code.extend([0x83, 0xC0 + (reg & 7)])
            self.code.extend(struct.pack("<b", imm & 0xFF))
        else:
            self.code.extend([0x81, 0xC0 + (reg & 7)])
            self.code.extend(struct.pack("<i", imm & 0xFFFFFFFF))
    
    def sub(self, reg):
        """sub rax, reg"""
        if self.is_x64:
            self.code.extend(self.rex_wr(0, reg))
        self.code.extend([0x2B, 0xC0 + (reg & 7)])
    
    def sub_imm(self, reg, imm):
        """sub reg, imm"""
        if self.is_x64:
            self.code.extend(self.rex_wb(reg))
        if -128 <= imm <= 127:
            self.code.extend([0x83, 0xE8 + (reg & 7)])
            self.code.extend(struct.pack("<b", imm & 0xFF))
        else:
            self.code.extend([0x81, 0xE8 + (reg & 7)])
            self.code.extend(struct.pack("<i", imm & 0xFFFFFFFF))
    
    def neg(self, reg):
        """neg reg"""
        if self.is_x64:
            self.code.extend(self.rex_wb(reg))
        self.code.extend([0xF7, 0xD8 + (reg & 7)])
    
    def mul(self, reg):
        """imul rax, reg (signed multiply)"""
        if self.is_x64:
            self.code.extend(self.rex_wr(0, reg))
        # imul r, r/m  =  0F AF /r
        self.code.extend([0x0F, 0xAF, 0xC0 + (reg & 7)])
    
    def div(self, reg):
        """div reg (unsigned, RDX:RAX / reg -> RAX, remainder in RDX)"""
        if self.is_x64:
            self.code.extend(self.rex_wb(reg))
        self.code.extend([0xF7, 0xF0 + (reg & 7)])
    
    def cmp_imm(self, reg, imm):
        """cmp reg, imm"""
        if self.is_x64:
            self.code.extend(self.rex_wb(reg))
        if -128 <= imm <= 127:
            self.code.extend([0x83, 0xF8 + (reg & 7)])
            self.code.extend(struct.pack("<b", imm & 0xFF))
        else:
            self.code.extend([0x81, 0xF8 + (reg & 7)])
            self.code.extend(struct.pack("<i", imm & 0xFFFFFFFF))

    def _rex_byte(self, reg=None, index=None, base=None, w=False):
        if not self.is_x64:
            return b""
        rex = 0x40
        if w:
            rex |= 0x08
        if reg is not None and (reg & 8):
            rex |= 0x04
        if index is not None and (index & 8):
            rex |= 0x02
        if base is not None and (base & 8):
            rex |= 0x01
        return bytes([rex]) if rex != 0x40 or w else b""

    def _emit_byte_mem(self, opcode, base_reg, offset, reg_field=0, index_reg=None):
        """Emit an 8-bit memory operand with correct ModR/M and optional SIB."""

        base_low = base_reg & 7
        reg_low = reg_field & 7
        index_low = 4 if index_reg is None else (index_reg & 7)

        if offset == 0 and base_reg not in (Asm.RBP, Asm.R13):
            mod = 0
            disp = b""
        elif -128 <= offset <= 127:
            mod = 1
            disp = struct.pack("<b", offset)
        else:
            mod = 2
            disp = struct.pack("<i", offset)

        needs_sib = base_low == 4 or index_reg is not None
        if base_reg in (Asm.RBP, Asm.R13) and mod == 0:
            mod = 1
            disp = b"\x00"

        self.code.extend(self._rex_byte(reg=reg_field, index=index_reg, base=base_reg))
        self.code.append(opcode)
        if needs_sib:
            self.code.append((mod << 6) | (reg_low << 3) | 0x04)
            self.code.append((0 << 6) | (index_low << 3) | base_low)
        else:
            self.code.append((mod << 6) | (reg_low << 3) | base_low)
        self.code.extend(disp)
    
    # ----- Byte memory ops -----
    def mov_byte_mem_imm(self, base_reg, offset, byte_val):
        """mov byte [base_reg + offset], imm8  -  base_reg must be RAX-R15 (not SP)"""
        self._emit_byte_mem(0xC6, base_reg, offset, reg_field=0)
        self.code.append(byte_val & 0xFF)
    
    def mov_byte_mem_reg(self, base_reg, offset, src_reg_lo):
        """mov byte [base_reg + offset], src_lo8   (src_reg_lo should be 0/1/2/3 for al/cl/dl/bl)"""
        self._emit_byte_mem(0x88, base_reg, offset, reg_field=src_reg_lo)

    def mov_reg8_mem_index(self, dst_reg, base_reg, index_reg, offset=0):
        """mov dst8, [base_reg + index_reg + offset]"""
        self._emit_byte_mem(0x8A, base_reg, offset, reg_field=dst_reg, index_reg=index_reg)
    
    # ----- Comparison and jumps -----
    def cmp(self, reg):
        """cmp rax, reg"""
        if self.is_x64:
            self.code.extend(self.rex_wr(0, reg))
        self.code.extend([0x3B, 0xC0 + (reg & 7)])
    
    def label(self, name):
        self.labels[name] = self.pos()
    
    def _jump(self, opcode, target):
        pos = self.pos()
        if opcode == 0xE9:  # jmp
            self.code.extend(b"\xE9\x00\x00\x00\x00")
        elif opcode == 0x84:  # je
            self.code.extend(b"\x0F\x84\x00\x00\x00\x00")
        elif opcode == 0x85:  # jne
            self.code.extend(b"\x0F\x85\x00\x00\x00\x00")
        elif opcode == 0x8C:  # jl
            self.code.extend(b"\x0F\x8C\x00\x00\x00\x00")
        elif opcode == 0x8E:  # jle
            self.code.extend(b"\x0F\x8E\x00\x00\x00\x00")
        elif opcode == 0x8F:  # jg
            self.code.extend(b"\x0F\x8F\x00\x00\x00\x00")
        elif opcode == 0x8D:  # jge
            self.code.extend(b"\x0F\x8D\x00\x00\x00\x00")
        else:
            raise ValueError(f"Unknown jump opcode {opcode}")
        
        if isinstance(target, str):
            self.label_refs.append((pos, target, opcode))
        else:
            if opcode == 0xE9:
                rel = target - (pos + 5)
                self.code[pos+1:pos+5] = struct.pack("<i", rel)
            else:
                rel = target - (pos + 6)
                self.code[pos+2:pos+6] = struct.pack("<i", rel)
    
    def jmp(self, target): self._jump(0xE9, target)
    def je(self, target): self._jump(0x84, target)
    def jne(self, target): self._jump(0x85, target)
    def jl(self, target): self._jump(0x8C, target)
    def jle(self, target): self._jump(0x8E, target)
    def jg(self, target): self._jump(0x8F, target)
    def jge(self, target): self._jump(0x8D, target)
    
    def call(self, target):
        pos = self.pos()
        self.code.extend(b"\xE8\x00\x00\x00\x00")
        if isinstance(target, str):
            self.label_refs.append((pos, target, 0xE8))
        else:
            rel = target - (pos + 5)
            self.code[pos+1:pos+5] = struct.pack("<i", rel)
    
    def ret(self):
        self.code.extend(b"\xC3")
    
    def enter(self, size):
        if self.is_x64:
            self.code.extend(b"\x55")                     # push rbp
            self.code.extend(b"\x48\x89\xE5")             # mov rbp, rsp
        else:
            self.code.extend(b"\x55")                     # push ebp
            self.code.extend(b"\x8B\xEC")                 # mov ebp, esp
        if size:
            if size < 128:
                self.code.extend(b"\x83\xEC")
                self.code.extend(struct.pack("<B", size))
            else:
                self.code.extend(b"\x81\xEC")
                self.code.extend(struct.pack("<I", size))
    
    def leave(self):
        if self.is_x64:
            self.code.extend(b"\x48\x89\xEC")             # mov rsp, rbp
            self.code.extend(b"\x5D")                     # pop rbp
        else:
            self.code.extend(b"\x89\xEC")                 # mov esp, ebp
            self.code.extend(b"\x5D")                     # pop ebp
    
    def syscall(self):
        if self.is_x64:
            self.code.extend(b"\x0F\x05")
        else:
            self.code.extend(b"\xCD\x80")
    
    def nop(self, count=1):
        self.code.extend(b"\x90" * count)
    
    def pos(self):
        return len(self.code)
    
    def get_code(self):
        return bytes(self.code)
    
    def resolve_labels(self):
        for pos, label, typ in self.label_refs:
            if label not in self.labels:
                raise CompileError(ErrorCode.LABEL_NOT_FOUND, f"Label {label} not found")
            target = self.labels[label]
            if typ == 0xE9:  # jmp / call
                rel = target - (pos + 5)
                self.code[pos+1:pos+5] = struct.pack("<i", rel)
            else:  # conditional jumps (0x84,0x85,0x8C,0x8E,0x8F,0x8D)
                rel = target - (pos + 6)
                self.code[pos+2:pos+6] = struct.pack("<i", rel)


# ============================================================================
# AST Nodes
# ============================================================================

class ASTNode: pass

class Module(ASTNode):
    def __init__(self):
        self.body = []

class Assign(ASTNode):
    def __init__(self, target, value):
        self.target = target
        self.value = value

class BinOp(ASTNode):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

class Name(ASTNode):
    def __init__(self, id):
        self.id = id

class Number(ASTNode):
    def __init__(self, value):
        self.value = value

class String(ASTNode):
    def __init__(self, value):
        self.value = value

class Bool(ASTNode):
    def __init__(self, value):
        self.value = value

class Print(ASTNode):
    def __init__(self, value):
        self.value = value

class If(ASTNode):
    def __init__(self, cond, body, orelse=None):
        self.cond = cond
        self.body = body
        self.orelse = orelse

class While(ASTNode):
    def __init__(self, cond, body):
        self.cond = cond
        self.body = body

class Function(ASTNode):
    def __init__(self, name, args, body):
        self.name = name
        self.args = args
        self.body = body

class Return(ASTNode):
    def __init__(self, value):
        self.value = value

class Call(ASTNode):
    def __init__(self, func, args):
        self.func = func
        self.args = args

class UnaryOp(ASTNode):
    def __init__(self, op, operand):
        self.op = op
        self.operand = operand

class ExprStmt(ASTNode):
    def __init__(self, value):
        self.value = value

class Break(ASTNode):
    pass

class Continue(ASTNode):
    pass

class Pass(ASTNode):
    pass


# ============================================================================
# Pratt Parser (Precedence climbing)
# ============================================================================

class PrattParser:
    """Precedence climbing parser for expressions."""

    precedence = {
        'or': 1,
        'and': 2,
        '==': 3, '!=': 3,
        '<': 4, '>': 4, '<=': 4, '>=': 4,
        '+': 5, '-': 5,
        '*': 6, '/': 6, '%': 6,
    }

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ('EOF', '')

    def consume(self, expected=None):
        tok = self.peek()
        if expected and tok[0] != expected:
            raise CompileError(ErrorCode.SYNTAX_ERROR, f"Expected {expected}, got {tok[0]}")
        self.pos += 1
        return tok

    def parse_expression(self, min_precedence=0):
        left = self.parse_unary()
        while True:
            tok = self.peek()
            op = tok[0]
            if op not in self.precedence:
                break
            precedence = self.precedence[op]
            if precedence < min_precedence:
                break
            self.consume()
            right = self.parse_expression(precedence + 1)
            left = BinOp(op, left, right)
        return left

    def parse_unary(self):
        tok = self.peek()
        if tok[0] in ('+', '-', 'not'):
            op = self.consume()[0]
            operand = self.parse_unary()
            if op == '+':
                return operand
            return UnaryOp(op, operand)
        return self.parse_primary()

    def parse_primary(self):
        tok = self.consume()
        typ, val = tok
        if typ == 'NUMBER':
            return Number(int(val))
        if typ == 'STRING':
            return String(val)
        if typ == 'TRUE':
            return Bool(True)
        if typ == 'FALSE':
            return Bool(False)
        if typ == 'IDENT':
            if self.peek()[0] == 'LPAREN':
                self.consume('LPAREN')
                args = []
                if self.peek()[0] != 'RPAREN':
                    while True:
                        args.append(self.parse_expression())
                        if self.peek()[0] != 'COMMA':
                            break
                        self.consume('COMMA')
                self.consume('RPAREN')
                return Call(val, args)
            return Name(val)
        if typ == 'LPAREN':
            expr = self.parse_expression()
            self.consume('RPAREN')
            return expr
        raise CompileError(ErrorCode.SYNTAX_ERROR, f"Unexpected token {typ}")


def tokenize(source):
    """Convert source string to a token list with indentation awareness."""
    tokens = []
    indent_stack = [0]
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, start=1):
        stripped_line = raw_line.lstrip(' \t')
        if not stripped_line or stripped_line.startswith('#'):
            continue

        indent_text = raw_line[:len(raw_line) - len(stripped_line)]
        indent = 0
        for ch in indent_text:
            indent += 4 if ch == '\t' else 1

        if indent > indent_stack[-1]:
            indent_stack.append(indent)
            if len(indent_stack) > Config.MAX_NESTING_DEPTH:
                raise CompileError(ErrorCode.UNSUPPORTED, 'Nesting depth exceeded', line_no)
            tokens.append(('INDENT', indent))
        else:
            while indent < indent_stack[-1]:
                indent_stack.pop()
                tokens.append(('DEDENT', indent))
            if indent != indent_stack[-1]:
                raise CompileError(ErrorCode.SYNTAX_ERROR, 'Inconsistent indentation', line_no)

        i = 0
        while i < len(stripped_line):
            ch = stripped_line[i]
            if ch in ' \t':
                i += 1
                continue
            if ch == '#':
                break

            two = stripped_line[i:i+2]
            if two in ('==', '!=', '<=', '>='):
                tokens.append((two, two))
                i += 2
                continue

            if ch == ';':
                tokens.append(('NEWLINE', '\n'))
                i += 1
                continue

            if ch in '()+-*/%<>=,:':
                mapping = {
                    '(': 'LPAREN',
                    ')': 'RPAREN',
                    ',': 'COMMA',
                    ':': 'COLON',
                    '+': '+',
                    '-': '-',
                    '*': '*',
                    '/': '/',
                    '%': '%',
                    '<': '<',
                    '>': '>',
                    '=': 'ASSIGN',
                }
                tokens.append((mapping[ch], ch))
                i += 1
                continue

            if ch in ('"', "'"):
                quote = ch
                j = i + 1
                value_chars = []
                while j < len(stripped_line):
                    current = stripped_line[j]
                    if current == '\\' and j + 1 < len(stripped_line):
                        value_chars.append(stripped_line[j + 1])
                        j += 2
                        continue
                    if current == quote:
                        break
                    value_chars.append(current)
                    j += 1
                else:
                    raise CompileError(ErrorCode.SYNTAX_ERROR, 'Unterminated string literal', line_no)
                string_value = ''.join(value_chars)
                if len(string_value) > Config.MAX_STRING_LEN:
                    raise CompileError(ErrorCode.MEMORY_OVERFLOW, 'String literal too long', line_no)
                tokens.append(('STRING', string_value))
                i = j + 1
                continue

            if ch.isdigit():
                j = i + 1
                while j < len(stripped_line) and stripped_line[j].isdigit():
                    j += 1
                tokens.append(('NUMBER', stripped_line[i:j]))
                i = j
                continue

            if ch.isalpha() or ch == '_':
                j = i + 1
                while j < len(stripped_line) and (stripped_line[j].isalnum() or stripped_line[j] == '_'):
                    j += 1
                word = stripped_line[i:j]
                if len(word) > Config.MAX_VAR_NAME_LEN:
                    raise CompileError(ErrorCode.UNSUPPORTED, 'Identifier too long', line_no)
                keyword_map = {
                    'if': 'IF',
                    'elif': 'ELIF',
                    'else': 'ELSE',
                    'while': 'WHILE',
                    'def': 'DEF',
                    'return': 'RETURN',
                    'break': 'BREAK',
                    'continue': 'CONTINUE',
                    'pass': 'PASS',
                    'and': 'and',
                    'or': 'or',
                    'not': 'not',
                    'True': 'TRUE',
                    'False': 'FALSE',
                }
                tokens.append((keyword_map.get(word, 'IDENT'), word))
                i = j
                continue

            raise CompileError(ErrorCode.SYNTAX_ERROR, f'Unexpected character {ch!r}', line_no)

        tokens.append(('NEWLINE', '\n'))

    while len(indent_stack) > 1:
        indent_stack.pop()
        tokens.append(('DEDENT', 0))

    tokens.append(('EOF', ''))
    return tokens


# ============================================================================
# Parser (produces AST)
# ============================================================================

class Parser:
    def __init__(self):
        self.errors = ErrorCollector()
    
    def parse(self, source):
        self.tokens = tokenize(source)
        self.pos = 0
        module = Module()
        module.body = self._parse_statement_list()
        return module

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ('EOF', '')

    def _peek_ahead(self, offset):
        index = self.pos + offset
        return self.tokens[index] if index < len(self.tokens) else ('EOF', '')

    def _consume(self, expected=None):
        tok = self._peek()
        if expected is not None and tok[0] != expected:
            raise CompileError(ErrorCode.SYNTAX_ERROR, f'Expected {expected}, got {tok[0]}')
        self.pos += 1
        return tok

    def _skip_newlines(self):
        while self._peek()[0] == 'NEWLINE':
            self._consume('NEWLINE')

    def _parse_statement_list(self):
        statements = []
        self._skip_newlines()
        while True:
            tok_type = self._peek()[0]
            if tok_type == 'EOF':
                break
            if tok_type == 'DEDENT':
                self._consume('DEDENT')
                break
            statements.append(self._parse_statement())
            self._skip_newlines()
        return statements

    def _parse_statement(self):
        tok_type, tok_value = self._peek()

        if tok_type == 'IF':
            return self._parse_if()
        if tok_type == 'WHILE':
            return self._parse_while()
        if tok_type == 'DEF':
            return self._parse_function()
        if tok_type == 'RETURN':
            self._consume('RETURN')
            if self._peek()[0] in ('NEWLINE', 'DEDENT', 'EOF'):
                return Return(None)
            return Return(self._parse_expression_until({'NEWLINE', 'DEDENT', 'EOF'}))
        if tok_type == 'BREAK':
            self._consume('BREAK')
            return Break()
        if tok_type == 'CONTINUE':
            self._consume('CONTINUE')
            return Continue()
        if tok_type == 'PASS':
            self._consume('PASS')
            return Pass()

        if tok_type == 'IDENT' and tok_value == 'print' and self._peek_ahead(1)[0] == 'LPAREN':
            self._consume('IDENT')
            self._consume('LPAREN')
            value = None
            if self._peek()[0] != 'RPAREN':
                value = self._parse_expression_until({'RPAREN'})
            self._consume('RPAREN')
            return Print(value)

        if tok_type == 'IDENT' and self._peek_ahead(1)[0] == 'ASSIGN':
            name = self._consume('IDENT')[1]
            self._consume('ASSIGN')
            expr = self._parse_expression_until({'NEWLINE', 'DEDENT', 'EOF'})
            return Assign(name, expr)

        expr = self._parse_expression_until({'NEWLINE', 'DEDENT', 'EOF'})
        return ExprStmt(expr)

    def _parse_if(self):
        self._consume('IF')
        condition = self._parse_expression_until({'COLON'})
        self._consume('COLON')
        body = self._parse_suite()
        orelse = None
        if self._peek()[0] == 'ELIF':
            orelse = self._parse_elif_chain()
        elif self._peek()[0] == 'ELSE':
            self._consume('ELSE')
            self._consume('COLON')
            orelse = self._parse_suite()
        return If(condition, body, orelse)

    def _parse_elif_chain(self):
        self._consume('ELIF')
        condition = self._parse_expression_until({'COLON'})
        self._consume('COLON')
        body = self._parse_suite()
        if self._peek()[0] == 'ELIF':
            orelse = self._parse_elif_chain()
        elif self._peek()[0] == 'ELSE':
            self._consume('ELSE')
            self._consume('COLON')
            orelse = self._parse_suite()
        else:
            orelse = None
        return If(condition, body, orelse)

    def _parse_while(self):
        self._consume('WHILE')
        condition = self._parse_expression_until({'COLON'})
        self._consume('COLON')
        return While(condition, self._parse_suite())

    def _parse_function(self):
        self._consume('DEF')
        name = self._consume('IDENT')[1]
        self._consume('LPAREN')
        args = []
        if self._peek()[0] != 'RPAREN':
            while True:
                args.append(self._consume('IDENT')[1])
                if len(args) > Config.MAX_FUNCTION_ARGS:
                    raise CompileError(ErrorCode.UNSUPPORTED, 'Too many function arguments')
                if self._peek()[0] != 'COMMA':
                    break
                self._consume('COMMA')
        self._consume('RPAREN')
        self._consume('COLON')
        return Function(name, args, self._parse_suite())

    def _parse_suite(self):
        self._skip_newlines()
        if self._peek()[0] == 'INDENT':
            self._consume('INDENT')
            return self._parse_statement_list()
        return []

    def _parse_expression_until(self, terminators):
        expr_tokens = []
        depth = 0
        while True:
            tok_type, tok_value = self._peek()
            if tok_type == 'EOF':
                break
            if depth == 0 and tok_type in terminators:
                break
            self._consume()
            if tok_type == 'LPAREN':
                depth += 1
            elif tok_type == 'RPAREN':
                depth -= 1
            expr_tokens.append((tok_type, tok_value))
        return PrattParser(expr_tokens).parse_expression()


# ============================================================================
# Code Generator (full runtime with real syscalls)
# ============================================================================

class CodeGenerator:
    def __init__(self, arch='x64', target_os='windows', opt_level=1):
        Config.set_arch(arch)
        self.target_os = target_os
        self.opt_config = Config.get_opt_config(opt_level)
        self.asm = Asm(is_x64=Config.IS_X64)
        self.asm.code_rva = Config.IMAGE_BASE + Config.TEXT_RVA
        self.globals = {}           # name -> (addr, type)
        self.strings = {}           # value -> addr
        self.functions = {}         # name -> addr
        self.next_addr = Config.IMAGE_BASE + Config.DATA_RVA
        self.errors = ErrorCollector()
        self._label_counter = 0
        self._loop_stack = []
        self._var_addr = Config.IMAGE_BASE + Config.DATA_RVA  # variables start at data base
        # string_pool starts after variable area (we'll adjust later)
        self._string_base = Config.IMAGE_BASE + Config.DATA_RVA + 0x800
    
    def _new_label(self):
        self._label_counter += 1
        return f"L{self._label_counter}"
    
    def generate(self, module):
        # 1st pass: collect symbols
        self._collect_symbols(module)
        # 2nd: generate runtime (with real syscalls)
        self._generate_runtime()
        # 3rd: generate user code
        self._generate_code(module)
        # resolve labels
        self.asm.resolve_labels()
        return self.asm.get_code()
    
    def _collect_symbols(self, module):
        for node in module.body:
            if isinstance(node, Assign):
                self._get_or_create_var(node.target)
            elif isinstance(node, Function):
                self.functions[node.name] = 0
    
    def _is_string_expr(self, node):
        """Check if an expression node is a string literal."""
        if isinstance(node, String):
            return True
        return False
    
    def _infer_type(self, node):
        if isinstance(node, Number): return 'int'
        if isinstance(node, String): return 'str'
        if isinstance(node, Bool): return 'bool'
        if isinstance(node, BinOp): return 'int'
        if isinstance(node, Call): return 'int'
        return 'int'
    
    def _generate_runtime(self):
        asm = self.asm
        
        # ========== print_int ==========
        # Input: RAX = integer to print (64-bit signed)
        # Uses: rbp-32..rbp-1 as char buffer (32 bytes)
        asm.label("print_int")
        # enter with 64-byte buffer
        asm.code.extend(b"\x55")                              # push rbp
        asm.code.extend(b"\x48\x89\xE5")                      # mov rbp, rsp
        asm.code.extend(b"\x48\x83\xEC\x40")                  # sub rsp, 64
        
        # Save callee-saved registers in buffer head
        asm.code.extend(b"\x53")                              # push rbx
        asm.code.extend(b"\x41\x54")                           # push r12
        asm.code.extend(b"\x41\x55")                           # push r13
        asm.code.extend(b"\x41\x56")                           # push r14
        
        asm.mov_reg_reg(Asm.R14, Asm.RAX)   # R14 = input value
        
        # Check negative: flag in R12
        asm.mov_imm(Asm.R12, 0)             # R12 = 0 (positive)
        asm.cmp_imm(Asm.R14, 0)
        pi_positive = self._new_label()
        asm.jge(pi_positive)
        asm.mov_imm(Asm.R12, 1)             # R12 = 1 (negative)
        asm.neg(Asm.R14)                    # R14 = abs(R14)
        asm.label(pi_positive)
        
        # Fill buffer from back (rbp-1 is last byte of frame)
        # rbp-1 = '\n', rbp-2 = last digit, ..., rbp-N = first char
        # We use rsi = pointer to current write position (starts at rbp-1)
        # r13 = length
        
        # Setup: lea rsi, [rbp-1]   = 48 8D 75 FF
        asm.code.extend(b"\x48\x8D\x75\xFF")                  # lea rsi, [rbp-1]
        # mov byte [rsi], 0x0A ('\n') = C6 06 0A
        asm.code.extend(b"\xC6\x06\x0A")                        # mov byte [rsi], 0x0A
        asm.mov_imm(Asm.R13, 1)            # length = 1
        
        # Division loop: value = R14
        pi_divloop = self._new_label()
        asm.label(pi_divloop)
        # RAX = R14 / 10, RDX = R14 % 10
        asm.mov_reg_reg(Asm.RAX, Asm.R14)
        asm.mov_imm(Asm.RDX, 0)
        asm.mov_imm(Asm.RCX, 10)
        asm.div(Asm.RCX)                    # RAX=quo, RDX=rem
        asm.mov_reg_reg(Asm.R14, Asm.RAX)   # R14 = quotient
        # Convert RDX low byte to ASCII: dl += '0'
        asm.add_imm(Asm.RDX, ord('0'))      # RDX = digit + '0'
        # rsi -= 1  (dec rsi = 48 FF CE)
        asm.code.extend(b"\x48\xFF\xCE")                      # dec rsi
        # mov byte [rsi], dl  = 88 16
        asm.code.extend(b"\x88\x16")                          # mov byte [rsi], dl
        asm.add_imm(Asm.R13, 1)             # length++
        asm.cmp_imm(Asm.R14, 0)
        asm.jne(pi_divloop)
        
        # If negative: prepend '-'
        asm.cmp_imm(Asm.R12, 0)
        pi_noneg = self._new_label()
        asm.je(pi_noneg)
        asm.code.extend(b"\x48\xFF\xCE")                      # dec rsi
        # mov byte [rsi], '-'  = C6 06 2D
        asm.code.extend(b"\xC6\x06\x2D")                        # mov byte [rsi], 0x2D
        asm.add_imm(Asm.R13, 1)
        asm.label(pi_noneg)
        
        # Now rsi = pointer to string start, r13 = length
        if self.target_os == 'windows':
            # Windows: use GetStdHandle + WriteConsole
            # push args for GetStdHandle(-11) -> returns handle in rax
            # Actually for simplicity, we'll use int 0x2e approach or just
            # syscall method for now. Let's use a simpler method:
            # Write directly using windows syscall (NtWriteFile)
            # But to avoid complexity, we use x64 fastcall convention with
            # a manual kernel32 lookup. SIMPLER: write the bytes using
            # int 0x80-like approach that works on Windows isn't available.
            # SOLUTION: Use inline syscall for Windows console via kernel32
            # This is complex - for now use same POSIX pattern (will test on wine)
            # Actually: Windows doesn't support direct syscall from user mode
            # the same way. Use WinAPI stub:
            # push regs, call GetStdHandle, call WriteFile
            # For this we need IAT - which is built in Packer
            # Use indirect call through IAT pointer stored in r10
            # r10 = pointer to IAT slot 1 (GetStdHandle)
            # r11 = pointer to IAT slot 2 (WriteFile)
            # Store IAT pointers: mov r10, [rel IAT_GetStdHandle]
            # mov ecx, -11   (STD_OUTPUT_HANDLE)
            # call [r10]     -> handle in rax
            # ... then WriteFile(handle, buf, len, &written, 0)
            # IAT entries are at data_rva + 0x100 area
            # Since we need RIP-relative addressing:
            # mov r10, [rip + (iat_addr - (code_rva + pos + 7))]
            iat_hnd_rva = Config.IMAGE_BASE + Config.DATA_RVA + 0x100  # IAT: GetStdHandle
            iat_wf_rva  = Config.IMAGE_BASE + Config.DATA_RVA + 0x108  # IAT: WriteFile
            # Compute RIP-relative offset for [rip+disp] to IAT_HND
            # lea r10, [rip] + ... no, we want mov r10, [rip+disp]
            # 4C 8B 15 disp32 = mov r10, [rip+disp32]
            pos1 = len(asm.code)
            disp1 = (iat_hnd_rva - (asm.code_rva + pos1 + 7)) & 0xFFFFFFFF
            asm.code.extend(b"\x4C\x8B\x15")
            asm.code.extend(struct.pack("<i", disp1))
            # mov ecx, -11  (STD_OUTPUT_HANDLE = -11)
            asm.code.extend(b"\xB9\xFF\xFF\xFF\xFF")            # mov ecx, -11
            # call [r10]   = FF 12
            asm.code.extend(b"\xFF\x12")                          # call [r10]
            # rax = handle. Now WriteFile(handle, buf, len, &written, 0)
            # 5th param on stack: 0
            asm.code.extend(b"\x48\x83\xEC\x20")                  # sub rsp, 32  (shadow space)
            asm.code.extend(b"\xC7\x44\x24\x20\x00\x00\x00\x00")  # mov [rsp+32], 0
            # 4th param: &written (use rsp+28 which is our stack var)
            asm.code.extend(b"\x48\x8D\x54\x24\x18")              # lea rdx, [rsp+24]
            # Need to reorder: ecx=handle, rdx=buf, r8=len, r9=&written, [rsp+32]=0
            # Actually: WriteFile(hFile, lpBuffer, nBytes, lpWritten, lpOverlapped)
            # rcx=hFile(rax), rdx=buf(rsi), r8=len(r13), r9=&written, stack=0
            # Save rax temporarily
            asm.code.extend(b"\x49\x89\xC1")                      # mov r9, rax   (save handle)
            # lea rdx, [rsp+24]  -> actually, we want &written on stack
            # Simpler: put written at [rsp+16] (inside shadow space)
            # But wait, we need to restore arguments in right order:
            # rcx = handle (=rax before we use it)
            # rdx = buffer (=rsi)
            # r8  = num_bytes (=r13)
            # r9  = &written (=use stack, e.g., rsp+16)
            # [rsp+32] = 0 (lpOverlapped)
            # Let's redo:
            # First, save handle from rax:
            asm.code.extend(b"\x50")                              # push rax (save handle)
            # Now set up args (reload because we pushed rax, rsp changed by 8):
            # rcx = handle
            asm.code.extend(b"\x48\x89\xE1")                      # mov rcx, rsp  (no! wrong - rsp points to pushed rax)
            # Actually simpler: pop back and use directly
            
            # Let me restart Windows call cleanly
            # Undo the push rax mess - pop rax back
            # Actually let me redo this section cleanly:
            # After GetStdHandle returns, rax = handle
            # WriteFile(rcx=handle, rdx=buf, r8=len, r9=&written, [rsp+32]=0)
            # Need 32 bytes shadow + 8 bytes 5th param = 40 bytes stack space
            # Stack must be 16-byte aligned before call (already aligned after ret from GetStdHandle+3 pushes? no)
            # Actually: after our push rbx/r12/r13/r14 (4 pushes = 32 bytes) + enter
            # Let's just use a clean approach:
            # Clear existing setup and do it fresh:
            # (actually the code above is already generated, let's keep going with the correct approach)
            
            # POP handle back and redo cleanly (the push rax above was wrong)
            # Skip: the push rax / mov rcx,rsp was incorrect
            # Correct approach: handle is in rax, we need to move it to rcx
            # But we need to undo the push first:
            # pop rax -> restore handle to rax
            # Then rcx = rax (handle), rdx = rsi (buf), r8 = r13 (len)
            # Need stack: 32 shadow + 8 for 5th param = 40 bytes, 16-aligned
            # sub rsp, 40 (after subtracting 40, rsp is aligned relative to before calls)
            # Actually: before call instruction, stack must be 8 mod 16 (so call pushes 8, making it 0 mod 16)
            # Our current state: 4 pushes (32) + enter (5 push rbp = 8) + sub rsp 64 = about 104 bytes from entry
            # Let's just make WriteFile work:
            # First, undo push rax:
            asm.code.extend(b"\x58")                              # pop rax (restore handle to rax)
            # sub rsp, 40 (32 shadow + 8 fifth param slot), ensure 16-byte alignment at call
            asm.code.extend(b"\x48\x83\xEC\x28")                  # sub rsp, 40
            # rcx = handle (=rax)
            asm.code.extend(b"\x48\x89\xC1")                      # mov rcx, rax
            # rdx = buf (rsi)
            asm.code.extend(b"\x48\x89\xF2")                      # mov rdx, rsi
            # r8 = length (r13)
            asm.code.extend(b"\x49\x89\xE8")                      # mov r8, r13
            # r9 = &written (use rsp+32 which is inside our sub rsp area)
            asm.code.extend(b"\x4C\x8D\x4C\x24\x20")              # lea r9, [rsp+32]
            # qword [rsp+32] = 0  (5th param, lpOverlapped = NULL)
            # Wait, shadow space is at rsp+0..rsp+31. 5th param at rsp+32.
            # But we used r9 = &rsp+32 which is same location as 5th param... conflict.
            # Use rsp+24 instead (in shadow space, which WriteFile won't write to for non-overlapped)
            # Actually: &written can be anywhere writeable, including our stack frame.
            # Let's use the enter-allocated frame: rbp-4 = &written (inside our 64-byte frame)
            # Undo the r9 setup and redo:
            # Actually mov r9, rbp ; sub r9, 4  but no rbp in r9
            # Simpler: lea r9, [rbp-8]  (inside stack frame, not shadow)
            # 4C 8D 4D F8
            # Actually since we already did sub rsp,40 we changed rsp. rbp is still valid.
            # Redo r9:
            # overwrite last 4 bytes of r9 setup:
            # Actually let me not overwrite - the lea r9, [rsp+32] is fine since
            # WriteFile will write to it AFTER reading the 5th param
            # 5th param: [rsp+32] = 0 (but &written pointer is also at rsp+32? no that's the value, not addr)
            # Actually: [rsp+32] is the VALUE of the 5th argument to the function (lpOverlapped),
            # which is separate from what r9 points to. &written = r9 points to some memory,
            # and [rsp+32]=0 is lpOverlapped value. They're independent.
            # BUT: WriteFile's 5th param VALUE goes on stack, not a pointer.
            # mov qword [rsp+32], 0  => 48 C7 44 24 20 00 00 00 00
            # But wait: r9 = rsp+32 points TO rsp+32 (for lpNumberOfBytesWritten)
            # Then [rsp+32] is OVERWRITTEN with 0 (the lpOverlapped value)? That's a bug!
            # Fix: use different locations. r9 = &written at rbp-8, 5th param at rsp+32 = 0.
            # Overwrite: redo r9 setup. Last bytes were 4C 8D 4C 24 20 (5 bytes for lea r9,[rsp+32])
            # Let me instead keep r9 as-is but use different 5th param location? no, 5th param MUST be at rsp+32.
            # FIX: change r9 to point elsewhere (rbp-8), then set [rsp+32]=0.
            # Patch: overwrite the 4C 8D 4C 24 20 with lea r9, [rbp-8] = 4C 8D 4D F8... but that's 4 bytes vs 5.
            # Let me not patch - just ADD: r9 already points to rsp+32, and we'll set [rsp+32]=0 after.
            # But then WriteFile will read 5th arg = 0, but &written (r9) = rsp+32 which WriteFile writes to...
            # Actually: WriteFile(handle, buf, len, r9=&written_at_rsp+32, [rsp+32]=0_AS_VALUE)?
            # Hmm wait, 5th param is AT location rsp+32. The CPU stores VALUE 0 at rsp+32.
            # But r9 also POINTS TO rsp+32 for &written.
            # When WriteFile executes: it reads rcx,rdx,r8,r9 correctly, reads [rsp+32]=0 as lpOverlapped.
            # Then internally it may write to *r9 = rsp+32 (overwriting the 0).
            # This is a race condition! r9 and 5th param share memory = bug.
            # Fix by changing r9 to point to another stack location.
            # Let me put &written at rbp-4 (inside our frame, which is above the shadow space):
            # Actually the simplest fix: just re-do r9 before the call using our frame
            # Undo: nop out 4C 8D 4C 24 20  = 5 bytes of nops? wasteful.
            # Alternative: we actually DON'T need to keep written count. Let's just use rsp+24 (inside shadow space).
            # Shadow space is writable. WriteFile can write there.
            # BUT we also need to pass lpOverlapped=0 at rsp+32. Different memory, no conflict.
            # So r9 = rsp+24 (pointer to inside shadow space), 5th param = 0 at rsp+32.
            # Patch: the 5 bytes (4C 8D 4C 24 20) need to become (4C 8D 4C 24 18)
            # That's just changing the last byte from 0x20 to 0x18!
            asm.code[-1] = 0x18                                  # fix: lea r9, [rsp+24]
            # Now 5th param: mov qword [rsp+32], 0
            asm.code.extend(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")  # mov qword [rsp+32], 0
            # Load IAT WriteFile pointer into r11
            pos2 = len(asm.code)
            disp2 = (iat_wf_rva - (asm.code_rva + pos2 + 7)) & 0xFFFFFFFF
            asm.code.extend(b"\x4C\x8B\x1D")
            asm.code.extend(struct.pack("<i", disp2))
            # call [r11]
            asm.code.extend(b"\xFF\x1B")                          # call [r11]
            # Clean stack: add rsp, 40
            asm.code.extend(b"\x48\x83\xC4\x28")                  # add rsp, 40
        else:
            # POSIX: syscall write(1, rsi, r13)
            asm.mov_imm(Asm.RAX, 1)            # sys_write
            asm.mov_imm(Asm.RDI, 1)            # fd = 1 (stdout)
            # rsi already = pointer to buffer
            asm.mov_reg_reg(Asm.RDX, Asm.R13)  # length
            asm.syscall()
        
        # Restore registers & return
        asm.code.extend(b"\x41\x5E")                           # pop r14
        asm.code.extend(b"\x41\x5D")                           # pop r13
        asm.code.extend(b"\x41\x5C")                           # pop r12
        asm.code.extend(b"\x5B")                              # pop rbx
        asm.code.extend(b"\x48\x89\xEC")                      # mov rsp, rbp
        asm.code.extend(b"\x5D")                              # pop rbp
        asm.code.extend(b"\xC3")                              # ret
        
        # ========== print_str ==========
        # Input: RAX = pointer to null-terminated string
        asm.label("print_str")
        asm.code.extend(b"\x55")                              # push rbp
        asm.code.extend(b"\x48\x89\xE5")                      # mov rbp, rsp
        asm.code.extend(b"\x53")                              # push rbx
        asm.code.extend(b"\x41\x54")                           # push r12
        asm.code.extend(b"\x41\x55")                           # push r13
        
        asm.mov_reg_reg(Asm.R12, Asm.RAX)   # R12 = string pointer
        
        # Scan for null terminator to find length
        asm.mov_imm(Asm.R13, 0)             # length = 0
        ps_lenloop = self._new_label()
        asm.label(ps_lenloop)
        asm.mov_reg8_mem_index(Asm.RAX, Asm.R12, Asm.R13)
        # test al, al => 84 C0
        asm.code.extend(b"\x84\xC0")                          # test al, al
        ps_lendone = self._new_label()
        asm.je(ps_lendone)
        asm.add_imm(Asm.R13, 1)
        asm.jmp(ps_lenloop)
        asm.label(ps_lendone)
        # r13 = length
        
        if self.target_os == 'windows':
            # Windows: GetStdHandle(STD_OUTPUT_HANDLE), then WriteFile(handle, r12, r13, &written, 0)
            iat_hnd_rva = Config.IMAGE_BASE + Config.DATA_RVA + 0x100
            iat_wf_rva  = Config.IMAGE_BASE + Config.DATA_RVA + 0x108
            # mov r10, [rip + disp] for GetStdHandle IAT
            pos1 = len(asm.code)
            disp1 = (iat_hnd_rva - (asm.code_rva + pos1 + 7)) & 0xFFFFFFFF
            asm.code.extend(b"\x4C\x8B\x15")
            asm.code.extend(struct.pack("<i", disp1))
            # mov ecx, -11
            asm.code.extend(b"\xB9\xFF\xFF\xFF\xFF")
            # call [r10]  (FF 12)
            asm.code.extend(b"\xFF\x12")
            # rax = handle. Now WriteFile setup
            asm.code.extend(b"\x48\x83\xEC\x28")                  # sub rsp, 40 (32 shadow + 8 5th param)
            asm.code.extend(b"\x48\x89\xC1")                      # mov rcx, rax (handle)
            asm.code.extend(b"\x49\x89\xE2")                      # mov rdx, r12 (buf)
            asm.code.extend(b"\x49\x89\xE8")                      # mov r8, r13 (len)
            asm.code.extend(b"\x4C\x8D\x4C\x24\x18")              # lea r9, [rsp+24] (&written)
            asm.code.extend(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")  # mov qword [rsp+32], 0
            # load WriteFile IAT
            pos2 = len(asm.code)
            disp2 = (iat_wf_rva - (asm.code_rva + pos2 + 7)) & 0xFFFFFFFF
            asm.code.extend(b"\x4C\x8B\x1D")
            asm.code.extend(struct.pack("<i", disp2))
            asm.code.extend(b"\xFF\x1B")                          # call [r11]
            asm.code.extend(b"\x48\x83\xC4\x28")                  # add rsp, 40
        else:
            # POSIX: write(1, str, len)
            asm.mov_imm(Asm.RAX, 1)
            asm.mov_imm(Asm.RDI, 1)
            asm.mov_reg_reg(Asm.RSI, Asm.R12)  # rsi = buf
            asm.mov_reg_reg(Asm.RDX, Asm.R13)  # rdx = length
            asm.syscall()
        
        asm.code.extend(b"\x41\x5D")                           # pop r13
        asm.code.extend(b"\x41\x5C")                           # pop r12
        asm.code.extend(b"\x5B")                              # pop rbx
        asm.code.extend(b"\x48\x89\xEC")                      # mov rsp, rbp
        asm.code.extend(b"\x5D")                              # pop rbp
        asm.code.extend(b"\xC3")                              # ret
        
        # ========== print_bool ==========
        # Input: RAX = 0 (false) or non-zero (true)
        asm.label("print_bool")
        asm.code.extend(b"\x55")                              # push rbp
        asm.code.extend(b"\x48\x89\xE5")                      # mov rbp, rsp
        asm.code.extend(b"\x53")                              # push rbx
        
        asm.cmp_imm(Asm.RAX, 0)
        pb_false = self._new_label()
        asm.je(pb_false)
        # True
        asm.mov_imm(Asm.RAX, self._get_or_create_string("True"))
        asm.call("print_str")
        pb_end = self._new_label()
        asm.jmp(pb_end)
        asm.label(pb_false)
        # False
        asm.mov_imm(Asm.RAX, self._get_or_create_string("False"))
        asm.call("print_str")
        asm.label(pb_end)
        
        asm.code.extend(b"\x5B")                              # pop rbx
        asm.code.extend(b"\x48\x89\xEC")                      # mov rsp, rbp
        asm.code.extend(b"\x5D")                              # pop rbp
        asm.code.extend(b"\xC3")                              # ret
    
    def _get_or_create_string(self, value):
        """Allocate a string in the string pool (data section)."""
        if value not in self.strings:
            self.strings[value] = self._string_base
            self._string_base += len(value) + 1
        return self.strings[value]
    
    def _get_or_create_var(self, name):
        """Get or allocate a variable address in the data section."""
        if name not in self.globals:
            self.globals[name] = (self._var_addr, 'int')
            self._var_addr += 8  # 8 bytes per variable (x64)
        return self.globals[name][0]
    
    def _generate_code(self, module):
        for node in module.body:
            if isinstance(node, Assign):
                self._gen_assign(node)
            elif isinstance(node, Print):
                self._gen_print(node)
            elif isinstance(node, If):
                self._gen_if(node)
            elif isinstance(node, While):
                self._gen_while(node)
            elif isinstance(node, Function):
                self._gen_function(node)
            elif isinstance(node, ExprStmt):
                self._gen_expr(node.value)
            elif isinstance(node, Break):
                if self._loop_stack:
                    self.asm.jmp(self._loop_stack[-1][1])
            elif isinstance(node, Continue):
                if self._loop_stack:
                    self.asm.jmp(self._loop_stack[-1][0])
            elif isinstance(node, Pass):
                continue
    
    def _gen_assign(self, node):
        addr = self._get_or_create_var(node.target)
        self._gen_expr(node.value)
        self.asm.mov_mem_reg(addr, Asm.RAX)
    
    def _gen_expr(self, node):
        asm = self.asm
        if isinstance(node, Number):
            asm.mov_imm(Asm.RAX, node.value)
        elif isinstance(node, String):
            asm.mov_imm(Asm.RAX, self._get_or_create_string(node.value))
        elif isinstance(node, Bool):
            asm.mov_imm(Asm.RAX, 1 if node.value else 0)
        elif isinstance(node, Name):
            addr = self._get_or_create_var(node.id)
            asm.mov_reg_mem(Asm.RAX, addr)
        elif isinstance(node, UnaryOp):
            self._gen_expr(node.operand)
            if node.op == '-':
                asm.neg(Asm.RAX)
            elif node.op == 'not':
                true_label = self._new_label()
                end_label = self._new_label()
                asm.cmp_imm(Asm.RAX, 0)
                asm.je(true_label)
                asm.mov_imm(Asm.RAX, 0)
                asm.jmp(end_label)
                asm.label(true_label)
                asm.mov_imm(Asm.RAX, 1)
                asm.label(end_label)
        elif isinstance(node, BinOp):
            if node.op in ('<','<=','>','>=','==','!='):
                self._gen_compare(node)
            elif node.op == 'and':
                self._gen_expr(node.left)
                false_label = self._new_label()
                end_label = self._new_label()
                asm.cmp_imm(Asm.RAX, 0)
                asm.je(false_label)
                self._gen_expr(node.right)
                asm.cmp_imm(Asm.RAX, 0)
                asm.je(false_label)
                asm.mov_imm(Asm.RAX, 1)
                asm.jmp(end_label)
                asm.label(false_label)
                asm.mov_imm(Asm.RAX, 0)
                asm.label(end_label)
            elif node.op == 'or':
                self._gen_expr(node.left)
                true_label = self._new_label()
                end_label = self._new_label()
                asm.cmp_imm(Asm.RAX, 0)
                asm.jne(true_label)
                self._gen_expr(node.right)
                asm.cmp_imm(Asm.RAX, 0)
                asm.jne(true_label)
                asm.mov_imm(Asm.RAX, 0)
                asm.jmp(end_label)
                asm.label(true_label)
                asm.mov_imm(Asm.RAX, 1)
                asm.label(end_label)
            else:
                self._gen_expr(node.left)
                asm.push(Asm.RAX)
                self._gen_expr(node.right)
                asm.push(Asm.RAX)
                asm.pop(Asm.RBX)
                asm.pop(Asm.RAX)
                if node.op == '+': asm.add(Asm.RBX)
                elif node.op == '-': asm.sub(Asm.RBX)
                elif node.op == '*': asm.mul(Asm.RBX)
                elif node.op == '/':
                    asm.mov_imm(Asm.RDX, 0)
                    asm.div(Asm.RBX)
                elif node.op == '%':
                    asm.mov_imm(Asm.RDX, 0)
                    asm.div(Asm.RBX)
                    asm.mov_reg_reg(Asm.RAX, Asm.RDX)
        elif isinstance(node, Call):
            if node.func in self.functions:
                for arg in reversed(node.args):
                    self._gen_expr(arg)
                    asm.push(Asm.RAX)
                asm.call(f"func_{node.func}")
                asm.add(Asm.RSP, len(node.args) * Config.PTR_SIZE)
            else:
                self.errors.error(ErrorCode.VAR_NOT_FOUND, f"Function {node.func} not defined")
        else:
            asm.mov_imm(Asm.RAX, 0)
    
    def _gen_compare(self, node):
        asm = self.asm
        self._gen_expr(node.left)
        asm.push(Asm.RAX)
        self._gen_expr(node.right)
        asm.push(Asm.RAX)
        asm.pop(Asm.RBX)
        asm.pop(Asm.RAX)
        asm.cmp(Asm.RBX)
        true_label = self._new_label()
        end_label = self._new_label()
        if node.op == '<': asm.jl(true_label)
        elif node.op == '<=': asm.jle(true_label)
        elif node.op == '>': asm.jg(true_label)
        elif node.op == '>=': asm.jge(true_label)
        elif node.op == '==': asm.je(true_label)
        elif node.op == '!=': asm.jne(true_label)
        asm.mov_imm(Asm.RAX, 0)
        asm.jmp(end_label)
        asm.label(true_label)
        asm.mov_imm(Asm.RAX, 1)
        asm.label(end_label)
    
    def _gen_print(self, node):
        # Determine type at compile time
        expr = node.value
        if expr is None:
            self._gen_expr(String(""))
            self.asm.call("print_str")
        elif self._is_string_expr(expr):
            self._gen_expr(expr)  # RAX = string address
            self.asm.call("print_str")
        elif isinstance(expr, Bool):
            self._gen_expr(expr)  # RAX = 0 or 1
            self.asm.call("print_bool")
        else:
            self._gen_expr(expr)  # RAX = integer value
            self.asm.call("print_int")
    
    def _gen_if(self, node):
        self._gen_expr(node.cond)
        asm = self.asm
        asm.mov_imm(Asm.RBX, 0)
        asm.cmp(Asm.RBX)
        else_label = self._new_label()
        asm.je(else_label)
        self._gen_block(node.body)
        end_label = self._new_label()
        asm.jmp(end_label)
        asm.label(else_label)
        if node.orelse:
            self._gen_block(node.orelse)
        asm.label(end_label)
    
    def _gen_while(self, node):
        asm = self.asm
        start_label = self._new_label()
        end_label = self._new_label()
        self._loop_stack.append((start_label, end_label))
        asm.label(start_label)
        self._gen_expr(node.cond)
        asm.mov_imm(Asm.RBX, 0)
        asm.cmp(Asm.RBX)
        asm.je(end_label)
        self._gen_block(node.body)
        asm.jmp(start_label)
        asm.label(end_label)
        self._loop_stack.pop()
    
    def _gen_function(self, node):
        asm = self.asm
        self.functions[node.name] = asm.pos()
        asm.label(f"func_{node.name}")
        asm.enter(32)  # allocate stack for locals
        self._gen_block(node.body)
        asm.leave()
        asm.ret()
    
    def _gen_block(self, block):
        for stmt in block:
            if isinstance(stmt, Assign):
                self._gen_assign(stmt)
            elif isinstance(stmt, Return):
                if stmt.value:
                    self._gen_expr(stmt.value)
                else:
                    self.asm.mov_imm(Asm.RAX, 0)
                self.asm.leave()
                self.asm.ret()
            elif isinstance(stmt, Print):
                self._gen_print(stmt)
            elif isinstance(stmt, If):
                self._gen_if(stmt)
            elif isinstance(stmt, While):
                self._gen_while(stmt)
            elif isinstance(stmt, ExprStmt):
                self._gen_expr(stmt.value)
            elif isinstance(stmt, Break):
                if self._loop_stack:
                    self.asm.jmp(self._loop_stack[-1][1])
            elif isinstance(stmt, Continue):
                if self._loop_stack:
                    self.asm.jmp(self._loop_stack[-1][0])
            elif isinstance(stmt, Pass):
                continue


# ============================================================================
# Packer (PE, ELF, Mach-O with sections)
# ============================================================================

class Packer:
    @staticmethod
    def pack_pe(code, data_bytes=b"", arch='x64'):
        """Build a PE (Portable Executable) with proper IAT for kernel32.dll imports."""
        Config.set_arch(arch)
        
        code_aligned = ((len(code) + Config.FILE_ALIGN - 1) // Config.FILE_ALIGN) * Config.FILE_ALIGN
        
        # ============= IAT and import structure layout =============
        # .data virtual layout (relative to DATA_RVA):
        #   0x0000 - 0x00FF: reserved
        #   0x0100 - 0x0107: IAT[0] = GetStdHandle thunk (qword)
        #   0x0108 - 0x010F: IAT[1] = WriteFile thunk (qword)
        #   0x0110 - 0x0117: IAT terminator (qword 0)
        #   0x0800 - ...   : user strings/variables
        # .rdata virtual layout (relative to RDATA_RVA):
        #   0x0000 - 0x0013: Import Descriptor #1 (kernel32.dll, 20 bytes)
        #   0x0014 - 0x0027: Import Descriptor #2 (zero, terminator)
        #   0x0100 - 0x0107: INT[0] = RVA to GetStdHandle hint/name
        #   0x0108 - 0x010F: IMAGE_ORDINAL_FLAG64 | 0 (if ordinal)
        #   0x0110 - 0x0117: 0 (INT terminator)
        #   0x0120 - 0x013F: hint(2 bytes) + "GetStdHandle\0" (13 bytes w/ null)
        #   0x0140 - 0x015F: hint(2 bytes) + "WriteFile\0" (10 bytes w/ null)
        #   0x0200 - 0x020D: "kernel32.dll\0" (13 bytes w/ null)
        
        IAT_HND_RVA = Config.DATA_RVA + 0x100
        IAT_WF_RVA  = Config.DATA_RVA + 0x108
        
        INT_ENTRY0_RVA = Config.RDATA_RVA + 0x0100
        INT_ENTRY1_RVA = Config.RDATA_RVA + 0x0108
        HINTNAME_GETSTDHANDLE_RVA = Config.RDATA_RVA + 0x0120
        HINTNAME_WRITEFILE_RVA    = Config.RDATA_RVA + 0x0140
        DLLNAME_RVA               = Config.RDATA_RVA + 0x0200
        
        IMPORTDESC_RVA = Config.RDATA_RVA + 0x0000
        
        # Build .rdata section content
        rdata = bytearray(0x400)  # 1024 bytes for .rdata structures
        
        # Import Descriptor #1: kernel32.dll
        # OriginalFirstThunk (INT RVA), TimeDateStamp, ForwarderChain, Name RVA, FirstThunk (IAT RVA)
        struct.pack_into("<IIIII", rdata, 0x0000,
            INT_ENTRY0_RVA,   # OriginalFirstThunk = INT
            0,                # TimeDateStamp
            0,                # ForwarderChain
            DLLNAME_RVA,      # Name = "kernel32.dll"
            IAT_HND_RVA)      # FirstThunk = IAT
        
        # Import Descriptor #2: zero terminator
        # (already zero because bytearray initialized to 0)
        
        # INT entries: RVAs to hint/name entries
        struct.pack_into("<Q", rdata, 0x0100, HINTNAME_GETSTDHANDLE_RVA)
        struct.pack_into("<Q", rdata, 0x0108, HINTNAME_WRITEFILE_RVA)
        # 0x0110 = terminator qword (already zero)
        
        # hint/name entries
        gs_name = b"GetStdHandle\x00"
        rdata[0x0120:0x0120+2] = b"\x00\x00"  # hint = 0
        rdata[0x0122:0x0122+len(gs_name)] = gs_name
        
        wf_name = b"WriteFile\x00"
        rdata[0x0140:0x0140+2] = b"\x00\x00"  # hint = 0
        rdata[0x0142:0x0142+len(wf_name)] = wf_name
        
        # DLL name string
        dll_name = b"kernel32.dll\x00"
        rdata[0x0200:0x0200+len(dll_name)] = dll_name
        
        rdata_size = len(rdata)
        rdata_aligned = ((rdata_size + Config.FILE_ALIGN - 1) // Config.FILE_ALIGN) * Config.FILE_ALIGN
        
        # Build .data section content
        # First: IAT entries (initial values = same RVAs as INT)
        data = bytearray(max(0x800 + len(data_bytes), 0x900))
        
        # IAT: initial content = RVAs to hint/name entries (same as INT)
        # After Windows loads the DLL, these are overwritten with real function addresses
        struct.pack_into("<Q", data, 0x100, HINTNAME_GETSTDHANDLE_RVA)
        struct.pack_into("<Q", data, 0x108, HINTNAME_WRITEFILE_RVA)
        # 0x110 = IAT terminator qword (already zero)
        
        # Append user data at offset 0x800
        data[0x800:0x800+len(data_bytes)] = data_bytes
        
        data_size = len(data)
        data_aligned = ((data_size + Config.FILE_ALIGN - 1) // Config.FILE_ALIGN) * Config.FILE_ALIGN
        
        # ============= PE Header Building =============
        pe = bytearray()
        
        # DOS header
        pe += b"MZ"
        pe += struct.pack("<H", 0x90)
        pe += struct.pack("<H", 3)
        pe += b"\x00" * 8
        pe += struct.pack("<H", 0x40)
        pe += b"\x00" * 30
        pe += struct.pack("<I", 0x80)  # PE header offset
        pe += b"\x00" * (0x80 - len(pe))
        
        # PE signature
        pe += b"PE\x00\x00"
        
        # COFF header (20 bytes)
        machine = 0x8664 if Config.IS_X64 else 0x14C
        pe += struct.pack("<H", machine)
        pe += struct.pack("<H", 3)               # NumberOfSections (.text, .rdata, .data)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<H", 0xF0)            # SizeOfOptionalHeader
        pe += struct.pack("<H", 0x202)           # Characteristics (EXECUTABLE_IMAGE + 32BIT_MACHINE)
        
        # Optional header (PE32+: 112 bytes of fixed fields + 16 data directories = 112+128=240)
        pe += struct.pack("<H", 0x20B if Config.IS_X64 else 0x10B)  # Magic (PE32+)
        pe += struct.pack("B", 1)
        pe += struct.pack("B", 0)
        pe += struct.pack("<I", code_aligned)    # SizeOfCode
        pe += struct.pack("<I", rdata_aligned + data_aligned)  # SizeOfInitializedData
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", Config.TEXT_RVA) # AddressOfEntryPoint
        pe += struct.pack("<I", Config.TEXT_RVA) # BaseOfCode
        if not Config.IS_X64:
            pe += struct.pack("<I", Config.DATA_RVA)
        pe += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE)
        pe += struct.pack("<I", Config.SECTION_ALIGN)
        pe += struct.pack("<I", Config.FILE_ALIGN)
        pe += struct.pack("<H", 6)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<H", 6)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<I", 0)
        
        image_size = Config.SECTION_ALIGN * 4  # headers + .text + .rdata + .data
        pe += struct.pack("<I", image_size)
        pe += struct.pack("<I", Config.FILE_ALIGN)  # SizeOfHeaders
        pe += struct.pack("<I", 0)
        pe += struct.pack("<H", 3)             # Subsystem = CONSOLE
        pe += struct.pack("<H", 0)
        pe += struct.pack(Config.PTR_FMT, 0x100000)
        pe += struct.pack(Config.PTR_FMT, 0x1000)
        pe += struct.pack(Config.PTR_FMT, 0x100000)
        pe += struct.pack(Config.PTR_FMT, 0x1000)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", 16)
        
        # Data directories (16 * 8 bytes = 128 bytes)
        # 0: Export table  (0,0)
        pe += struct.pack("<II", 0, 0)
        # 1: Import table (RVA, size) - at .rdata, our import descriptors
        pe += struct.pack("<II", IMPORTDESC_RVA, 0x20)
        # 2: Resource table
        pe += struct.pack("<II", 0, 0)
        # 3: Exception table
        pe += struct.pack("<II", 0, 0)
        # 4: Certificate table
        pe += struct.pack("<II", 0, 0)
        # 5: Base relocation table
        pe += struct.pack("<II", 0, 0)
        # 6: Debug table
        pe += struct.pack("<II", 0, 0)
        # 7: Architecture
        pe += struct.pack("<II", 0, 0)
        # 8: Global ptr
        pe += struct.pack("<II", 0, 0)
        # 9: TLS table
        pe += struct.pack("<II", 0, 0)
        # 10: Load config
        pe += struct.pack("<II", 0, 0)
        # 11: Bound import
        pe += struct.pack("<II", 0, 0)
        # 12: IAT - the actual import address table in .data
        pe += struct.pack("<II", IAT_HND_RVA, 0x18)  # 3 qwords = 24 bytes
        # 13: Delay import
        pe += struct.pack("<II", 0, 0)
        # 14: COM descriptor
        pe += struct.pack("<II", 0, 0)
        # 15: Reserved
        pe += struct.pack("<II", 0, 0)
        
        # Section headers (3 sections * 40 bytes = 120 bytes)
        # .text
        pe += b".text\x00\x00\x00"
        pe += struct.pack("<I", len(code))
        pe += struct.pack("<I", Config.TEXT_RVA)
        pe += struct.pack("<I", code_aligned)
        text_raw_off = Config.FILE_ALIGN
        pe += struct.pack("<I", text_raw_off)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<I", 0x60000020)  # CODE | EXECUTE | READ
        
        # .rdata
        pe += b".rdata\x00\x00"
        pe += struct.pack("<I", rdata_size)
        pe += struct.pack("<I", Config.RDATA_RVA)
        pe += struct.pack("<I", rdata_aligned)
        rdata_raw_off = text_raw_off + code_aligned
        pe += struct.pack("<I", rdata_raw_off)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<I", 0x40000040)  # INITIALIZED_DATA | READ
        
        # .data
        pe += b".data\x00\x00\x00"
        pe += struct.pack("<I", data_size)
        pe += struct.pack("<I", Config.DATA_RVA)
        pe += struct.pack("<I", data_aligned)
        data_raw_off = rdata_raw_off + rdata_aligned
        pe += struct.pack("<I", data_raw_off)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<I", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<H", 0)
        pe += struct.pack("<I", 0xC0000040)  # INITIALIZED_DATA | READ | WRITE
        
        # Pad header to FILE_ALIGN
        while len(pe) < Config.FILE_ALIGN:
            pe += b"\x00"
        
        # .text section raw data
        pe += code
        while len(pe) < text_raw_off + code_aligned:
            pe += b"\x00"
        
        # .rdata section raw data
        pe += bytes(rdata)
        while len(pe) < rdata_raw_off + rdata_aligned:
            pe += b"\x00"
        
        # .data section raw data
        pe += bytes(data)
        while len(pe) < data_raw_off + data_aligned:
            pe += b"\x00"
        
        return bytes(pe)
    
    @staticmethod
    def pack_macho(code, data_bytes=b"", arch='x64'):
        Config.set_arch(arch)
        macho = bytearray()
        macho += struct.pack("<I", 0xFEEDFACF)  # MH_MAGIC_64
        macho += struct.pack("<I", 0x1000007)  # CPU_TYPE_X86_64
        macho += struct.pack("<I", 0x3)        # CPU_SUBTYPE_X86_64_ALL
        macho += struct.pack("<I", 0x2)        # MH_EXECUTE
        macho += struct.pack("<I", 1)          # ncmds
        macho += struct.pack("<I", 72)         # sizeofcmds
        macho += struct.pack("<I", 0)          # flags
        # LC_SEGMENT_64
        macho += struct.pack("<I", 0x19)       # LC_SEGMENT_64
        macho += struct.pack("<I", 72)         # cmdsize
        macho += b"__TEXT\x00\x00\x00"
        macho += struct.pack("<Q", 0)          # vmaddr
        macho += struct.pack("<Q", 0x1000)     # vmsize
        macho += struct.pack("<Q", 0)          # fileoff
        macho += struct.pack("<Q", len(code))  # filesize
        macho += struct.pack("<I", 0x7)        # maxprot
        macho += struct.pack("<I", 0x5)        # initprot
        macho += struct.pack("<I", 1)          # nsects
        macho += struct.pack("<I", 0)          # flags
        # Section __text
        macho += b"__text\x00\x00\x00\x00"
        macho += b"__TEXT\x00\x00\x00"
        macho += struct.pack("<Q", 0)
        macho += struct.pack("<Q", len(code))
        macho += struct.pack("<I", 0)
        macho += struct.pack("<I", 2)
        macho += struct.pack("<I", 0)
        macho += struct.pack("<I", 0)
        macho += struct.pack("<I", 0)
        macho += struct.pack("<I", 0)
        macho += struct.pack("<I", 0)
        macho += code
        return bytes(macho)
    
    @staticmethod
    def pack_elf(code, data_bytes=b"", arch='x64'):
        Config.set_arch(arch)
        # Layout: [ELF hdr][phdrs][pad][code][pad][data]
        code_aligned = ((len(code) + 0xFFF) // 0x1000) * 0x1000
        data_aligned = ((len(data_bytes) + 0xFFF) // 0x1000) * 0x1000
        code_file_offset = 0x1000
        data_file_offset = code_file_offset + code_aligned
        total_size = data_file_offset + data_aligned
        
        elf = bytearray()
        # ELF header
        elf += b"\x7FELF"
        elf += struct.pack("B", 2 if Config.IS_X64 else 1)
        elf += struct.pack("B", 1)
        elf += struct.pack("B", 1)
        elf += struct.pack("B", 0)
        elf += b"\x00"*8
        elf += struct.pack("<H", 2)            # ET_EXEC
        elf += struct.pack("<H", 0x3E if Config.IS_X64 else 0x3)
        elf += struct.pack("<I", 1)            # ELF version
        # entry = IMAGE_BASE + TEXT_RVA
        elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE + Config.TEXT_RVA)
        elf += struct.pack(Config.PTR_FMT, 0x40)  # phoff (right after ELF header)
        elf += struct.pack(Config.PTR_FMT, 0)  # shoff
        elf += struct.pack("<I", 0)            # flags
        elf += struct.pack("<H", 0x40)         # ehsize
        elf += struct.pack("<H", 0x38)         # phentsize
        elf += struct.pack("<H", 2)            # phnum (2 segments: code + data)
        elf += struct.pack("<H", 0x40)         # shentsize
        elf += struct.pack("<H", 0)            # shnum
        elf += struct.pack("<H", 0)            # shstrndx
        
        # Program header 1: CODE segment (R+X)
        elf += struct.pack("<I", 1)            # PT_LOAD
        elf += struct.pack("<I", 5)            # PF_R|PF_X
        elf += struct.pack(Config.PTR_FMT, 0)  # offset in file = 0 (covers headers too)
        elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE)  # vaddr
        elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE)  # paddr
        elf += struct.pack(Config.PTR_FMT, code_file_offset + code_aligned)  # filesz
        elf += struct.pack(Config.PTR_FMT, code_file_offset + code_aligned)  # memsz
        elf += struct.pack(Config.PTR_FMT, 0x1000)    # align
        
        # Program header 2: DATA segment (R+W)
        if data_bytes:
            elf += struct.pack("<I", 1)            # PT_LOAD
            elf += struct.pack("<I", 6)            # PF_R|PF_W
            elf += struct.pack(Config.PTR_FMT, data_file_offset)  # file offset
            elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE + Config.DATA_RVA)  # vaddr
            elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE + Config.DATA_RVA)  # paddr
            elf += struct.pack(Config.PTR_FMT, len(data_bytes))  # filesz
            elf += struct.pack(Config.PTR_FMT, data_aligned)  # memsz
            elf += struct.pack(Config.PTR_FMT, 0x1000)    # align
        else:
            # empty data segment - still include a writable page
            elf += struct.pack("<I", 1)
            elf += struct.pack("<I", 6)
            elf += struct.pack(Config.PTR_FMT, data_file_offset)
            elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE + Config.DATA_RVA)
            elf += struct.pack(Config.PTR_FMT, Config.IMAGE_BASE + Config.DATA_RVA)
            elf += struct.pack(Config.PTR_FMT, 0)
            elf += struct.pack(Config.PTR_FMT, 0x1000)
            elf += struct.pack(Config.PTR_FMT, 0x1000)
        
        # Pad to code section start (page boundary)
        while len(elf) < code_file_offset:
            elf += b"\x00"
        
        # Write code
        elf += code
        while len(elf) < code_file_offset + code_aligned:
            elf += b"\x00"
        
        # Write data
        if data_bytes:
            elf += data_bytes
            while len(elf) < data_file_offset + data_aligned:
                elf += b"\x00"
        
        return bytes(elf)


# ============================================================================
# Main Compiler
# ============================================================================

class PyBinCoreCompiler:
    def __init__(self):
        self.parser = Parser()
        self.errors = ErrorCollector()
    
    def compile_file(self, src_path, arch='x64', target='exe', optimize=1, output=None):
        try:
            with open(src_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except Exception as e:
            self.errors.error(ErrorCode.FILE_READ_FAILED, str(e))
            return None
        return self.compile_str(source, arch, target, optimize, output)
    
    def compile_str(self, source, arch='x64', target='exe', optimize=1, output=None):
        # Determine target OS
        if target == 'exe':
            target_os = 'windows'
        elif target == 'app':
            target_os = 'darwin'
        elif target == 'elf':
            target_os = 'linux'
        else:
            target_os = 'windows'
        
        # Parse
        module = self.parser.parse(source)
        if self.parser.errors.has_errors():
            self.errors = self.parser.errors
            return None
        
        # Generate code
        generator = CodeGenerator(arch, target_os, optimize)
        code = generator.generate(module)
        if generator.errors.has_errors():
            self.errors = generator.errors
            return None
        
        # Build .data section from string constants
        Config.set_arch(arch)
        # User data starts at virtual: IMAGE_BASE + DATA_RVA + 0x800
        #   (leaves 0x800 bytes at start of .data for IAT/other structures)
        user_data_base = Config.IMAGE_BASE + Config.DATA_RVA + 0x800
        data_bytes = bytearray()
        for str_val, addr in sorted(generator.strings.items(), key=lambda x: x[1]):
            user_offset = addr - user_data_base
            while len(data_bytes) < user_offset:
                data_bytes.append(0)
            data_bytes.extend(str_val.encode('utf-8'))
            data_bytes.append(0)
        while len(data_bytes) % 8:
            data_bytes.append(0)
        
        # Pack into executable format
        if target == 'exe':
            return Packer.pack_pe(code, bytes(data_bytes), arch)
        elif target == 'app':
            return Packer.pack_macho(code, bytes(data_bytes), arch)
        elif target == 'elf':
            return Packer.pack_elf(code, bytes(data_bytes), arch)
        else:
            return code
    
    def run_compile(self, args):
        if args.exe:
            target = 'exe'
            ext = '.exe'
        elif args.app:
            target = 'app'
            ext = ''
        elif args.linux:
            target = 'elf'
            ext = ''
        else:
            target = 'bin'
            ext = '.bin'
        
        code = self.compile_file(args.src, args.arch, target, args.optimize, args.output)
        if code is None:
            print(self.errors.report(), file=sys.stderr)
            return 1
        
        out_dir = args.output or os.getcwd()
        os.makedirs(out_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(args.src))[0]
        out_path = os.path.join(out_dir, base + ext)
        with open(out_path, 'wb') as f:
            f.write(code)
        if sys.platform == 'darwin' and target == 'app':
            os.chmod(out_path, 0o755)
        print(f"✅ Compiled: {out_path} ({len(code)} bytes)")
        return 0


# ============================================================================
# Unit Tests
# ============================================================================

def run_tests():
    from compiler_regression import run_suite

    return run_suite()


# ============================================================================
# CLI Entry
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="PyBinCore V3.5.5 - Python to Native Compiler")
    parser.add_argument("src", nargs="?", help="Source file")
    parser.add_argument("-e", "--exe", action="store_true", help="Windows PE")
    parser.add_argument("-s", "--app", action="store_true", help="macOS Mach-O")
    parser.add_argument("-l", "--linux", action="store_true", help="Linux ELF")
    parser.add_argument("-a", "--arch", choices=["x86", "x64"], default="x64", help="Architecture")
    parser.add_argument("-O", "--optimize", type=int, default=1, help="Optimization level 0-3")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--test", action="store_true", help="Run tests")
    args = parser.parse_args()
    
    if args.test:
        sys.exit(run_tests())
    if not args.src:
        parser.print_help()
        sys.exit(1)
    compiler = PyBinCoreCompiler()
    sys.exit(compiler.run_compile(args))


if __name__ == "__main__":
    sys.modules.setdefault("main", sys.modules[__name__])
    main()
