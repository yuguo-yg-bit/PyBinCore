"""Formal regression suite for PyBinCore."""

from __future__ import annotations

import sys
import unittest

from compiler_contract import CompileError, ErrorCode, compile_source, parse_source
from compiler_fixtures import INVALID_SOURCES, VALID_SOURCES
from compiler_frontend import Assign, Function, If, Module, Parser
from main import Asm


class ParserRegressionTests(unittest.TestCase):
    def test_nested_blocks_parse(self):
        module = parse_source(VALID_SOURCES["nested_if"])
        self.assertIsInstance(module, Module)
        self.assertEqual(len(module.body), 1)
        outer_if = module.body[0]
        self.assertIsInstance(outer_if, If)
        self.assertEqual(len(outer_if.body), 1)
        self.assertIsInstance(outer_if.body[0], Assign)
        self.assertEqual(len(outer_if.orelse), 1)
        self.assertIsInstance(outer_if.orelse[0], Assign)

    def test_function_signature_parse(self):
        module = parse_source(VALID_SOURCES["function"])
        self.assertEqual(len(module.body), 1)
        func = module.body[0]
        self.assertIsInstance(func, Function)
        self.assertEqual(func.name, "add")
        self.assertEqual(func.args, ["a", "b"])

    def test_invalid_indentation_fails(self):
        with self.assertRaises(CompileError) as captured:
            parse_source(INVALID_SOURCES["indentation"])
        self.assertEqual(captured.exception.code, ErrorCode.SYNTAX_ERROR)

    def test_unterminated_string_fails(self):
        with self.assertRaises(CompileError) as captured:
            parse_source(INVALID_SOURCES["unterminated_string"])
        self.assertEqual(captured.exception.code, ErrorCode.SYNTAX_ERROR)


class SemanticRegressionTests(unittest.TestCase):
    def test_boolean_assignment_compiles(self):
        artifact, compiler = compile_source("flag = True", target="bin")
        self.assertIsNotNone(artifact)
        self.assertFalse(compiler.errors.has_errors())

    def test_undefined_call_is_reported(self):
        artifact, compiler = compile_source(INVALID_SOURCES["undefined_call"], target="bin")
        self.assertIsNone(artifact)
        self.assertTrue(compiler.errors.has_errors())
        code, message, line = compiler.errors.errors[0]
        self.assertEqual(code, ErrorCode.VAR_NOT_FOUND)
        self.assertIn("missing", message)
        self.assertEqual(line, 0)

    def test_while_break_compiles(self):
        artifact, compiler = compile_source(VALID_SOURCES["while_break"], target="bin")
        self.assertIsNotNone(artifact)
        self.assertFalse(compiler.errors.has_errors())


class ArtifactRegressionTests(unittest.TestCase):
    def test_pe_artifact_signature(self):
        artifact, _ = compile_source(VALID_SOURCES["assignment"], target="exe")
        self.assertIsNotNone(artifact)
        self.assertGreater(len(artifact), 0)
        self.assertEqual(artifact[:2], b"MZ")
        self.assertEqual(artifact[0x80:0x84], b"PE\x00\x00")

    def test_elf_artifact_signature(self):
        artifact, _ = compile_source(VALID_SOURCES["assignment"], target="elf")
        self.assertIsNotNone(artifact)
        self.assertGreater(len(artifact), 0)
        self.assertEqual(artifact[:4], b"\x7fELF")

    def test_macho_artifact_signature(self):
        artifact, _ = compile_source(VALID_SOURCES["assignment"], target="app")
        self.assertIsNotNone(artifact)
        self.assertGreater(len(artifact), 0)
        self.assertEqual(artifact[:4], b"\xcf\xfa\xed\xfe")


class ModuleBoundaryTests(unittest.TestCase):
    def test_frontend_module_exports_parser(self):
        from compiler_frontend import Parser as FrontendParser

        self.assertIs(FrontendParser, Parser)

    def test_backend_module_exports_compiler(self):
        from compiler_backend import PyBinCoreCompiler as BackendCompiler

        self.assertIsNotNone(BackendCompiler)


class AssemblerEncodingTests(unittest.TestCase):
    def test_rsp_byte_store_uses_sib(self):
        asm = Asm(is_x64=True)
        asm.mov_byte_mem_imm(Asm.RSP, 4, 0x41)
        self.assertEqual(asm.get_code(), bytes([0xC6, 0x44, 0x24, 0x04, 0x41]))

    def test_r12_byte_store_uses_sib(self):
        asm = Asm(is_x64=True)
        asm.mov_byte_mem_reg(Asm.R12, 8, 1)
        self.assertEqual(asm.get_code(), bytes([0x41, 0x88, 0x4C, 0x24, 0x08]))

    def test_r12_r13_byte_load_uses_sib(self):
        asm = Asm(is_x64=True)
        asm.mov_reg8_mem_index(Asm.RAX, Asm.R12, Asm.R13)
        self.assertEqual(asm.get_code(), bytes([0x43, 0x8A, 0x04, 0x2C]))


class SafetyRegressionTests(unittest.TestCase):
    def test_identifier_length_guard(self):
        long_name = "x" * 300
        with self.assertRaises(CompileError) as captured:
            parse_source(f"{long_name} = 1")
        self.assertEqual(captured.exception.code, ErrorCode.UNSUPPORTED)

    def test_string_length_guard(self):
        long_string = "a" * 40000
        with self.assertRaises(CompileError) as captured:
            parse_source(f's = "{long_string}"')
        self.assertEqual(captured.exception.code, ErrorCode.MEMORY_OVERFLOW)

    def test_function_argument_guard(self):
        args = ", ".join(f"a{i}" for i in range(20))
        with self.assertRaises(CompileError) as captured:
            parse_source(f"def f({args}):\n    return 1")
        self.assertEqual(captured.exception.code, ErrorCode.UNSUPPORTED)


def run_suite() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(run_suite())
