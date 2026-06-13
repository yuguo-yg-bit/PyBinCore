"""Stable compiler contract for external consumers and tests."""

from __future__ import annotations

from typing import Optional, Tuple

from compiler_backend import Config, ErrorCode, ErrorCollector, Packer, PyBinCoreCompiler
from compiler_frontend import (
    Assign,
    BinOp,
    Bool,
    Break,
    Call,
    CompileError,
    Continue,
    ExprStmt,
    Function,
    If,
    Module,
    Name,
    Number,
    Pass,
    Parser,
    Return,
    String,
    UnaryOp,
    While,
)


__all__ = [
    "Assign",
    "BinOp",
    "Bool",
    "Break",
    "Call",
    "CompileError",
    "Continue",
    "Config",
    "ErrorCode",
    "ErrorCollector",
    "ExprStmt",
    "Function",
    "If",
    "Module",
    "Name",
    "Number",
    "Pass",
    "Parser",
    "Packer",
    "PyBinCoreCompiler",
    "Return",
    "String",
    "UnaryOp",
    "While",
    "compile_source",
    "parse_source",
]


def parse_source(source: str) -> Module:
    """Parse source text into an AST module."""

    return Parser().parse(source)


def compile_source(
    source: str,
    *,
    arch: str = "x64",
    target: str = "exe",
    optimize: int = 1,
) -> Tuple[Optional[bytes], PyBinCoreCompiler]:
    """Compile source text and return the artifact together with the compiler."""

    compiler = PyBinCoreCompiler()
    artifact = compiler.compile_str(source, arch=arch, target=target, optimize=optimize)
    return artifact, compiler
