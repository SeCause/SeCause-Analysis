"""Conservative syntax checks for remediation snippets; never executes generated code.

Syntax validity does not prove that a fix is secure or compiles in the repository.
Unknown languages and incomplete snippets are omitted rather than guessed.
"""
import ast
import json
import re
from functools import lru_cache
from pathlib import PurePosixPath
from textwrap import dedent

import yaml
from tree_sitter import Language, Parser
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_typescript


LANGUAGES = {
    ".py": "python", ".java": "java", ".js": "javascript",
    ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".yaml": "yaml",
    ".yml": "yaml", ".json": "json",
}
ALIASES = {
    "py": "python", "python3": "python", "js": "javascript",
    "jsx": "javascript", "ts": "typescript", "yml": "yaml",
    "typescriptreact": "tsx", "javascriptreact": "javascript",
}


def target_language(file_path: str) -> str | None:
    return LANGUAGES.get(PurePosixPath(file_path).suffix.lower())


def canonical_language(language: str | None) -> str | None:
    value = (language or "").strip().lower()
    return ALIASES.get(value, value) or None


def normalize_code(value: str, language: str) -> str | None:
    code = dedent(value).strip()
    # Unwrap only a single complete fence. Prose around a fence is not extracted.
    if "```" in code:
        match = re.fullmatch(r"```([^\n`]*)\n(.*?)\n```", code, re.DOTALL)
        if not match:
            return None
        label = canonical_language(match[1])
        if label and label != language and not (language == "tsx" and label == "typescript"):
            return None
        code = dedent(match[2]).strip()
    if not code:
        return None
    return code if is_code(code, language) else None


def is_code(code: str, language: str) -> bool:
    try:
        if language == "python":
            tree = ast.parse(dedent(code))
            body = tree.body
            # Only the first string in a module/function/class body is a docstring.
            docstrings = {
                id(node.body[0])
                for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            }
            return any(id(node) not in docstrings for node in body) and all(
                not isinstance(node, ast.Expr)
                or id(node) in docstrings
                or isinstance(node.value, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom))
                for node in ast.walk(tree)
            )
        if language in {"yaml", "json"}:
            value = yaml.safe_load(code) if language == "yaml" else json.loads(code)
            return isinstance(value, (dict, list)) and bool(value)
        if language in {"java", "javascript", "typescript", "tsx"}:
            parser = _parser(language)
            if _valid_tree(parser.parse(code.encode()).root_node, language):
                return True
            if language == "java":
                # Java remediation often consists of method-body statements or members.
                for wrapped, method_body in (
                    (f"class Fix {{ void apply() {{\n{code}\n}} }}", True),
                    (f"class Fix {{\n{code}\n}}", False),
                ):
                    root = parser.parse(wrapped.encode()).root_node
                    if root.has_error:
                        continue
                    body = root.named_children[0].child_by_field_name("body")
                    if method_body:
                        body = body.named_children[0].child_by_field_name("body")
                    if _valid_tree(body):
                        return True
    except (SyntaxError, ValueError, yaml.YAMLError, RecursionError):
        return False
    return False


@lru_cache(maxsize=4)
def _parser(language: str) -> Parser:
    grammar = {
        "java": tree_sitter_java.language,
        "javascript": tree_sitter_javascript.language,
        "typescript": tree_sitter_typescript.language_typescript,
        "tsx": tree_sitter_typescript.language_tsx,
    }[language]
    return Parser(Language(grammar()))


def _valid_tree(root, language: str | None = None) -> bool:
    if root.has_error:
        return False
    # Recognize a directive prologue, ignoring comments, without counting it as code.
    directives = set()
    if language in {"javascript", "typescript", "tsx"}:
        for child in root.named_children:
            if child.type == "comment":
                continue
            if (child.type == "expression_statement" and child.named_children
                    and child.named_children[0].type == "string"
                    and child.named_children[0].text in {
                        b'"use client"', b"'use client'", b'"use server"', b"'use server'",
                        b'"use strict"', b"'use strict'",
                    }):
                directives.add((child.start_byte, child.end_byte))
            else:
                break
    meaningful = False
    stack = [root]
    while stack:
        node = stack.pop()
        if (node.start_byte, node.end_byte) in directives and node.type == "expression_statement":
            continue
        if node.type in {"expression_statement"}:
            expressions = node.named_children
            if not expressions or expressions[0].type in {
                "identifier", "string", "string_literal", "number", "true", "false",
                "null", "member_expression", "field_access",
            }:
                return False
        if (node.type.endswith("statement") and node.type not in {
            "empty_statement", "block", "expression_statement",
        }) or node.type in {
            "call_expression", "method_invocation", "assignment_expression",
            "local_variable_declaration", "lexical_declaration", "variable_declaration",
            "class_declaration", "function_declaration", "method_declaration",
            "import_statement", "import_declaration", "export_statement",
        }:
            meaningful = True
        stack.extend(node.named_children)
    return meaningful
