from __future__ import annotations

import logging
import multiprocessing as mp
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
import tree_sitter_go as tsgo
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjavascript
import tree_sitter_php as tsphp
import tree_sitter_python as tspython
import tree_sitter_ruby as tsruby
import tree_sitter_rust as tsrust
from tree_sitter import Language, Node, Parser

logger = logging.getLogger(__name__)

LANGUAGE_MAP = {
    ".py": Language(tspython.language()),
    ".js": Language(tsjavascript.language()),
    ".jsx": Language(tsjavascript.language()),
    ".ts": Language(tsjavascript.language()),
    ".tsx": Language(tsjavascript.language()),
    ".java": Language(tsjava.language()),
    ".go": Language(tsgo.language()),
    ".c": Language(tsc.language()),
    ".h": Language(tsc.language()),
    ".cpp": Language(tscpp.language()),
    ".hpp": Language(tscpp.language()),
    ".cc": Language(tscpp.language()),
    ".rs": Language(tsrust.language()),
    ".rb": Language(tsruby.language()),
    ".php": Language(tsphp.language_php()),
}


@dataclass
class ASTNode:
    node_type: str
    text: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    children: list[ASTNode] = field(default_factory=list)
    parent_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.node_type,
            "text": self.text[:200],
            "line": self.start_line,
            "end_line": self.end_line,
            "children": [c.to_dict() for c in self.children[:5]],
        }


@dataclass
class FunctionDef:
    name: str
    params: list[str]
    start_line: int
    end_line: int
    body: str
    calls: list[str] = field(default_factory=list)


@dataclass
class ImportStmt:
    module: str
    names: list[str]
    line: int


@dataclass
class ASTResult:
    file_path: str
    language: str
    functions: list[FunctionDef] = field(default_factory=list)
    imports: list[ImportStmt] = field(default_factory=list)
    assignments: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    strings: list[dict[str, Any]] = field(default_factory=list)
    decorators: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "functions": [
                {
                    "name": f.name,
                    "params": f.params,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "body": f.body,
                    "calls": f.calls,
                }
                for f in self.functions
            ],
            "imports": [{"module": i.module, "names": i.names, "line": i.line} for i in self.imports],
            "assignments": self.assignments,
            "calls": self.calls,
            "strings": self.strings,
            "decorators": self.decorators,
        }


def _dict_to_ast_result(data: dict[str, Any]) -> ASTResult:
    result = ASTResult(
        file_path=data.get("file_path", ""),
        language=data.get("language", ""),
        assignments=data.get("assignments", []),
        calls=data.get("calls", []),
        strings=data.get("strings", []),
        decorators=data.get("decorators", []),
    )
    for f in data.get("functions", []):
        result.functions.append(
            FunctionDef(
                name=f.get("name", ""),
                params=f.get("params", []),
                start_line=f.get("start_line", 0),
                end_line=f.get("end_line", 0),
                body=f.get("body", ""),
                calls=f.get("calls", []),
            )
        )
    for i in data.get("imports", []):
        result.imports.append(
            ImportStmt(
                module=i.get("module", ""),
                names=i.get("names", []),
                line=i.get("line", 0),
            )
        )
    return result


class ASTParser:
    # tree-sitter 是原生 C 扩展，畸形输入可能段错误。8KB 以上走子进程隔离，
    # 避免主扫描进程崩溃；8KB 以下进程内解析以保留吞吐（绝大多数源文件 < 8KB）。
    SUBPROCESS_SIZE_THRESHOLD = 8 * 1024

    def __init__(self):
        self._parsers: dict[str, Parser] = {}

    def _get_parser(self, ext: str) -> Parser | None:
        if ext in self._parsers:
            return self._parsers[ext]
        lang = LANGUAGE_MAP.get(ext)
        if not lang:
            return None
        p = Parser(lang)
        self._parsers[ext] = p
        return p

    def parse(self, file_path: Path, content: str) -> ASTResult | None:
        ext = file_path.suffix
        parser = self._get_parser(ext)
        if not parser:
            logger.debug(f"不支持的语言: {ext}")
            return None

        if len(content) > self.SUBPROCESS_SIZE_THRESHOLD:
            return self._parse_in_subprocess(file_path, content, ext)

        return self._parse_inner(parser, file_path, content, ext)

    def _parse_inner(self, parser: Parser, file_path: Path, content: str, ext: str) -> ASTResult | None:
        try:
            tree = parser.parse(content.encode("utf-8"))
            root = tree.root_node
            lang_name = ext.lstrip(".")
            result = ASTResult(file_path=str(file_path), language=lang_name)
            self._walk(root, content, result, ext)
            return result
        except Exception as e:
            logger.warning(f"AST 解析失败 {file_path}: {e}")
            return None

    def _parse_in_subprocess(self, file_path: Path, content: str, ext: str) -> ASTResult | None:
        parent_conn, child_conn = mp.Pipe(duplex=False)
        proc = mp.Process(
            target=_ast_subprocess_worker,
            args=(child_conn, str(file_path), content, ext),
            daemon=True,
        )
        proc.start()
        try:
            proc.join(timeout=30)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=5)
                logger.warning(f"AST 子进程超时，已终止: {file_path}")
                return None
            if parent_conn.poll():
                data = parent_conn.recv()
                if data is None:
                    logger.warning(f"AST 子进程解析失败: {file_path}")
                    return None
                return _dict_to_ast_result(data)
            logger.warning(f"AST 子进程无返回: {file_path}")
            return None
        except Exception as e:
            logger.warning(f"AST 子进程异常 {file_path}: {e}")
            if proc.is_alive():
                proc.kill()
            return None

    def _walk(self, node: Node, content: str, result: ASTResult, ext: str):
        if ext == ".py":
            self._walk_python(node, content, result)
        elif ext in (".js", ".jsx", ".ts", ".tsx"):
            self._walk_js(node, content, result)
        elif ext == ".java":
            self._walk_java(node, content, result)
        elif ext == ".go":
            self._walk_go(node, content, result)
        elif ext in (".c", ".h"):
            self._walk_c(node, content, result)
        elif ext in (".cpp", ".hpp", ".cc"):
            self._walk_cpp(node, content, result)
        elif ext == ".rs":
            self._walk_rust(node, content, result)
        elif ext == ".rb":
            self._walk_ruby(node, content, result)
        elif ext == ".php":
            self._walk_php(node, content, result)

    def _walk_python(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "function_definition":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "class_definition":
                for member in child.children:
                    if member.type == "function_definition":
                        result.functions.append(self._extract_function(member, content))
            elif child.type == "import_statement" or child.type == "import_from_statement":
                result.imports.append(self._extract_import(child, content))
            elif child.type == "decorator":
                result.decorators.append(
                    {
                        "name": child.text.decode("utf-8", errors="ignore"),
                        "line": child.start_point[0] + 1,
                    }
                )

            self._collect_calls_and_strings(child, content, result)
            self._walk_python(child, content, result)

    def _walk_js(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type in ("function_declaration", "arrow_function", "method_definition"):
                result.functions.append(self._extract_function(child, content))
            elif child.type == "import_statement":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_js(child, content, result)

    def _walk_java(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "method_declaration":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "import_declaration":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_java(child, content, result)

    def _walk_go(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "function_declaration":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "import_declaration":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_go(child, content, result)

    def _walk_c(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "function_definition":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "preproc_include":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_c(child, content, result)

    def _walk_cpp(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type in ("function_definition", "declaration"):
                if child.child_by_field_name("declarator"):
                    result.functions.append(self._extract_function(child, content))
            elif child.type == "preproc_include":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_cpp(child, content, result)

    def _walk_rust(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "function_item":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "use_declaration":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_rust(child, content, result)

    def _walk_ruby(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "method":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "call":
                func_name = child.child_by_field_name("method")
                if func_name and func_name.text.decode("utf-8", errors="ignore") == "require":
                    result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_ruby(child, content, result)

    def _walk_php(self, node: Node, content: str, result: ASTResult):
        for child in node.children:
            if child.type == "function_definition":
                result.functions.append(self._extract_function(child, content))
            elif child.type == "namespace_use_declaration":
                result.imports.append(self._extract_import(child, content))
            self._collect_calls_and_strings(child, content, result)
            self._walk_php(child, content, result)

    def _extract_function(self, node: Node, content: str) -> FunctionDef:
        name = ""
        params = []
        for child in node.children:
            if child.type in ("identifier", "property_identifier"):
                name = child.text.decode("utf-8", errors="ignore")
            elif child.type == "parameters":
                params = [
                    p.text.decode("utf-8", errors="ignore")
                    for p in child.children
                    if p.type in ("identifier", "typed_parameter", "default_parameter")
                ]

        body_node = node.child_by_field_name("body")
        body = body_node.text.decode("utf-8", errors="ignore")[:2000] if body_node else ""

        calls = []
        if body_node:
            calls = self._find_calls_in_node(body_node)

        return FunctionDef(
            name=name,
            params=params,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            body=body,
            calls=calls,
        )

    def _extract_import(self, node: Node, content: str) -> ImportStmt:
        text = node.text.decode("utf-8", errors="ignore")
        names = [
            c.text.decode("utf-8", errors="ignore")
            for c in node.children
            if c.type == "identifier" or c.type == "dotted_name"
        ]
        return ImportStmt(
            module=text,
            names=names,
            line=node.start_point[0] + 1,
        )

    def _collect_calls_and_strings(self, node: Node, content: str, result: ASTResult):
        if node.type == "call":
            func_name = node.child_by_field_name("function")
            if func_name:
                result.calls.append(
                    {
                        "name": func_name.text.decode("utf-8", errors="ignore"),
                        "line": node.start_point[0] + 1,
                        "args_count": len(
                            [c for c in node.children if c.type not in ("identifier", "call_expression")]
                        ),
                    }
                )
        elif node.type == "string":
            text = node.text.decode("utf-8", errors="ignore")
            if len(text) > 5 and len(text) < 500:
                result.strings.append(
                    {
                        "value": text,
                        "line": node.start_point[0] + 1,
                    }
                )
        elif node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                result.assignments.append(
                    {
                        "name": left.text.decode("utf-8", errors="ignore"),
                        "value": right.text.decode("utf-8", errors="ignore")[:200],
                        "line": node.start_point[0] + 1,
                    }
                )

    def _find_calls_in_node(self, node: Node) -> list[str]:
        calls = []
        if node.type == "call":
            func = node.child_by_field_name("function")
            if func:
                calls.append(func.text.decode("utf-8", errors="ignore"))
        for child in node.children:
            calls.extend(self._find_calls_in_node(child))
        return calls

    def get_supported_extensions(self) -> set[str]:
        return set(LANGUAGE_MAP.keys())


def _ast_subprocess_worker(conn, file_path: str, content: str, ext: str) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        lang = LANGUAGE_MAP.get(ext)
        if not lang:
            conn.send(None)
            return
        p = Parser(lang)
        tree = p.parse(content.encode("utf-8"))
        root = tree.root_node
        lang_name = ext.lstrip(".")
        result = ASTResult(file_path=file_path, language=lang_name)
        tmp = ASTParser.__new__(ASTParser)
        tmp._parsers = {}
        tmp._walk(root, content, result, ext)
        conn.send(result.to_dict())
    except Exception:
        logger.warning(f"AST 子进程解析异常: {file_path}", exc_info=True)
        conn.send(None)
    finally:
        conn.close()
