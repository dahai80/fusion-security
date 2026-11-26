from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ast_parser import ASTParser, ASTResult

logger = logging.getLogger(__name__)

SOURCES = {
    "request.args",
    "request.form",
    "request.data",
    "request.json",
    "request.files",
    "request.headers",
    "request.cookies",
    "request.query_params",
    "request.body",
    "input(",
    "sys.stdin",
    "os.environ",
    "req.params",
    "req.query",
    "req.body",
    "req.headers",
    "params",
    "query",
    "HttpContext",
    "r.FormValue",
    "r.URL.Query",
}

SINKS = {
    "execute": "SQL injection",
    "exec": "Command injection",
    "query": "SQL injection",
    "os.system": "Command injection",
    "subprocess.call": "Command injection",
    "subprocess.Popen": "Command injection",
    "subprocess.run": "Command injection",
    "eval": "Code injection",
    "innerHTML": "XSS",
    "document.write": "XSS",
    "open": "Path traversal",
    "Path": "Path traversal",
    "redirect": "Open redirect",
    "send_file": "Path traversal",
    "render_template_string": "SSTI",
    "system": "Command injection",
    "Popen": "Command injection",
    "run": "Command injection",
    "call": "Command injection",
}

# Generic sink base names (run/call/open/query/execute/system/Popen) alone have a very high false-positive rate
# (app.run, client.query, config.open, etc.). Only treat them as sinks when attached to a dangerous owner.
GENERIC_SINK_BASES = {"run", "call", "open", "query", "execute", "system", "Popen"}
DANGEROUS_OWNERS = {"os", "subprocess", "cursor", "db", "session", "conn", "engine", "shell", "commands"}

SANITIZERS = {
    "escape",
    "html_escape",
    "bleach.clean",
    "markupsafe.escape",
    "parameterize",
    "bind_param",
    "prepare",
    "quote",
    "sanitize",
    "validate",
    "check_path",
    "abspath",
    "escape_string",
    "realpath",
}


@dataclass
class TaintSource:
    name: str
    line: int
    variable: str
    source_type: str


@dataclass
class TaintSink:
    name: str
    line: int
    sink_type: str


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    propagation: list[dict[str, Any]]
    is_sanitized: bool


@dataclass
class TaintResult:
    file_path: str
    taint_paths: list[TaintPath] = field(default_factory=list)


class TaintTracker:
    def __init__(self):
        self._ast_parser = ASTParser()

    def analyze(self, file_path: Path, content: str) -> TaintResult:
        ast_result = self._ast_parser.parse(file_path, content)
        if not ast_result:
            return TaintResult(file_path=str(file_path))

        result = TaintResult(file_path=str(file_path))
        sources = self._find_sources(ast_result)
        sinks = self._find_sinks(ast_result)

        for source in sources:
            for sink in sinks:
                propagation = self._trace_propagation(source, sink, ast_result)
                is_sanitized = self._check_sanitization(source, sink, ast_result)

                if not is_sanitized:
                    result.taint_paths.append(
                        TaintPath(
                            source=source,
                            sink=sink,
                            propagation=propagation,
                            is_sanitized=False,
                        )
                    )

        return result

    def analyze_project(self, files: list[tuple[Path, str]]) -> list[TaintPath]:
        all_results: list[TaintPath] = []
        file_asts: dict[str, ASTResult] = {}

        for file_path, content in files:
            ast_result = self._ast_parser.parse(file_path, content)
            if ast_result:
                file_asts[str(file_path)] = ast_result
                taint_result = self.analyze(file_path, content)
                all_results.extend(taint_result.taint_paths)

        cross_file_paths = self._cross_file_analysis(file_asts)
        all_results.extend(cross_file_paths)

        return all_results

    def _find_sources(self, ast_result: ASTResult) -> list[TaintSource]:
        sources = []
        for call in ast_result.calls:
            name = call.get("name", "")
            if self._is_source(name):
                sources.append(
                    TaintSource(
                        name=name,
                        line=call.get("line", 0),
                        variable="",
                        source_type=self._classify_source(name),
                    )
                )

        for assign in ast_result.assignments:
            value = assign.get("value", "")
            for src in SOURCES:
                if src in value:
                    sources.append(
                        TaintSource(
                            name=src,
                            line=assign.get("line", 0),
                            variable=assign.get("name", ""),
                            source_type=self._classify_source(src),
                        )
                    )
        return sources

    def _find_sinks(self, ast_result: ASTResult) -> list[TaintSink]:
        sinks = []
        for call in ast_result.calls:
            name = call.get("name", "")
            base = name.split(".")[-1] if "." in name else name
            if base not in SINKS:
                continue
            # Generic base names only count as sinks when attached to a dangerous owner; otherwise normal calls like
            # app.run()/client.query() would flood false positives. Non-generic sinks (eval/exec/innerHTML etc.) are accepted directly.
            if base in GENERIC_SINK_BASES:
                owner = name.rsplit(".", 1)[0].lower() if "." in name else ""
                if owner not in DANGEROUS_OWNERS:
                    continue
            sinks.append(
                TaintSink(
                    name=name,
                    line=call.get("line", 0),
                    sink_type=SINKS[base],
                )
            )
        return sinks

    def _trace_propagation(self, source: TaintSource, sink: TaintSink, ast_result: ASTResult) -> list[dict[str, Any]]:
        path = []
        path.append({"type": "source", "name": source.name, "line": source.line})

        for func in ast_result.functions:
            if func.start_line <= source.line <= func.end_line:
                path.append({"type": "function", "name": func.name, "line": func.start_line})
                for call_name in func.calls:
                    if call_name == sink.name or call_name.split(".")[-1] == sink.name.split(".")[-1]:
                        path.append({"type": "call", "name": call_name, "line": sink.line})
                    elif call_name not in SANITIZERS:
                        path.append({"type": "propagation", "name": call_name})

        path.append({"type": "sink", "name": sink.name, "line": sink.line})
        return path

    def _check_sanitization(self, source: TaintSource, sink: TaintSink, ast_result: ASTResult) -> bool:
        for call in ast_result.calls:
            line = call.get("line", 0)
            if source.line < line < sink.line:
                name = call.get("name", "")
                base = name.split(".")[-1] if "." in name else name
                if base in SANITIZERS:
                    return True
        return False

    def _cross_file_analysis(self, file_asts: dict[str, ASTResult]) -> list[TaintPath]:
        paths = []

        exports: dict[str, list[tuple[str, int, str, list[str]]]] = {}
        for fpath, ast_result in file_asts.items():
            for func in ast_result.functions:
                exports.setdefault(func.name, []).append((fpath, func.start_line, func.name, func.calls))

        for fpath, ast_result in file_asts.items():
            sources = self._find_sources(ast_result)
            if not sources:
                continue

            imported_names: set[str] = set()
            for imp in ast_result.imports:
                if imp.names:
                    for n in imp.names:
                        if " as " in n:
                            imported_names.add(n.split(" as ")[-1].strip())
                        else:
                            imported_names.add(n.split(".")[-1])
                else:
                    imported_names.add(imp.module.split(".")[-1])

            for source in sources:
                for imp_name in imported_names:
                    if imp_name not in exports:
                        continue
                    for exp_fpath, exp_line, _exp_func_name, exp_calls in exports[imp_name]:
                        for call_name in exp_calls:
                            base = call_name.split(".")[-1] if "." in call_name else call_name
                            if base not in SINKS:
                                continue
                            if base in GENERIC_SINK_BASES:
                                owner = call_name.rsplit(".", 1)[0].lower() if "." in call_name else ""
                                if owner not in DANGEROUS_OWNERS:
                                    continue
                            paths.append(
                                TaintPath(
                                    source=source,
                                    sink=TaintSink(name=call_name, line=exp_line, sink_type=SINKS[base]),
                                    propagation=[
                                        {"type": "source", "name": source.name, "line": source.line, "file": fpath},
                                        {"type": "import", "name": imp_name, "file": exp_fpath},
                                        {"type": "sink", "name": call_name, "line": exp_line, "file": exp_fpath},
                                    ],
                                    is_sanitized=False,
                                )
                            )

        return paths

    def _is_source(self, name: str) -> bool:
        return any(src in name or name.endswith(src.replace("(", "")) for src in SOURCES)

    def _classify_source(self, name: str) -> str:
        if any(k in name for k in ["args", "form", "query", "params", "body"]):
            return "http_input"
        if any(k in name for k in ["stdin", "input"]):
            return "user_input"
        if "environ" in name:
            return "environment"
        return "unknown"
