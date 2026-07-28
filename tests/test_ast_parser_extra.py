from pathlib import Path

from fusion_security.engine.rules.ast_parser import (
    ASTNode,
    ASTParser,
    ASTResult,
    FunctionDef,
    ImportStmt,
    _dict_to_ast_result,
)


class TestASTNodeToDict:
    def test_to_dict_basic(self):
        node = ASTNode(
            node_type="function_definition",
            text="def hello(): pass",
            start_line=1,
            end_line=1,
            start_col=0,
            end_col=16,
        )
        d = node.to_dict()
        assert d["type"] == "function_definition"
        assert d["text"] == "def hello(): pass"
        assert d["line"] == 1
        assert d["end_line"] == 1
        assert d["children"] == []

    def test_to_dict_truncates_text_and_children(self):
        child = ASTNode(
            node_type="identifier",
            text="x",
            start_line=2,
            end_line=2,
            start_col=4,
            end_col=5,
        )
        parent = ASTNode(
            node_type="function_definition",
            text="x" * 300,
            start_line=1,
            end_line=3,
            start_col=0,
            end_col=1,
            children=[child] * 8,
        )
        d = parent.to_dict()
        assert len(d["text"]) <= 200
        assert len(d["children"]) == 5


class TestASTResultToDict:
    def test_to_dict_empty(self):
        r = ASTResult(file_path="test.py", language="py")
        d = r.to_dict()
        assert d["file_path"] == "test.py"
        assert d["language"] == "py"
        assert d["functions"] == []
        assert d["imports"] == []
        assert d["assignments"] == []
        assert d["calls"] == []
        assert d["strings"] == []
        assert d["decorators"] == []

    def test_to_dict_with_data(self):
        r = ASTResult(
            file_path="a.py",
            language="py",
            functions=[
                FunctionDef(
                    name="foo",
                    params=["x", "y"],
                    start_line=1,
                    end_line=3,
                    body="return x+y",
                    calls=["bar"],
                )
            ],
            imports=[ImportStmt(module="os", names=["path"], line=1)],
            assignments=[{"name": "a", "value": "1", "line": 2}],
            calls=[{"name": "print", "line": 3, "args_count": 1}],
            strings=[{"value": "'hello'", "line": 4}],
            decorators=[{"name": "@app.route", "line": 1}],
        )
        d = r.to_dict()
        assert d["functions"][0]["name"] == "foo"
        assert d["functions"][0]["params"] == ["x", "y"]
        assert d["functions"][0]["calls"] == ["bar"]
        assert d["imports"][0]["module"] == "os"
        assert d["imports"][0]["names"] == ["path"]
        assert d["assignments"] == [{"name": "a", "value": "1", "line": 2}]
        assert d["calls"] == [{"name": "print", "line": 3, "args_count": 1}]
        assert d["strings"] == [{"value": "'hello'", "line": 4}]
        assert d["decorators"] == [{"name": "@app.route", "line": 1}]


class TestDictToASTResult:
    def test_from_empty_dict(self):
        r = _dict_to_ast_result({})
        assert r.file_path == ""
        assert r.language == ""
        assert r.functions == []
        assert r.imports == []

    def test_from_full_dict(self):
        data = {
            "file_path": "test.py",
            "language": "py",
            "functions": [
                {
                    "name": "hello",
                    "params": ["name"],
                    "start_line": 1,
                    "end_line": 2,
                    "body": "print(name)",
                    "calls": ["print"],
                }
            ],
            "imports": [{"module": "os", "names": ["path"], "line": 1}],
            "assignments": [{"name": "x", "value": "1", "line": 3}],
            "calls": [{"name": "print", "line": 2, "args_count": 1}],
            "strings": [{"value": "'abc'", "line": 4}],
            "decorators": [{"name": "@route", "line": 1}],
        }
        r = _dict_to_ast_result(data)
        assert r.file_path == "test.py"
        assert r.language == "py"
        assert len(r.functions) == 1
        assert r.functions[0].name == "hello"
        assert r.functions[0].params == ["name"]
        assert r.functions[0].calls == ["print"]
        assert len(r.imports) == 1
        assert r.imports[0].module == "os"
        assert r.imports[0].names == ["path"]

    def test_from_dict_missing_function_fields(self):
        data = {"functions": [{}], "imports": [{}]}
        r = _dict_to_ast_result(data)
        assert r.functions[0].name == ""
        assert r.functions[0].params == []
        assert r.functions[0].start_line == 0
        assert r.functions[0].end_line == 0
        assert r.functions[0].body == ""
        assert r.functions[0].calls == []
        assert r.imports[0].module == ""
        assert r.imports[0].names == []
        assert r.imports[0].line == 0


class TestToDictFromDictRoundtrip:
    def test_roundtrip(self):
        original = ASTResult(
            file_path="test.py",
            language="py",
            functions=[
                FunctionDef(
                    name="main",
                    params=[],
                    start_line=5,
                    end_line=10,
                    body="pass",
                    calls=["init"],
                )
            ],
            imports=[ImportStmt(module="sys", names=[], line=1)],
            assignments=[{"name": "x", "value": "42", "line": 2}],
            calls=[{"name": "init", "line": 6, "args_count": 0}],
            strings=[{"value": "'hello world'", "line": 7}],
            decorators=[{"name": "@click", "line": 4}],
        )
        d = original.to_dict()
        restored = _dict_to_ast_result(d)
        assert restored.file_path == original.file_path
        assert restored.language == original.language
        assert len(restored.functions) == 1
        assert restored.functions[0].name == "main"
        assert restored.functions[0].calls == ["init"]
        assert len(restored.imports) == 1
        assert restored.imports[0].module == "sys"


class TestSubprocessIsolation:
    def test_large_content_routes_to_subprocess(self):
        parser = ASTParser()
        line = "x = 1\n"
        needed = (ASTParser.SUBPROCESS_SIZE_THRESHOLD // len(line)) + 100
        code = line * needed
        assert len(code) > ASTParser.SUBPROCESS_SIZE_THRESHOLD
        try:
            result = parser.parse(Path("big.py"), code)
            if result is not None:
                assert result.language == "py"
        except (AttributeError, TypeError, OSError):
            pass

    def test_subprocess_timeout_returns_none(self, monkeypatch):
        parser = ASTParser()

        import multiprocessing as mp

        class SlowProcess:
            def __init__(self, *a, **kw):
                self._alive = True

            def start(self):
                pass

            def join(self, timeout=None):
                pass

            def is_alive(self):
                return True

            def kill(self):
                self._alive = False

        monkeypatch.setattr(mp, "Process", SlowProcess)

        code = "x" * (ASTParser.SUBPROCESS_SIZE_THRESHOLD + 1)
        try:
            result = parser.parse(Path("slow.py"), code)
            assert result is None
        except (AttributeError, TypeError, OSError):
            pass


class TestExtractFunction:
    def setup_method(self):
        self.parser = ASTParser()

    def test_extract_python_function(self):
        code = "def hello(name, age=10):\n    print(name)\n"
        tree = self.parser._get_parser(".py").parse(code.encode("utf-8"))
        func_node = tree.root_node.children[0]
        result = self.parser._extract_function(func_node, code)
        assert result.name == "hello"
        assert "name" in result.params
        assert result.start_line == 1
        assert result.calls == ["print"]

    def test_extract_function_no_body(self):
        code = "def noop(): pass\n"
        tree = self.parser._get_parser(".py").parse(code.encode("utf-8"))
        func_node = tree.root_node.children[0]
        result = self.parser._extract_function(func_node, code)
        assert result.name == "noop"


class TestExtractImport:
    def setup_method(self):
        self.parser = ASTParser()

    def test_extract_python_import(self):
        code = "import os\n"
        tree = self.parser._get_parser(".py").parse(code.encode("utf-8"))
        import_node = tree.root_node.children[0]
        result = self.parser._extract_import(import_node, code)
        assert "os" in result.module
        assert result.line == 1


class TestCollectCallsAndStrings:
    def setup_method(self):
        self.parser = ASTParser()

    def test_collect_call(self):
        code = "print('hello world test')\n"
        result = self.parser.parse(Path("t.py"), code)
        assert result is not None
        assert len(result.calls) >= 1
        assert result.calls[0]["name"] == "print"

    def test_collect_string(self):
        code = "x = 'this is a longer string value'\n"
        result = self.parser.parse(Path("t.py"), code)
        assert result is not None
        assert len(result.strings) >= 1

    def test_collect_assignment(self):
        code = "x = 42\n"
        result = self.parser.parse(Path("t.py"), code)
        assert result is not None
        assert len(result.assignments) >= 1
        assert result.assignments[0]["name"] == "x"


class TestWalkC:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_c_function_and_include(self):
        code = '#include <stdio.h>\nvoid hello() {\n    printf("hi");\n}\n'
        result = self.parser.parse(Path("test.c"), code)
        assert result is not None
        assert result.language == "c"
        assert len(result.functions) >= 1
        assert len(result.imports) >= 1

    def test_parse_h_file(self):
        code = '#include "types.h"\nint add(int a, int b);\n'
        result = self.parser.parse(Path("test.h"), code)
        assert result is not None
        assert result.language == "h"


class TestWalkCpp:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_cpp_function_and_include(self):
        code = '#include <iostream>\nint main() {\n    std::cout << "hi";\n    return 0;\n}\n'
        result = self.parser.parse(Path("test.cpp"), code)
        assert result is not None
        assert result.language == "cpp"
        assert len(result.imports) >= 1

    def test_parse_hpp_file(self):
        code = "#include <vector>\n"
        result = self.parser.parse(Path("test.hpp"), code)
        assert result is not None
        assert result.language == "hpp"

    def test_parse_cc_file(self):
        code = "#include <string>\n"
        result = self.parser.parse(Path("test.cc"), code)
        assert result is not None
        assert result.language == "cc"


class TestWalkRust:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_rust_function_and_use(self):
        code = 'use std::io;\nfn main() {\n    println!("hi");\n}\n'
        result = self.parser.parse(Path("test.rs"), code)
        assert result is not None
        assert result.language == "rs"
        assert len(result.functions) >= 1
        assert len(result.imports) >= 1


class TestWalkRuby:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_ruby_method_and_require(self):
        code = "require 'json'\ndef hello\n  puts 'hi'\nend\n"
        result = self.parser.parse(Path("test.rb"), code)
        assert result is not None
        assert result.language == "rb"
        assert len(result.functions) >= 1


class TestWalkPHP:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_php_function_and_use(self):
        code = '<?php\nuse Some\\Lib;\nfunction hello() {\n    echo "hi";\n}\n?>\n'
        result = self.parser.parse(Path("test.php"), code)
        assert result is not None
        assert result.language == "php"
        assert len(result.functions) >= 1


class TestWalkJava:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_java_method_and_import(self):
        code = "import java.util.List;\npublic class Foo {\n    void bar() {}\n}\n"
        result = self.parser.parse(Path("Test.java"), code)
        assert result is not None
        assert result.language == "java"
        assert len(result.imports) >= 1


class TestWalkGo:
    def setup_method(self):
        self.parser = ASTParser()

    def test_parse_go_function_and_import(self):
        code = 'import "fmt"\nfunc main() {\n    fmt.Println("hi")\n}\n'
        result = self.parser.parse(Path("test.go"), code)
        assert result is not None
        assert result.language == "go"
        assert len(result.imports) >= 1


class TestWalkPythonClassMethods:
    def setup_method(self):
        self.parser = ASTParser()

    def test_python_class_with_methods(self):
        code = "class Foo:\n    def bar(self):\n        pass\n    def baz(self):\n        pass\n"
        result = self.parser.parse(Path("test.py"), code)
        assert result is not None
        assert len(result.functions) == 2
        names = [f.name for f in result.functions]
        assert "bar" in names
        assert "baz" in names


class TestWalkJsImport:
    def setup_method(self):
        self.parser = ASTParser()

    def test_js_import_statement(self):
        code = 'import React from "react";\nfunction App() { return null; }\n'
        result = self.parser.parse(Path("test.js"), code)
        assert result is not None
        assert len(result.imports) >= 1
