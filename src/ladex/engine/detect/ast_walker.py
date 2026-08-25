"""Tree-sitter based detection for Python source.

Despite the historical filename, this is a *tree-sitter* walker, not a stdlib ``ast`` one —
that is the whole point: tree-sitter parses half-typed and syntactically invalid code and
still yields a usable tree, so detection works while a developer is mid-keystroke.

Pipeline for one file:

1. Parse the source bytes into a tree (always succeeds; broken code just has ERROR nodes).
2. First pass — collect ``import`` bindings (local name → fully-qualified dotted path) and
   emit ``import`` detections.
3. Second pass — for every ``call`` / ``attribute`` / ``string`` node, resolve dotted
   callees through the import bindings and match against the taxonomy.

Resolving through imports is what lets ``from openai import OpenAI; OpenAI()`` match the
same rule as ``openai.OpenAI()`` — and, crucially, means a bare ``OpenAI()`` with no such
import does *not* fire (ruthless silence).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from ladex.engine.detect.records import Detection, SourceSpan
from ladex.engine.taxonomy import Taxonomy, load_builtin_taxonomy
from ladex.engine.taxonomy.models import (
    AttributeMatch,
    CallMatch,
    ImportMatch,
    Rule,
    StringMatch,
)


@lru_cache(maxsize=1)
def _language() -> Language:
    return Language(tspython.language())


class PythonDetector:
    """Runs the taxonomy against Python source using tree-sitter."""

    def __init__(self, taxonomy: Taxonomy | None = None) -> None:
        self._taxonomy = taxonomy if taxonomy is not None else load_builtin_taxonomy()
        self._parser = Parser(_language())
        self._index_rules()

    def _index_rules(self) -> None:
        self._import_rules: list[Rule] = []
        self._call_targets: dict[str, list[Rule]] = {}
        self._attr_targets: dict[str, list[Rule]] = {}
        self._string_rules: list[tuple[re.Pattern[str], Rule]] = []
        for rule in self._taxonomy.rules:
            match = rule.match
            if isinstance(match, ImportMatch):
                self._import_rules.append(rule)
            elif isinstance(match, CallMatch):
                self._call_targets.setdefault(match.target, []).append(rule)
            elif isinstance(match, AttributeMatch):
                self._attr_targets.setdefault(match.target, []).append(rule)
            elif isinstance(match, StringMatch):
                self._string_rules.append((re.compile(match.pattern), rule))

    # -- public API ---------------------------------------------------------

    def detect_source(self, code: str, path: str = "<source>") -> list[Detection]:
        """Detect AI components in a source string. Never raises on invalid syntax."""
        data = code.encode("utf-8")
        root = self._parser.parse(data).root_node
        detections: list[Detection] = []
        bindings = self._collect_imports(root, data, path, detections)
        self._collect_usages(root, data, path, bindings, detections)
        detections.sort(key=Detection.sort_key)
        return detections

    def detect_file(self, path: Path) -> list[Detection]:
        """Detect AI components in a file. Unreadable/undecodable files yield no detections."""
        try:
            data = path.read_bytes()
        except OSError:
            return []
        return self.detect_source(data.decode("utf-8", errors="replace"), str(path))

    # -- pass 1: imports ----------------------------------------------------

    def _collect_imports(
        self, root: Node, data: bytes, path: str, out: list[Detection]
    ) -> dict[str, str]:
        bindings: dict[str, str] = {}
        for node in _iter_nodes(root):
            if node.type == "import_statement":
                self._handle_import(node, data, path, bindings, out)
            elif node.type == "import_from_statement":
                self._handle_import_from(node, data, path, bindings, out)
        return bindings

    def _handle_import(
        self, node: Node, data: bytes, path: str, bindings: dict[str, str], out: list[Detection]
    ) -> None:
        for child in node.named_children:
            if child.type == "dotted_name":
                module = _text(child, data)
                bindings.setdefault(module.split(".")[0], module.split(".")[0])
                self._emit_import(module, None, child, path, out)
            elif child.type == "aliased_import":
                name = child.child_by_field_name("name")
                alias = child.child_by_field_name("alias")
                if name is None or alias is None:
                    continue
                module = _text(name, data)
                bindings[_text(alias, data)] = module
                self._emit_import(module, None, child, path, out)

    def _handle_import_from(
        self, node: Node, data: bytes, path: str, bindings: dict[str, str], out: list[Detection]
    ) -> None:
        module_node = node.child_by_field_name("module_name")
        if module_node is None:
            return
        module = _text(module_node, data)
        for name_node in node.children_by_field_name("name"):
            if name_node.type == "dotted_name":
                symbol = _text(name_node, data)
                bindings[symbol.split(".")[0]] = f"{module}.{symbol}"
                self._emit_import(module, symbol, name_node, path, out)
            elif name_node.type == "aliased_import":
                inner = name_node.child_by_field_name("name")
                alias = name_node.child_by_field_name("alias")
                if inner is None or alias is None:
                    continue
                symbol = _text(inner, data)
                bindings[_text(alias, data)] = f"{module}.{symbol}"
                self._emit_import(module, symbol, name_node, path, out)

    def _emit_import(
        self, module: str, symbol: str | None, node: Node, path: str, out: list[Detection]
    ) -> None:
        for rule in self._import_rules:
            match = rule.match
            assert isinstance(match, ImportMatch)
            if not _module_matches(match.module, module):
                continue
            if match.symbol is not None and match.symbol != symbol:
                continue
            evidence = module if symbol is None else f"{module}.{symbol}"
            out.append(self._make(rule, "import", evidence, node, path))

    # -- pass 2: usages -----------------------------------------------------

    def _collect_usages(
        self, root: Node, data: bytes, path: str, bindings: dict[str, str], out: list[Detection]
    ) -> None:
        for node in _iter_nodes(root):
            if node.type == "call":
                self._handle_call(node, data, path, bindings, out)
            elif node.type == "attribute":
                self._handle_attribute(node, data, path, bindings, out)
            elif node.type == "string":
                self._handle_string(node, data, path, out)

    def _handle_call(
        self, node: Node, data: bytes, path: str, bindings: dict[str, str], out: list[Detection]
    ) -> None:
        func = node.child_by_field_name("function")
        if func is None:
            return
        resolved = _resolve(_flatten(func, data), bindings)
        if resolved is None:
            return
        rules = self._call_targets.get(resolved, ())
        if not rules:
            return
        first_arg = _first_string_arg(node, data)
        for rule in rules:
            match = rule.match
            assert isinstance(match, CallMatch)
            if match.arg is not None and (
                first_arg is None or re.search(match.arg, first_arg) is None
            ):
                continue
            out.append(self._make(rule, "call", resolved, func, path))

    def _handle_attribute(
        self, node: Node, data: bytes, path: str, bindings: dict[str, str], out: list[Detection]
    ) -> None:
        parent = node.parent
        # Skip attributes that are the callee of a call, or the object half of a longer
        # chain — evaluate only the outermost attribute expression to avoid duplicates.
        if parent is not None and parent.type in {"call", "attribute"}:
            return
        resolved = _resolve(_flatten(node, data), bindings)
        if resolved is None:
            return
        for rule in self._attr_targets.get(resolved, ()):
            out.append(self._make(rule, "attribute", resolved, node, path))

    def _handle_string(self, node: Node, data: bytes, path: str, out: list[Detection]) -> None:
        value = _string_value(node, data)
        if not value:
            return
        for pattern, rule in self._string_rules:
            if pattern.search(value):
                out.append(self._make(rule, "string", value, node, path))

    # -- helpers ------------------------------------------------------------

    def _make(self, rule: Rule, kind: str, evidence: str, node: Node, path: str) -> Detection:
        srow, scol = node.start_point
        erow, ecol = node.end_point
        return Detection(
            rule_id=rule.id,
            name=rule.name,
            component_type=rule.component_type,
            match_kind=kind,
            evidence=evidence,
            path=path,
            span=SourceSpan(srow + 1, scol, erow + 1, ecol),
            provider=rule.provider,
            tags=tuple(rule.tags),
        )


def _iter_nodes(root: Node) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _text(node: Node, data: bytes) -> str:
    return data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _flatten(node: Node, data: bytes) -> list[str] | None:
    """Flatten an identifier/attribute chain to a list of names, or None if impure."""
    if node.type == "identifier":
        return [_text(node, data)]
    if node.type == "attribute":
        obj = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        if obj is None or attr is None or attr.type != "identifier":
            return None
        base = _flatten(obj, data)
        if base is None:
            return None
        return [*base, _text(attr, data)]
    return None


def _resolve(path: list[str] | None, bindings: dict[str, str]) -> str | None:
    if not path:
        return None
    head, *rest = path
    base = bindings.get(head)
    if base is None:
        return None
    return base if not rest else base + "." + ".".join(rest)


def _module_matches(rule_module: str, imported_module: str) -> bool:
    return imported_module == rule_module or imported_module.startswith(rule_module + ".")


def _string_value(node: Node, data: bytes) -> str:
    parts = [_text(c, data) for c in node.named_children if c.type == "string_content"]
    return "".join(parts)


def _first_string_arg(call: Node, data: bytes) -> str | None:
    """The value of a call's first argument if it is a plain string literal, else None."""
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    for arg in arguments.named_children:
        if arg.type == "comment":
            continue
        return _string_value(arg, data) if arg.type == "string" else None
    return None
