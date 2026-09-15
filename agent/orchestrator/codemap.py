"""The Eyes, part 1 -- a LOCAL tree-sitter code map (structure): functions, call graph, imports, entry
points, and entry->sink reachability.

The model is stateless: it can only reason over what's in its context window, and it can't hold a whole
codebase's structure while it focuses on one piece (see the memory/cross-file analysis). So the HARNESS
holds the structure and hands the model a RESOLVED slice ("input enters at X, flows through Y, reaches
sink Z"). This module is that map. It is exact + exhaustive for the *syntactic* skeleton (who-calls-whom,
who is exported) and deliberately cheap/local. It is BLIND to dynamic dispatch / eval / reflection /
framework magic -- those get audited on top by a comprehension model (eyes.py). Name-based call
resolution is best-effort, not type-sound; the audit + ensemble cover the gaps.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

_EXT_LANG = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
             ".jsx": "javascript", ".ts": "typescript", ".tsx": "tsx", ".mts": "typescript",
             ".rb": "ruby", ".php": "php",
             ".go": "go", ".java": "java", ".cs": "csharp", ".rs": "rust",
             ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".scala": "scala", ".sc": "scala",
             ".ex": "elixir", ".exs": "elixir", ".sh": "bash", ".bash": "bash", ".lua": "lua",
             ".hs": "haskell", ".dart": "dart", ".pl": "perl", ".pm": "perl",
             ".c": "c", ".h": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
             ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp"}
_SKIP = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "vendor",
         "site-packages", "test", "tests", "__tests__", "spec", "examples", "example"}

_FUNC_DEF = {"function_definition", "function_declaration", "method_definition",
             "generator_function_declaration", "function_expression", "arrow_function",
             "method", "singleton_method",                # ruby
             "method_declaration",                        # php/java/c#/go
             "constructor_declaration",                   # java / c#
             "function_item",                             # rust (function_definition covers php/c/cpp)
             "subroutine_declaration_statement",          # perl
             "function_signature",                        # dart (name field; body is a sibling)
             "function"}                                  # haskell (a bare `function` keyword token elsewhere
                                                          # has no name -> skipped by the `if name` guard)
_CLASS_DEF = {"class_definition", "class_declaration", "class",   # +class = ruby
              "interface_declaration", "enum_declaration",        # java / c#
              "struct_declaration",                               # c#
              "struct_item", "impl_item", "trait_item",           # rust
              "class_specifier", "struct_specifier"}              # c++
_CALL = {"call", "call_expression", "function_call_expression", "member_call_expression",
         "scoped_call_expression", "method_call", "command",      # +php +ruby +bash(command)
         "method_invocation",                                     # java
         "invocation_expression",                                 # c#
         "macro_invocation",                                      # rust (call_expression covers go/rust/c/cpp)
         "function_call",                                         # lua
         "apply"}                                                 # haskell


@dataclass
class Func:
    name: str
    file: str
    line: int
    end: int = 0                                      # last line of the body (for exact source slicing)
    exported: bool = False
    decorators: list = field(default_factory=list)   # e.g. route decorators -> entry points
    sig: str = ""                                     # parameter signature, e.g. "(req, res)"


@dataclass
class Cls:
    name: str
    file: str
    line: int
    end: int = 0
    exported: bool = False
    decorators: list = field(default_factory=list)
    methods: list = field(default_factory=list)      # [Func]


@dataclass
class FileInfo:
    """Everything one source file is COMPOSED OF -- the per-file view the detailed repo map renders."""
    path: str
    lang: str
    loc: int = 0
    doc: str = ""                                     # module docstring / leading comment ("what it does")
    imports: list = field(default_factory=list)       # raw import lines / required modules
    functions: list = field(default_factory=list)     # top-level Funcs (methods live under their class)
    classes: list = field(default_factory=list)       # [Cls]
    exports: list = field(default_factory=list)        # exported public names


@dataclass
class CodeMap:
    funcs: dict = field(default_factory=lambda: defaultdict(list))   # name -> [Func]
    calls: list = field(default_factory=list)                        # (caller_name, callee_name, file, line)
    imports: dict = field(default_factory=lambda: defaultdict(set))  # file -> {module}
    classes: dict = field(default_factory=lambda: defaultdict(list)) # name -> [Cls]
    files: dict = field(default_factory=dict)                        # path -> FileInfo (the by-file view)
    _callers: dict = field(default_factory=lambda: defaultdict(set)) # callee_name -> {caller_name}

    def entry_points(self):
        """Functions untrusted input can enter through: exported / decorated (routes) / top-level mains."""
        out = []
        for name, fs in self.funcs.items():
            for f in fs:
                if f.exported or f.decorators or name in ("main", "handler", "handle"):
                    out.append(f)
        return out

    def callers_of(self, name):
        return sorted(self._callers.get(name, set()))

    def chain_to_entry(self, sink_func, max_hops=8):
        """Walk the call graph BACKWARD from a sink function to an entry point. Returns the shortest
        name chain [entry, ..., sink] or None. This is the 'resolved slice' handed to the model."""
        if not sink_func:
            return None
        entries = {f.name for f in self.entry_points()}
        if sink_func in entries:                 # the sink function is itself reachable input (an export/route)
            return [sink_func]
        seen = {sink_func}
        q = deque([[sink_func]])
        while q:
            path = q.popleft()
            head = path[0]
            if head in entries and len(path) > 1:
                return path
            if len(path) > max_hops:
                continue
            for caller in self._callers.get(head, ()):
                if caller not in seen:
                    seen.add(caller)
                    if caller in entries:
                        return [caller] + path
                    q.append([caller] + path)
        return None


def _iter_files(target):
    p = Path(target)
    for f in p.rglob("*"):
        if f.suffix.lower() in _EXT_LANG and not any(s in f.parts for s in _SKIP):
            try:
                if f.stat().st_size < 400_000:
                    yield f
            except OSError:
                pass


def _txt(node):
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:
        return ""


def _callee_name(call_node):
    """The name being called: `foo(...)` -> foo, `a.b.foo(...)` -> foo, `obj.method(...)` -> method.
    ruby: the callee is the `method` field; php member-call is the `name` field."""
    fn = (call_node.child_by_field_name("function") or call_node.child_by_field_name("method")
          or call_node.child_by_field_name("name"))
    if fn is None:
        fn = call_node.children[0] if call_node.children else None
    if fn is None:
        return ""
    if fn.type in ("identifier", "name", "constant", "field_identifier", "type_identifier"):
        return _txt(fn)
    if fn.type in ("attribute", "member_expression", "member_access_expression", "scoped_call_expression",
                   "selector_expression",          # go  exec.Command
                   "field_expression",             # c/cpp/rust  obj.method / obj->method
                   "scoped_identifier",            # rust/java  Command::new / a.b.c
                   "qualified_identifier"):         # c++  ns::fn
        last = (fn.child_by_field_name("attribute") or fn.child_by_field_name("property")
                or fn.child_by_field_name("name") or fn.child_by_field_name("field")
                or fn.child_by_field_name("selector"))
        return _txt(last) if last else _txt(fn).split("::")[-1].split(".")[-1].split("->")[-1]
    return _txt(fn).split("::")[-1].split(".")[-1].split("->")[-1].split("(")[0].split("<")[0].strip()


def _def_name(node):
    n = node.child_by_field_name("name")
    if n is not None:
        return _txt(n)
    # C/C++: function_definition has no `name` field -- the name is nested in the declarator chain
    # (function_declarator -> declarator -> identifier/field_identifier/qualified_identifier).
    if node.type in ("function_definition",):
        d = node.child_by_field_name("declarator")
        for _ in range(6):
            if d is None:
                break
            if d.type in ("identifier", "field_identifier", "qualified_identifier", "operator_name",
                          "destructor_name"):
                return _txt(d).split("::")[-1]
            nxt = d.child_by_field_name("declarator")
            if nxt is None:
                ids = [c for c in d.children
                       if c.type in ("identifier", "field_identifier", "qualified_identifier")]
                return _txt(ids[0]).split("::")[-1] if ids else ""
            d = nxt
        return ""
    # Kotlin/Swift/Scala: the name is a `simple_identifier`/`type_identifier` CHILD, with no `name` field.
    # Scoped to real declarations (NOT arrow_function/function_expression, whose first identifier is a param).
    if node.type in ("function_declaration", "function_definition", "class_declaration", "class_definition"):
        for c in node.children:
            if c.type in ("simple_identifier", "type_identifier", "identifier"):
                return _txt(c)
    # anonymous function bound to a name: `const f = () =>`, `exports.f =`, `module.exports = fn`, `{f: fn}`
    par = node.parent
    if par is not None and par.type in ("variable_declarator", "assignment", "assignment_expression", "pair"):
        nm = par.child_by_field_name("name") or par.child_by_field_name("left") or par.child_by_field_name("key")
        if nm is not None:
            txt = _txt(nm)
            if nm.type in ("member_expression", "attribute"):  # exports.foo / module.exports / a.b.foo
                seg = txt.split(".")[-1]
                return "default" if seg == "exports" else seg   # `module.exports = fn` -> the module default
            return txt
    return ""


def _cjs_export(node):
    """CommonJS export? `module.exports = fn`, `module.exports.foo = fn`, `exports.foo = fn`, or a func
    sitting in a `module.exports = {...}` object literal."""
    p = node.parent
    depth = 0
    while p is not None and depth < 5:
        t = p.type
        if t in ("statement_block", "function_definition", "function_declaration",
                 "method_definition", "arrow_function", "function_expression"):
            return False        # we've crossed into an enclosing scope -> not a direct export
        if t in ("assignment_expression", "assignment"):
            left = p.child_by_field_name("left")
            lt = _txt(left) if left is not None else ""
            if lt == "module.exports" or lt == "exports" or lt.startswith(("module.exports.", "exports.")):
                return True
            return False        # some other assignment -> stop
        p = p.parent
        depth += 1
    return False


def _is_exported(node, lang):
    if lang == "go":                                       # Go: an uppercase first letter = exported
        nm = _def_name(node)
        return bool(nm) and nm[:1].isupper()
    if lang in ("java", "csharp", "rust", "c", "cpp", "kotlin", "scala", "swift"):  # visibility from the sig
        head = _txt(node)[:100].lower()
        if lang == "rust":
            return "pub " in head or "pub(" in head
        if lang in ("java", "csharp"):
            return "public" in head or "protected" in head
        if lang in ("kotlin", "scala", "swift"):           # public by default; only `private` hides it
            return "private" not in head
        return True                                        # c/cpp: top-level functions are linkable
    if lang in ("bash", "lua", "perl", "haskell", "dart", "elixir"):  # top-level defs are callable
        return True
    p = node.parent
    depth = 0
    while p is not None and depth < 4:
        t = p.type
        if t in ("export_statement", "export_default_declaration"):
            return True
        if lang == "python" and t == "module":                 # top-level def in a module = importable
            return True
        if lang in ("ruby", "php") and t == "program":         # top-level def / public method = callable
            return True
        p = p.parent
        depth += 1
    return lang not in ("python", "ruby", "php") and _cjs_export(node)   # CommonJS: module.exports / exports.x


_ATTR_TYPES = ("attribute_item", "attribute_list", "attribute", "annotation", "marker_annotation")


def _decorators(node):
    """Decorators / attribute macros / annotations attached to a definition, ACROSS languages -- these are
    the primary route/entry-point signal (reachability + repomap read them):
      Python  @app.get(...)           -> a `decorated_definition` wrapper holds `decorator` children
      Rust    #[get("/x")]            -> `attribute_item` PRECEDING siblings (Rocket/Actix macros)
      Java    @GetMapping(...)        -> `annotation`/`marker_annotation` inside a `modifiers` child (Spring)
      C#      [HttpGet("x")]          -> `attribute_list` child or preceding sibling (ASP.NET)
      PHP     #[Route('/x')]          -> `attribute_list` preceding sibling (Symfony)
    Best-effort + defensive: an unknown grammar just yields nothing (same as before)."""
    out = []
    p = node.parent
    if p is not None and p.type == "decorated_definition":         # Python
        for c in p.children:
            if c.type == "decorator":
                out.append(_txt(c).strip())
    for c in node.children:                                        # Java/Kotlin modifiers, C# attribute_list
        if c.type == "modifiers":
            for cc in c.children:
                if cc.type in _ATTR_TYPES:
                    out.append(_txt(cc).strip())
        elif c.type in ("attribute_list", "attribute_item"):
            out.append(_txt(c).strip())
    sib = node.prev_sibling                                        # Rust/C#/PHP preceding attributes
    while sib is not None and sib.type in _ATTR_TYPES + ("line_comment", "block_comment", "comment"):
        if sib.type in _ATTR_TYPES:
            out.append(_txt(sib).strip())
        sib = sib.prev_sibling
    seen, uniq = set(), []                                         # dedup, preserve order
    for d in out:
        if d and d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def _params(node):
    """The parameter signature of a function/method, e.g. '(req, res)'. Best-effort, one line."""
    for fld in ("parameters",):
        p = node.child_by_field_name(fld)
        if p is not None:
            return " ".join(_txt(p).split())[:200]
    for c in node.children:
        if c.type in ("parameters", "formal_parameters", "method_parameters", "parameter_list"):
            return " ".join(_txt(c).split())[:200]
        if c.type in ("function_declarator",):             # c/cpp: params live inside the declarator
            for cc in c.children:
                if cc.type == "parameter_list":
                    return " ".join(_txt(cc).split())[:200]
        if c.type == "identifier":                        # arrow fn with a single bare param: x => ...
            return f"({_txt(c)})"
    return ""


def _module_doc(root, lang):
    """A cheap 'what this file does' line: Python module docstring or a JS/TS leading comment."""
    for c in root.children[:4]:
        if lang == "python" and c.type == "expression_statement":
            s = c.children[0] if c.children else None
            if s is not None and s.type == "string":
                return " ".join(_txt(s).strip("\"'` \n").split())[:200]
            return ""                                      # first stmt isn't a string -> no docstring
        if lang != "python" and c.type == "comment":
            return " ".join(_txt(c).lstrip("/*# ").rstrip("*/ ").split())[:200]
    return ""


def _elixir_def(node):
    """Elixir def/defp/defmodule are `call` MACROS, not distinct node types. Return ('func'|'module', name)
    or (None, None). `def get_user(id) do` = call(identifier 'def', arguments call(identifier 'get_user'...));
    `defmodule My.Ctrl do` = call(identifier 'defmodule', arguments alias 'My.Ctrl')."""
    if not node.children or node.children[0].type != "identifier":
        return None, None
    kw = _txt(node.children[0])
    args = node.child_by_field_name("arguments")
    if args is None:                                        # `arguments` is a child TYPE, not always a named field
        args = next((c for c in node.children if c.type == "arguments"), None)
    if args is None:
        return None, None
    if kw in ("def", "defp", "defmacro", "defmacrop"):
        for c in args.children:
            if c.type == "call" and c.children and c.children[0].type == "identifier":
                return "func", _txt(c.children[0])          # def name(args)
            if c.type == "identifier":
                return "func", _txt(c)                      # def name  (no parens)
    elif kw == "defmodule":
        for c in args.children:
            if c.type in ("alias", "identifier"):
                return "module", _txt(c)
    return None, None


def _walk(node, m, file, lang, enclosing, finfo, cls):
    t = node.type
    new_enc = enclosing
    new_cls = cls
    if lang == "elixir" and t == "call":                   # def/defmodule are macros -> handle, else fall through
        kind, name = _elixir_def(node)
        if kind == "func" and name:
            fobj = Func(name=name, file=file, line=node.start_point[0] + 1, end=node.end_point[0] + 1,
                        exported=True, sig=_params(node))
            m.funcs[name].append(fobj)
            if cls is not None:
                cls.methods.append(fobj)
            elif finfo is not None:
                finfo.functions.append(fobj)
                if name not in finfo.exports:
                    finfo.exports.append(name)
            for c in node.children:
                _walk(c, m, file, lang, name, finfo, cls)   # body calls attributed to this fn
            return
        if kind == "module" and name:
            c_obj = Cls(name=name, file=file, line=node.start_point[0] + 1, end=node.end_point[0] + 1,
                        exported=True)
            m.classes[name].append(c_obj)
            if finfo is not None:
                finfo.classes.append(c_obj)
                if name not in finfo.exports:
                    finfo.exports.append(name)
            for c in node.children:
                _walk(c, m, file, lang, enclosing, finfo, c_obj)   # defs inside = its methods
            return
        # not a def macro -> a real call: fall through to the generic _CALL handling below
    if t in _CLASS_DEF:
        cname = _def_name(node)
        if cname:
            c_obj = Cls(name=cname, file=file, line=node.start_point[0] + 1, end=node.end_point[0] + 1,
                        exported=_is_exported(node, lang), decorators=_decorators(node))
            m.classes[cname].append(c_obj)
            if finfo is not None:
                finfo.classes.append(c_obj)
                if c_obj.exported and cname not in finfo.exports:
                    finfo.exports.append(cname)
            new_cls = c_obj
    elif t in _FUNC_DEF:
        name = _def_name(node)
        if name:
            fobj = Func(name=name, file=file, line=node.start_point[0] + 1, end=node.end_point[0] + 1,
                        exported=_is_exported(node, lang), decorators=_decorators(node), sig=_params(node))
            m.funcs[name].append(fobj)
            if cls is not None:                            # a method of the enclosing class
                cls.methods.append(fobj)
            elif finfo is not None:                        # a top-level (module) function
                finfo.functions.append(fobj)
                if fobj.exported and name not in finfo.exports:
                    finfo.exports.append(name)
            new_enc = name
            new_cls = None                                 # nested defs in a fn body aren't class methods
    elif t in _CALL:
        callee = _callee_name(node)
        if callee:
            m.calls.append((enclosing, callee, file, node.start_point[0] + 1))
            m._callers[callee].add(enclosing)
            if callee in ("require", "require_relative", "__import__", "load", "autoload"):  # +ruby require
                args = node.child_by_field_name("arguments")
                if args is not None:
                    m.imports[file].add(_txt(args).strip("()\"' "))
    elif t in ("import_statement", "import_from_statement", "import_declaration",
               "require_once_expression", "require_expression", "include_expression",   # php
               "include_once_expression", "namespace_use_declaration",
               "import_spec", "using_directive", "use_declaration", "preproc_include"):  # go/c#/rust/c/cpp
        m.imports[file].add(" ".join(_txt(node)[:120].split()))
    for c in node.children:
        _walk(c, m, file, lang, new_enc, finfo, new_cls)


def build(target, progress=True):
    """Parse every source file under `target` into a CodeMap (structure + a per-file composition view).
    On a large repo this is the slowest deterministic step, so emit a heartbeat every 300 files."""
    from tree_sitter_language_pack import get_parser
    m = CodeMap()
    parsers = {}
    n = 0
    for f in _iter_files(target):
        lang = _EXT_LANG[f.suffix.lower()]
        try:
            src = f.read_bytes()
            if lang not in parsers:
                parsers[lang] = get_parser(lang)
            tree = parsers[lang].parse(src)
        except Exception:
            continue
        path = str(f)
        finfo = FileInfo(path=path, lang=lang, loc=src.count(b"\n") + 1,
                         doc=_module_doc(tree.root_node, lang))
        m.files[path] = finfo
        _walk(tree.root_node, m, path, lang, "<module>", finfo, None)
        finfo.imports = sorted(m.imports.get(path, ()))
        n += 1
        if progress and n % 300 == 0:
            print(f"[codemap] parsed {n} files ...", flush=True)
    return m
