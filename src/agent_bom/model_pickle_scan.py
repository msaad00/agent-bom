"""Safe pickle opcode disassembly for malicious-model detection.

Pickle deserialization is arbitrary-code-execution: a model shipped as a
pickle can run code on ``pickle.load`` / ``torch.load`` / ``joblib.load`` via
the ``__reduce__`` protocol. This module detects malicious models **without
ever deserializing them**.

It uses :func:`pickletools.genops`, which *walks* the opcode stream and yields
``(opcode, argument, position)`` tuples **without executing** any of them.
There is no ``pickle.load``, ``pickle.loads``, ``Unpickler``, ``torch.load``,
``joblib.load``, or ``find_class`` call anywhere in this module — the
no-execution guarantee of agent-bom is preserved.

Detection model
---------------
Dangerous code execution in a pickle is reachable through a small set of
opcodes:

* ``GLOBAL`` / ``STACK_GLOBAL`` — resolve an arbitrary ``module.callable``
  (e.g. ``posix system``). This is how attackers smuggle in ``os.system``.
* ``REDUCE`` — call the top-of-stack callable with the args tuple. This is the
  trigger that turns a smuggled ``os.system`` reference into execution.
* ``BUILD`` / ``INST`` / ``OBJ`` / ``NEWOBJ`` / ``NEWOBJ_EX`` — object
  construction primitives that can invoke ``__setstate__`` / ``__init__`` on
  attacker-chosen classes.

A pickle that imports a dangerous module/callable (``os``, ``subprocess``,
``builtins.eval``/``exec`` …) is flagged. When that import is combined with a
``REDUCE`` (the actual call), it is classified malicious at CRITICAL severity.
A pickle that only contains tensor/primitive opcodes is clean.

Bounds
------
Both the number of opcodes walked and the bytes read are bounded so a crafted
file cannot DoS the scanner. Truncated or garbage input never raises; it is
reported as a safe ``ERROR``/``TRUNCATED`` outcome.
"""

from __future__ import annotations

import io
import logging
import os
import pickletools
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Tunable safety bounds (override via env, all read once on demand) ──
# A normal model pickle resolves a handful of globals and is small relative to
# the weight payload; these ceilings are generous for benign files but cap the
# work an adversarial file can force.
_MAX_OPCODES = 1_000_000
_MAX_PICKLE_BYTES = 256 * 1024 * 1024  # 256 MiB per embedded pickle stream
_MAX_ZIP_MEMBERS = 4096
_MAX_EMBEDDED_PICKLES = 64
# Bound the string-operand stack and the memo so an adversarial file with
# millions of strings/memo entries cannot exhaust memory while we model the
# stack to recover STACK_GLOBAL operands.
_MAX_STR_STACK = 4096
_MAX_MEMO_ENTRIES = 200_000

# String-pushing opcodes whose operands can become a STACK_GLOBAL module/name.
_STRING_OPCODES = frozenset({"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"})
# Memo store/load opcodes. Tracking them defeats evasion that hides the
# dangerous operands behind the memo (PUT/BINPUT then a later BINGET) instead of
# leaving them as the most recent literal strings.
_MEMO_PUT_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_MEMO_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})

# Extensions whose contents may be (or may embed) a pickle stream.
PICKLE_BEARING_EXTENSIONS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".npy", ".ckpt", ".model"})

# Opcodes that *enable* code execution. Presence alone is suspicious; presence
# of a dangerous global import is what makes a pickle malicious.
_CODE_EXEC_OPCODES = frozenset(
    {
        "GLOBAL",
        "STACK_GLOBAL",
        "REDUCE",
        "BUILD",
        "INST",
        "OBJ",
        "NEWOBJ",
        "NEWOBJ_EX",
    }
)

# The opcode that actually *invokes* a callable — the trigger that turns a
# smuggled reference into execution.
_CALL_OPCODES = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"})

# Modules whose import inside a pickle is a strong malicious signal: they grant
# process / shell / network / dynamic-import capability.
_DANGEROUS_MODULES = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "sys",
        "socket",
        "shutil",
        "pty",
        "runpy",
        "importlib",
        "ctypes",
        "multiprocessing",
        "threading",
        "asyncio",
        "commands",
        "popen2",
        "platform",
        "webbrowser",
        "pip",
        "pdb",
        "bdb",
        "code",
        "codeop",
        "timeit",
        "venv",
        "smtplib",
        "ftplib",
        "telnetlib",
        "urllib",
        "urllib2",
        "requests",
        "httplib",
    }
)

# Specific ``module.callable`` pairs that are dangerous regardless of module
# (e.g. ``builtins.eval``). Stored as ``"module.callable"`` lowercase keys.
_DANGEROUS_CALLABLES = frozenset(
    {
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
        "builtins.__import__",
        "builtins.getattr",
        "builtins.setattr",
        "builtins.open",
        "builtins.input",
        "builtins.breakpoint",
        "__builtin__.eval",
        "__builtin__.exec",
        "__builtin__.compile",
        "__builtin__.__import__",
        "__builtin__.getattr",
        "__builtin__.open",
        "operator.attrgetter",
        "operator.methodcaller",
        "functools.reduce",
    }
)

# Callable names that are dangerous even with an unexpected module qualifier
# (covers ``os.system``, ``subprocess.Popen``, vendored shims, etc.).
_DANGEROUS_CALLABLE_NAMES = frozenset(
    {
        "system",
        "popen",
        "spawn",
        "spawnl",
        "spawnv",
        "exec",
        "execv",
        "execve",
        "execl",
        "eval",
        "compile",
        "call",
        "check_call",
        "check_output",
        "run",
        "popen2",
        "popen3",
        "popen4",
        "fork",
        "forkpty",
        "remove",
        "unlink",
        "rmtree",
        "connect",
        "getoutput",
        "getstatusoutput",
        "load_module",
        "import_module",
        "loads",
        "load",
        "fromstring",
    }
)


@dataclass
class PickleScanResult:
    """Outcome of disassembling one logical pickle target (file or member)."""

    path: str
    member: str | None = None  # zip member name when scanned from an archive
    is_pickle: bool = False
    truncated: bool = False
    error: str | None = None
    opcodes_scanned: int = 0
    code_exec_opcodes: list[str] = field(default_factory=list)
    has_reduce: bool = False
    dangerous_imports: list[str] = field(default_factory=list)  # "module.callable"
    severity: str | None = None  # CRITICAL | HIGH | MEDIUM | None
    verdict: str = "clean"  # clean | suspicious | malicious | error | not_pickle
    oversize_unscanned: bool = False  # member exceeded the byte cap; tail unscanned
    declared_size: int | None = None  # declared (uncompressed) size when oversize

    def to_security_flag(self) -> dict | None:
        """Render a ``security_flags``-shaped dict, or ``None`` when clean."""
        if self.verdict in {"clean", "not_pickle"}:
            if self.oversize_unscanned:
                # A pickle-bearing member larger than the byte cap could only be
                # disassembled up to the cap; bytes beyond it are UNVERIFIED. Fail
                # safe — surface a finding even when the scanned prefix is clean,
                # because an attacker can pad a malicious pickle past the cap to
                # evade the scanner.
                location = f" (zip member {self.member})" if self.member else ""
                size_note = f"declared size {self.declared_size} bytes; " if self.declared_size else ""
                return {
                    "severity": "HIGH",
                    "type": "OVERSIZE_PICKLE_UNSCANNED",
                    "description": (
                        f"Pickle-bearing member{location} exceeds the scan byte cap "
                        f"({size_note}cap {_max_pickle_bytes()} bytes); only the leading slice was "
                        "disassembled and the remainder was NOT scanned. Padding a pickle past the "
                        "cap is a known evasion — treat as suspicious; prefer safetensors/ONNX or "
                        "raise AGENT_BOM_PICKLE_MAX_BYTES to scan it fully."
                    ),
                }
            return None
        if self.verdict == "error":
            return {
                "severity": "LOW",
                "type": "PICKLE_SCAN_ERROR",
                "description": (f"Pickle opcode scan could not complete (no deserialization attempted): {self.error}"),
            }
        location = f" (zip member {self.member})" if self.member else ""
        imports = ", ".join(sorted(set(self.dangerous_imports))[:12]) or "none captured"
        opcodes = ", ".join(sorted(set(self.code_exec_opcodes)))
        return {
            "severity": self.severity or "HIGH",
            "type": "MALICIOUS_PICKLE" if self.verdict == "malicious" else "SUSPICIOUS_PICKLE",
            "description": (
                f"Pickle opcode disassembly{location} found code-execution opcodes "
                f"[{opcodes}] referencing dangerous imports [{imports}]. "
                "Detected by static opcode walk (pickletools.genops); the model was NOT deserialized. "
                "Treat as a potential supply-chain implant — prefer safetensors/ONNX."
            ),
            "dangerous_imports": sorted(set(self.dangerous_imports)),
            "code_exec_opcodes": sorted(set(self.code_exec_opcodes)),
        }


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _max_opcodes() -> int:
    return _int_env("AGENT_BOM_PICKLE_MAX_OPCODES", _MAX_OPCODES)


def _max_pickle_bytes() -> int:
    return _int_env("AGENT_BOM_PICKLE_MAX_BYTES", _MAX_PICKLE_BYTES)


def _normalize_global(arg: object) -> tuple[str, str] | None:
    """Extract ``(module, callable)`` from a GLOBAL/STACK_GLOBAL argument.

    ``GLOBAL`` yields a string ``"module callable"`` (space-separated).
    ``STACK_GLOBAL`` takes its operands from the stack, so ``arg`` is ``None``;
    those are recovered separately from the preceding string opcodes.
    """
    if not isinstance(arg, str):
        return None
    parts = arg.split(" ", 1) if " " in arg else arg.rsplit("\n", 1)
    if len(parts) != 2:
        return None
    module, name = parts[0].strip(), parts[1].strip()
    if not module and not name:
        return None
    return module, name


def _classify_global(module: str, name: str) -> str | None:
    """Return a danger label for a ``module.callable`` import, or None.

    The label is the captured ``module.callable`` string when dangerous.
    """
    mod = module.lower()
    nm = name.lower()
    qualified = f"{mod}.{nm}"
    if qualified in _DANGEROUS_CALLABLES:
        return f"{module}.{name}"
    if mod in _DANGEROUS_MODULES:
        return f"{module}.{name}"
    if nm in _DANGEROUS_CALLABLE_NAMES:
        return f"{module}.{name}"
    return None


def _scan_opcode_stream(data: bytes, path: str, member: str | None) -> PickleScanResult:
    """Disassemble a single pickle byte stream via ``pickletools.genops``.

    NEVER deserializes. Walks opcodes only, capturing dangerous globals and the
    presence of code-execution opcodes. Bounded by opcode count and never
    raises on malformed input.
    """
    result = PickleScanResult(path=path, member=member)
    if not data:
        result.verdict = "not_pickle"
        return result

    # A valid pickle starts with PROTO (\x80) for protocol >= 2, or a protocol-0
    # opcode. We do not require this — genops tolerates protocol 0/1 — but a
    # stream with no recognizable first opcode falls through to the except.
    max_ops = _max_opcodes()
    # Model the operand stack and the pickle memo so STACK_GLOBAL's module/name
    # are recovered even when an adversary parks them in the memo (PUT/BINPUT)
    # and replays them via GET/BINGET, instead of leaving them as the last
    # literal strings. ``None`` marks an opaque (non-string) stack value.
    str_stack: list[str | None] = []
    memo: dict[int, str | None] = {}
    memo_index = 0  # auto-incrementing index assigned by MEMOIZE
    code_exec: set[str] = set()
    dangerous: list[str] = []
    unresolved_globals: list[str] = []  # globals whose operands we could not recover
    saw_call = False

    def _push(value: str | None) -> None:
        str_stack.append(value)
        if len(str_stack) > _MAX_STR_STACK:
            del str_stack[: len(str_stack) - _MAX_STR_STACK]

    try:
        # genops is a generator that statically parses opcodes; it does not
        # build or execute the pickled object graph.
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            result.is_pickle = True
            result.opcodes_scanned += 1
            if result.opcodes_scanned > max_ops:
                result.truncated = True
                break

            name = opcode.name

            # Track string operands and the memo so we can reconstruct the
            # module + callable that STACK_GLOBAL pops off the stack.
            if name in _STRING_OPCODES:
                _push(arg if isinstance(arg, str) else None)
                continue
            if name == "MEMOIZE":
                if len(memo) < _MAX_MEMO_ENTRIES:
                    memo[memo_index] = str_stack[-1] if str_stack else None
                memo_index += 1
                continue
            if name in _MEMO_PUT_OPCODES:
                if isinstance(arg, int) and len(memo) < _MAX_MEMO_ENTRIES:
                    memo[arg] = str_stack[-1] if str_stack else None
                continue
            if name in _MEMO_GET_OPCODES:
                _push(memo.get(arg) if isinstance(arg, int) else None)
                continue

            if name in _CODE_EXEC_OPCODES:
                code_exec.add(name)
            if name in _CALL_OPCODES:
                saw_call = True

            if name == "GLOBAL":
                parsed = _normalize_global(arg)
                if parsed is None:
                    # Operand could not be parsed — fail safe, do not ignore.
                    unresolved_globals.append("?.?")
                else:
                    label = _classify_global(*parsed)
                    if label:
                        dangerous.append(label)
            elif name == "STACK_GLOBAL":
                # operands are the two top stack values: module then name
                # (name pushed last), resolved through the memo above.
                callable_name = str_stack.pop() if str_stack else None
                module = str_stack.pop() if str_stack else None
                if isinstance(module, str) and isinstance(callable_name, str):
                    label = _classify_global(module, callable_name)
                    if label:
                        dangerous.append(label)
                else:
                    # Operands hidden behind the memo / produced by non-string
                    # opcodes could not be fully recovered. Fail safe: never
                    # silently ignore an unresolved dynamic import.
                    unresolved_globals.append(
                        f"{module if isinstance(module, str) else '?'}.{callable_name if isinstance(callable_name, str) else '?'}"
                    )
            else:
                # Any other value-producing opcode pushes an opaque value; record
                # it so stale strings cannot masquerade as a later STACK_GLOBAL
                # operand.
                _push(None)
    except Exception as exc:  # noqa: BLE001 — any malformed-pickle error is SAFE here
        # genops raises on truncated/garbage streams. We never propagate; a
        # broken pickle is reported, not crashed on.
        if result.is_pickle:
            result.truncated = True
            result.error = f"opcode stream ended early: {exc}"
        else:
            result.verdict = "not_pickle"
            result.error = str(exc)
            return result

    result.has_reduce = "REDUCE" in code_exec
    result.code_exec_opcodes = sorted(code_exec)
    result.dangerous_imports = dangerous + [f"unresolved:{ref}" for ref in unresolved_globals]

    if not result.is_pickle:
        result.verdict = "not_pickle"
        return result

    if dangerous and (saw_call or result.has_reduce):
        result.verdict = "malicious"
        result.severity = "CRITICAL"
    elif dangerous or unresolved_globals:
        # Dangerous import present but no call opcode observed (e.g. truncated
        # before REDUCE), or a global whose operands could not be recovered —
        # still a suspicious supply-chain signal that must not be ignored.
        result.verdict = "suspicious"
        result.severity = "HIGH"
    else:
        result.verdict = "clean"
    return result


def _looks_like_zip(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06"


def _scan_zip(data: bytes, path: str) -> list[PickleScanResult]:
    """Find and scan embedded pickle members inside a torch/zip archive.

    Torch ``.pt`` files are ZIP archives containing ``data.pkl`` (and shards).
    We enumerate members and disassemble those that are pickle streams, without
    extracting to disk and without deserializing.
    """
    results: list[PickleScanResult] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = zf.namelist()[:_MAX_ZIP_MEMBERS]
            scanned = 0
            for member in members:
                if scanned >= _MAX_EMBEDDED_PICKLES:
                    break
                lower = member.lower()
                # Torch stores the pickle as data.pkl / *.pkl; also scan any
                # member that begins with the pickle PROTO opcode.
                try:
                    info = zf.getinfo(member)
                except KeyError:
                    continue
                if info.is_dir():
                    continue
                # An oversized member is NOT silently skipped: a pickle padded
                # past the cap would otherwise evade scanning entirely. We still
                # disassemble the leading slice (bounded read keeps the DoS cap)
                # and flag the unscanned remainder as suspicious below.
                cap = _max_pickle_bytes()
                oversize = info.file_size > cap
                try:
                    with zf.open(member) as fh:
                        head = fh.read(2)
                        is_pkl_ext = lower.endswith((".pkl", ".pickle"))
                        starts_pickle = head[:1] == b"\x80"  # PROTO
                        if not (is_pkl_ext or starts_pickle):
                            continue
                        body = head + fh.read(cap)
                except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                    results.append(PickleScanResult(path=path, member=member, error=f"could not read zip member: {exc}", verdict="error"))
                    continue
                res = _scan_opcode_stream(body, path=path, member=member)
                if oversize:
                    res.oversize_unscanned = True
                    res.declared_size = info.file_size
                results.append(res)
                scanned += 1
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        results.append(PickleScanResult(path=path, error=f"not a readable zip archive: {exc}", verdict="error"))
    return results


def scan_pickle_file(file_path: str | Path) -> list[PickleScanResult]:
    """Disassemble a model file's pickle opcodes WITHOUT deserializing it.

    Handles three shapes safely:

    * a raw pickle stream (``.pkl`` / ``.pickle`` / ``.joblib`` / many ``.bin``),
    * a torch ZIP container (``.pt`` / ``.pth`` / ``.ckpt``) embedding pickle(s),
    * truncated / non-pickle / garbage input → a safe ``error``/``not_pickle``
      result, never an exception.

    Returns a list because a zip container may embed several pickle members.
    The scanner reads at most ``AGENT_BOM_PICKLE_MAX_BYTES`` and walks at most
    ``AGENT_BOM_PICKLE_MAX_OPCODES`` opcodes per stream.
    """
    p = Path(file_path)
    path_str = str(p)
    try:
        with open(p, "rb") as fh:
            data = fh.read(_max_pickle_bytes() + 1)
    except OSError as exc:
        return [PickleScanResult(path=path_str, error=f"could not open file: {exc}", verdict="error")]

    if not data:
        return [PickleScanResult(path=path_str, verdict="not_pickle")]

    if len(data) > _max_pickle_bytes():
        # Truncate the working buffer to the cap; opcode walk still bounded.
        data = data[: _max_pickle_bytes()]

    if _looks_like_zip(data):
        return _scan_zip(data, path=path_str)

    return [_scan_opcode_stream(data, path=path_str, member=None)]


def scan_pickle_file_flags(file_path: str | Path) -> tuple[list[dict], list[PickleScanResult]]:
    """Convenience wrapper: scan a file and return ``security_flags`` dicts.

    Returns ``(flags, raw_results)``. ``flags`` is the list of non-clean
    security-flag dicts ready to extend a model file's ``security_flags``.
    """
    results = scan_pickle_file(file_path)
    flags: list[dict] = []
    for res in results:
        flag = res.to_security_flag()
        if flag is not None:
            flags.append(flag)
    return flags, results
