#!/usr/bin/env python3
import argparse
import json
import sys
import time
from pathlib import Path

current_script_dir = Path(__file__).resolve().parent
search_root = current_script_dir.parent.parent
files_to_find = ['rag_tool_ollama.py', 'interact_with_ollama.py']
for filename in files_to_find:
    found_files = list(search_root.rglob(filename))
    if found_files:
        folder_path = str(found_files[0].parent.resolve())
        if folder_path not in sys.path:
            sys.path.insert(0, folder_path)
    else:
        raise FileNotFoundError(f"Could not find '{filename}' anywhere inside the project.")

sys.path.insert(0, str(current_script_dir.parent.parent))
from libsndfile.libsndfile_tool import OUTPUT_DIR, POC_DIR, VAR_DIR, WORK_DIR, DATASET_PATH, T_SESSIONS, I_REFINEMENTS, RAG_TOP_K, OLLAMA_MODEL, OLLAMA_BASE_URL, log, build_rag_corpus, format_rag_context, generate_variants, ANCHOR_ID
import os
_OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'qwen2.5:72b')
_OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')

def main() -> None:
    parser = argparse.ArgumentParser(description='PoCE — libsndfile Variant Tool')
    parser.add_argument('--entry', default=None, help='Process only this ID')
    parser.add_argument('--sessions', type=int, default=T_SESSIONS)
    parser.add_argument('--refine', type=int, default=I_REFINEMENTS)
    parser.add_argument('--top-k', type=int, default=RAG_TOP_K)
    parser.add_argument('--model', default=_OLLAMA_MODEL)
    parser.add_argument('--ollama-url', default=_OLLAMA_BASE_URL)
    args = parser.parse_args()
    for d in [OUTPUT_DIR, VAR_DIR, WORK_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    log(f'[Variant-Tool] libsndfile variant generation  model={args.model}')
    if not DATASET_PATH.exists():
        log(f'[Variant-Tool] ERROR: dataset not found at {DATASET_PATH}')
        sys.exit(1)
    with open(DATASET_PATH, encoding='utf-8', errors='replace') as fh:
        entries = json.load(fh)
    all_entries = {e['ID']: e for e in entries}
    anchor = all_entries.get(ANCHOR_ID, entries[0])
    log('[Variant-Tool] Building RAG corpus ...')
    corpus = build_rag_corpus(entries)
    if args.entry:
        targets = [e for e in entries if e['ID'] == args.entry]
    else:
        targets = [e for e in entries if list((POC_DIR / e['ID']).glob('crafted_payload.*'))]
    if not targets:
        log('[Variant-Tool] No verified PoC entries found in POC/ directory')
        sys.exit(0)
    log(f'[Variant-Tool] Processing {len(targets)} verified entries')
    all_variants = []
    for entry in targets:
        eid = entry['ID']
        entry_dir = WORK_DIR / eid
        entry_dir.mkdir(parents=True, exist_ok=True)
        poc_files = list((POC_DIR / eid).glob('crafted_payload.*'))
        if not poc_files:
            log(f'[Variant-Tool] {eid} no crafted_payload file in POC/ — skipping')
            continue
        poc_script = next((POC_DIR / eid).glob('reproduce.py'), None)
        if poc_script is None:
            poc_scripts = list((POC_DIR / eid).glob('*.py'))
            poc_script = poc_scripts[0] if poc_scripts else None
        if poc_script is None:
            log(f'[Variant-Tool] {eid} no reproduce.py — skipping')
            continue
        verified_poc = poc_script.read_text()
        query = ' '.join(filter(None, [entry.get('Function Name', ''), entry.get('Vulnerability', '')]))
        from rag_tool_ollama import retrieve
        hits = retrieve(query, corpus, top_k=RAG_TOP_K, exclude_id=eid)
        rag_ctx = format_rag_context(hits, all_entries)
        log(f'[Variant-Tool] {eid} generating variants')
        variants = generate_variants(entry, verified_poc, rag_ctx, anchor, args.sessions, args.refine, entry_dir)
        all_variants.extend(variants)
        log(f'[Variant-Tool] {eid} → {len(variants)} variant(s)')
    log(f'[Variant-Tool] Done — {len(all_variants)} total variant(s)  output → {VAR_DIR}/')
if __name__ == '__main__':
    main()