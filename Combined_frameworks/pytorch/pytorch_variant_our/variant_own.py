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
from pytorch.pytorch_tool import PROVEN_GADGETS, OUTPUT_DIR, POC_DIR, VAR_DIR, WORK_DIR, LOG_PATH, DATASET_PATH, RAG_DOCS_PATH, T_SESSIONS, I_REFINEMENTS, RAG_TOP_K, CONDA_ENV, ABLATION_NO_RAG, log, build_rag_corpus, format_rag_context, generate_variants
import os
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3.3:70b')
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')

def main() -> None:
    global OLLAMA_MODEL, OLLAMA_BASE_URL
    parser = argparse.ArgumentParser(description='PoCE — PyTorch Variant Tool')
    parser.add_argument('--entry', default=None, help='Process only this GHSA ID')
    parser.add_argument('--sessions', type=int, default=T_SESSIONS)
    parser.add_argument('--refine', type=int, default=I_REFINEMENTS)
    parser.add_argument('--top-k', type=int, default=RAG_TOP_K)
    parser.add_argument('--model', default=OLLAMA_MODEL)
    parser.add_argument('--ollama-url', default=OLLAMA_BASE_URL)
    args = parser.parse_args()
    OLLAMA_MODEL = args.model
    OLLAMA_BASE_URL = args.ollama_url
    for d in [OUTPUT_DIR, VAR_DIR, WORK_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    log(f'[Variant-Tool] PyTorch variant generation  model={OLLAMA_MODEL}')
    if not DATASET_PATH.exists():
        log(f'[Variant-Tool] ERROR: dataset not found at {DATASET_PATH}')
        sys.exit(1)
    with open(DATASET_PATH) as fh:
        summary = json.load(fh)
    entries = summary['poc_entries']
    all_entries = {e['id']: e for e in entries}
    log('[Variant-Tool] Building RAG corpus ...')
    corpus = build_rag_corpus(entries)
    if args.entry:
        targets = [e for e in entries if e['id'] == args.entry]
    else:
        targets = [e for e in entries if (POC_DIR / e['id'] / 'payload.pkl').exists()]
    if not targets:
        log('[Variant-Tool] No verified PoC entries found in POC/ directory')
        sys.exit(0)
    log(f'[Variant-Tool] Processing {len(targets)} verified entries for variant generation')
    all_variants = []
    for entry in targets:
        ghsa_id = entry['id']
        poc_pkl = POC_DIR / ghsa_id / 'payload.pkl'
        entry_dir = WORK_DIR / ghsa_id
        entry_dir.mkdir(parents=True, exist_ok=True)
        poc_script = next((f for f in (POC_DIR / ghsa_id).iterdir() if f.suffix == '.py'), None)
        if poc_script is None:
            log(f'[Variant-Tool] {ghsa_id} no reproduce.py in POC/ — skipping')
            continue
        verified_poc = poc_script.read_text()
        log(f'[Variant-Tool] {ghsa_id} generating variants from {poc_script.name}')
        variants = generate_variants(entry, verified_poc, corpus, all_entries, args.sessions, args.refine, entry_dir)
        all_variants.extend(variants)
        log(f'[Variant-Tool] {ghsa_id} → {len(variants)} variant(s)')
    log(f'[Variant-Tool] Done — {len(all_variants)} total variant(s)  output → {VAR_DIR}/')
if __name__ == '__main__':
    main()