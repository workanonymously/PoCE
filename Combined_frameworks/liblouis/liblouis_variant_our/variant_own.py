
import os
import time
import requests
import pandas as pd
import re
import logging
import uuid
from sandbox import run_in_sandbox, extract_crash_type  # adjust module name accordingly
from extract_feature_liblouis_2 import extract_liblouis_features_from_code



from pathlib import Path

current_script_dir = Path(__file__).resolve().parent

search_root = current_script_dir.parent
input_data = search_root/ "liblouis_variant_our"/"dataset" / "poc.csv"

from datetime import datetime

run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

output_dir = Path("new_outputs") / "liblouis" / "liblouis_variants" / "output"
output_dir.mkdir(parents=True, exist_ok=True)

#output_txt = output_dir / f"output_{run_id}.txt"
output_xlsx = output_dir / f"variant_results_{run_id}.xlsx"

# === Logging Configuration ===
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def save_to_excel(results, filename=None):
    if filename is None:
        filename = output_dir / f"results_{run_id}.xlsx"

    logger.debug(f"Saving results to {filename}")

    try:
        df = pd.DataFrame(results, columns=[
            "Source File",
            "Variant",
            "Attempt",
            "Exploit Successful",
            "Crash Type",
            "Log Snippet",
            "Variant Code"
        ])

        df.to_excel(filename, index=False)
        logger.info(f"Results saved to {filename}")

    except Exception as e:
        logger.exception("Failed to save results to Excel: %s", e)

# === Prompt Builder ===
def build_prompt(poc_code):

    prompt_poc = extract_liblouis_features_from_code(poc_code)
    prompt = prompt_poc.get('prompt_template') if isinstance(prompt_poc, dict) else prompt_poc
    if not prompt:
        logger.warning("Extractor returned no prompt; falling back to minimal prompt.")
        prompt = f"Given this PoC:\n```c\n{poc_code}\n```\nGenerate 3 crash-focused fuzz-only C variants (no main)."
    print("Prompt:\n", prompt)
    return prompt

# === Chat with Ollama (robust) ===
def chat_with_ollama(poc_code, model="llama3:70b", url="http://localhost:11434/api/generate"):
    prompt = build_prompt(poc_code)
    headers = {"Content-Type": "application/json"}
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=1200)
    except Exception as e:
        logger.exception("Request to Ollama failed: %s", e)
        return None

    if not response.ok:
        logger.error("Ollama returned error %s: %s", response.status_code, response.text)
        return None

    # Try common response shapes
    try:
        j = response.json()
    except Exception:
        # fallback to raw text
        return response.text

    # try several keys that Ollama-like endpoints might use
    for key in ("response", "output", "result", "text"):
        if isinstance(j, dict) and key in j:
            val = j[key]
            # sometimes nested lists/dicts; try to normalize to a string
            if isinstance(val, list):
                try:
                    return " ".join([str(x) for x in val])
                except:
                    return str(val)
            return str(val)

    # last fallback: entire json dumped
    return str(j)

# === Extract Variants ===
def extract_variants_from_response(response_text):
    if not response_text:
        return []

    # Accept both '//' and '#' comment styles and optionally variant lines
    pattern = r'(?:^|\n)(?://|#|\s*)\s*Variant\s*\d+\s*-\s*.*?\n(.*?)(?=(?:\n(?:\s*(?://|#|\s*)\s*Variant\s*\d+)|\Z))'
    blocks = re.findall(pattern, response_text, flags=re.DOTALL | re.IGNORECASE)
    
    # If above misses, fallback to a more permissive split by lines that start with Variant
    if not blocks:
        splits = re.split(r'(?m)^(?:\s*(?://|#|\s*)\s*)?Variant\s*\d+\s*-\s*.*\n', response_text)
        blocks = [s.strip() for s in splits[1:] if s.strip()]
    
    # FIX: Only remove comment markers that are part of variant headers, not #include directives
    cleaned = []
    for b in blocks:
        # Remove ONLY the variant header comment markers, not #include directives
        # Split into lines and process only the first line if it's a comment
        lines = b.split('\n')
        if lines and (lines[0].lstrip().startswith('//') or lines[0].lstrip().startswith('#')):
            # Only remove from first line if it looks like a variant header comment
            first_line = lines[0].lstrip()
            if 'variant' in first_line.lower():
                lines[0] = re.sub(r'^\s*(//|#)\s*', '', lines[0])
        cleaned.append('\n'.join(lines).strip())
    
    return cleaned
# === Helper to pick CSV columns flexibly ===
def get_csv_columns(df):
    # primary names expected
    if "Index" in df.columns and "PoC Exploit Code" in df.columns:
        return "Index", "PoC Exploit Code"
    # fallback common variants
    for idx_col in ("Index"):
        for poc_col in ("PoC Exploit Code"):
            if idx_col in df.columns and poc_col in df.columns:
                return idx_col, poc_col
    # last resort: assume first two columns are index and code
    if len(df.columns) >= 2:
        return df.columns[0], df.columns[1]
    raise ValueError("CSV does not contain usable columns for index and PoC code.")

# === Main Script ===

def main(csv_path=input_data, output_xlsx=output_xlsx):
    if not os.path.exists(csv_path):
        logger.error("CSV path does not exist: %s", csv_path)
        return

    df = pd.read_csv(csv_path, dtype=str).fillna("")
    try:
        idx_col, poc_col = get_csv_columns(df)
    except Exception as e:
        logger.exception("Unable to find columns in CSV: %s", e)
        return

    all_results = []

    # Variant preamble with necessary includes
    VARIANT_PREAMBLE = (
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include \"liblouis.h\"\n"
    )

    for _, row in df.iterrows():
        idx = row.get(idx_col, "<no-index>")
        poc_code = row.get(poc_col, "")

        logger.info("Processing Index %s", idx)
        if not isinstance(poc_code, str) or not poc_code.strip():
            logger.warning("Skipping Index %s: Invalid or missing PoC code.", idx)
            continue

        response = chat_with_ollama(poc_code)
        if not response:
            logger.warning("Index %s: No response received.", idx)
            continue

        variants = extract_variants_from_response(response)
        if not variants:
            logger.warning("Index %s: No valid variants extracted.", idx)
            continue

        for i, variant_code in enumerate(variants):
            print("\n===== Variant Code Being Tested =====")
            print(variant_code)
            print("=====================================")

            # Create complete code with preamble
            complete_code = VARIANT_PREAMBLE + "\n" + variant_code
            
            # create a unique temp filename per attempt to avoid collisions
            base_temp = f"temp_variant_exec_{idx}_v{i+1}"
            attempt = 0
            max_attempts = 10
            success = False
            logs = ""
            crash_type = "None"

            while attempt < max_attempts and not success:
                attempt += 1
                temp_file = f"{base_temp}_{uuid.uuid4().hex[:8]}.c"
                logger.info("Attempt %d for Index %s Variant %d", attempt, idx, i + 1)
                try:
                    # Write the complete code to file
                    with open(temp_file, "w", encoding="utf-8") as f:
                        f.write(complete_code)

                    
               #     liblouis_version = "3.24"  
               #     success, logs = run_in_sandbox(complete_code, liblouis_version, temp_file)
               #     crash_type = extract_crash_type(logs)
                
                    liblouis_versions = ["3.24", "3.21", "3.6", "3.5", "2.5.2"]
                    results = {}

                    for version in liblouis_versions:
                        try:
                            success, logs = run_in_sandbox(complete_code, version, temp_file)
                            crash_type = extract_crash_type(logs)
                            results[version] = {
                                "success": success,
                                "crash_type": crash_type,
                                "logs": logs
                            }
                            print(f"Version {version}: {crash_type}")
                        except Exception as e:
                            results[version] = {
                                "success": False,
                                "crash_type": "TEST_ERROR",
                                "error": str(e)
                            }
                except Exception as e:
                    logger.exception("run_in_sandbox failed: %s", e)
                    success = False
                    logs = f"run_in_sandbox exception: {e}"
                    crash_type = "Exception"

                if success:
                    logger.info("Variant %d Crash Type: %s", i + 1, crash_type)
                else:
                    logger.debug("Attempt %d failed for Index %s Variant %d", attempt, idx, i + 1)
                
                # Clean up temp file
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
                
                # small sleep to avoid hammering sandbox rapidly
                time.sleep(0.2)
            
            result_entry = [
                f"Index_{idx}",
                f"Variant_{i+1}",
                attempt,
                bool(success),
                crash_type or "None",
                (logs or "")[:300].strip().replace('\n', ' '),  # shortened log
                variant_code  # Store original variant code without preamble
            ]
            all_results.append(result_entry)
    print(output_xlsx)
    print(type(output_xlsx))
    save_to_excel(all_results, filename=output_xlsx)
    logger.info("Finished processing CSV: %s", csv_path)

if __name__ == "__main__":
    main()
