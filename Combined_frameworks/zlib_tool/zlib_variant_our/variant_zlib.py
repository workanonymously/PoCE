import os
import re
import pandas as pd
import requests
from pathlib import Path
from extract_zlib_feature import extract_poc_features
from Combined_frameworks.interact_with_ollama import chat_with_ollama
# === Configuration ===

CSV_PATH = "zlib_pocs.csv"  # Replace with your actual file path
OUTPUT_DIR = "variant_outputs_zlib"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def chat_with_ollama(prompt, model=MODEL_NAME):
    headers = {"Content-Type": "application/json"}
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_API_URL, headers=headers, json=data)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception as e:
        print(f"Error communicating with Ollama: {e}")
        return None


def build_prompt(poc_code, variant_suggestions, mutatable_values, mutatable_dtypes, mutatable_sizes):
    prompt_poc = extract_poc_features(poc_code)
    prompt = prompt_poc['prompt_template']
    print(prompt)
    return prompt



def extract_and_save_variants(index, ollama_response):
    # Get content inside first ```python ... ``` block
    matches = re.findall(r"```(?:c|cpp)\n(.*?)```", ollama_response, re.DOTALL)
    if not matches:
        print(f"[Index {index}] No code block found.")
        return

    full_code_block = matches[0].strip()

    # Split using "# Variant X" style markers
    variant_chunks = re.split(r"(?=# Variant \d+)", full_code_block)

    for i, chunk in enumerate(variant_chunks):
        if not chunk.strip():
            continue
        filename = Path(OUTPUT_DIR) / f"Index_{index}_p{i}.c"
        with open(filename, "w") as f:
            f.write(chunk.strip())
        print(f"[Index {index}] Saved: {filename}")


def process_csv(csv_path):
    df = pd.read_csv(csv_path)
    for _, row in df.iterrows():
        index = row.get("Vul_Index")
        poc_code = row.get("PoC Exploit Code")
        variant_suggestions = row.get("variant_suggestions", "[]")
        mutatable_values = row.get("mutatable_values", "[]")
        mutatable_dtypes = row.get("mutatable_dtypes", "[]")
        mutatable_sizes = row.get("mutatable_sizes", "[]")

        if not isinstance(poc_code, str) or not poc_code.strip():
            print(f"[Index {index}] Skipping: missing PoC code.")
            continue

        print(f"[Index {index}] Generating prompt and sending to Ollama...")
        prompt = build_prompt(
            poc_code,
            variant_suggestions,
            mutatable_values,
            mutatable_dtypes,
            mutatable_sizes
        )

        response = chat_with_ollama(prompt)
        if response:
            extract_and_save_variants(index, response)
        else:
            print(f"[Index {index}] No response from Ollama.")


# === Entry Point ===
if __name__ == "__main__":
    process_csv(CSV_PATH)
