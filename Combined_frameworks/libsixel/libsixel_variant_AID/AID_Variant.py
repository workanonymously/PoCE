import os
import pandas as pd
from pathlib import Path
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def chat_with_ollama(prompt, model="llama3:70b", api_url=" ", temperature=0.8, top_p=0.95, max_tokens=512):
    headers = {"Content-Type": "application/json"}
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens
        }
    }
    try:
        logger.info(f"Sending request to Ollama with model: {model}")
        response = requests.post(api_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        output = response.json()
        logger.info("Request successful")
        return output.get("response", "")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with Ollama API: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return None

def build_prompt(code: str) -> str:
    return (
        "You are a professional coding competition participant, skilled at identifying bugs and logic flaws in code.\n"
        "You will receive a piece of Python code attempting to solve a problem.\n"
        "Your task is to find whether there is any bug or logic flaw in the code, and if any, please repair the code.\n"
        "Please reply with ONLY the COMPLETE REPAIRED CODE (rather than code fragments) and DO NOT reply with any other content.\n\n"
        f"**CODE**:\n{code.strip()}\n\n"
    )

model_name = "llama3:70b"
num_variants_per_poc = 7
max_tokens = 512
temperature = 0.8
top_p = 0.95
output_dir = Path("variant/generated_poc_variants-AID")
output_dir.mkdir(parents=True, exist_ok=True)

csv_path = "variant/fig2dev_pocs.csv"
try:
    df = pd.read_csv(csv_path)
    logger.info(f"Loaded CSV: {csv_path}")
except FileNotFoundError:
    logger.error(f"CSV file not found: {csv_path}")
    raise
except Exception as e:
    logger.error(f"Error loading CSV: {str(e)}")
    raise

for _, row in df.iterrows():
    idx = row["Vul_Index"]
    code = row["PoC Exploit Code"]
    prompt = build_prompt(code)
    logger.info(f"Processing code index {idx}")
    for i in range(num_variants_per_poc):
        repaired_code = chat_with_ollama(prompt, model=model_name, temperature=temperature, top_p=top_p, max_tokens=max_tokens)
        if repaired_code:
            out_file = output_dir / f"Index_{idx}_P{i}.fig"
            with open(out_file, "w") as f:
                f.write(repaired_code.strip())
            logger.info(f"[✓] Saved: {out_file}")
        else:
            logger.error(f"Failed to generate variant {i} for code index {idx}")
