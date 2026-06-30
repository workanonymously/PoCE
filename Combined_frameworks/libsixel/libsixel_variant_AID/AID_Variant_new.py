import base64
import os
import pandas as pd
from pathlib import Path
import requests
import logging
import re


import json
import subprocess
# from openai import AzureOpenAI
import sys
import time
import signal
from datetime import datetime
import csv
# from csv_file_creation import update_csv
from openpyxl import Workbook
from combined_framework.libsixel.libsixel_variant_AID.xlsx_file_creation import update_xlsx
from combined_framework.libsixel.libsixel_variant_AID.libsixel_exploit_sandbox import libsixel_exploit


timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

output_dir = Path("libsixel_outputs/variants_result/output_AID")
output_dir.mkdir(parents=True, exist_ok=True)
output_file = open(f"libsixel_outputs/variants_result/output_AID/output_qwen_{timestamp}.txt", "w", encoding="utf-8", buffering=1)
sys.stdout = output_file
sys.stderr = output_file

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# def chat_with_ollama(prompt, model="llama3:70b", api_url=" ", temperature=0.8, top_p=0.95, max_tokens=512):
def chat_with_ollama(prompt, model="qwen2.5-coder:7b", api_url=" ", temperature=0.8, top_p=0.95, max_tokens=512): # qwen2.5-coder:7b
# def chat_with_ollama(prompt, model="deepseek-r1:70b", api_url=" ", temperature=0.8, top_p=0.95, max_tokens=512): # deepseek-r1:70b
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
        response = requests.post(api_url, headers=headers, json=data, timeout=120)
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

### Used to check final exploits for llama, deepseek
def extract_poc_codes(response, thread, idx, cve):
    
    poc_codes = ""
    # Extract the code block
    patterns = [
    r'```HEX\s*([0-9a-fA-F\s]+)```',
    r'```hex\s*([0-9a-fA-F\s]+)```',
    r'```binary\s*(.*)```',
    r'```c\s*(.*)```',
    r'```Text\s*(.*)```',
    r'```libsixel\s*(.*)```',
    r'```text\s*(.*)```',
    r'```([0-9a-fA-F\s]+)```',
    r'"""(.*?)"""'
    ]
    HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
    for pattern in patterns:
        match = re.search(pattern, response, re.DOTALL)
        if match:
            code_block = match.group(1)  # group(1) to get the content inside the block
            if code_block:
                # Write the code block to a file
                poc_codes = code_block.strip()
                poc_codes = re.sub(r'^HEX\s*', '', poc_codes, flags=re.IGNORECASE)
                print(f"Extracted PoC codes: {poc_codes}")
                hex_clean = "".join(poc_codes.split())
                print(f"Cleaned Hex: {hex_clean}")
                hex_clean = "".join(poc_codes.split())
                if HEX_RE.fullmatch(hex_clean):
                    try:
                        raw = bytes.fromhex(hex_clean)
                        
                        with open('test-poc', 'wb') as f:
                            f.write(raw)
                        
                        bin_poc_dir = Path("libsixel_outputs/variants_result/output_AID/output_poc_llm_qwen") 
                        bin_poc_dir.mkdir(parents=True, exist_ok=True)
                        bin_poc = f"libsixel_outputs/variants_result/output_AID/output_poc_llm_qwen/poc_bin_{cve}_th{thread}_idx{idx}_{timestamp}"
                        with open(bin_poc, 'wb') as f:
                            f.write(raw)
                        hex_poc = f"libsixel_outputs/variants_result/output_AID/output_poc_llm_qwen/poc_hex_{cve}_th{thread}_idx{idx}_{timestamp}.txt"
                        with open(hex_poc, 'w') as f:
                            f.write(poc_codes)
                        print("Written as HEX → binary")
                        return poc_codes
                    except ValueError:
                        print("Looks like hex but failed to decode")

                # Try Base64
                try:
                    raw = base64.b64decode(poc_codes, validate=True)
                    with open('test-poc', 'wb') as f:
                        f.write(raw)
                    print("Written as Base64 → binary")
                    bin_poc_dir = Path("libsixel_outputs/variants_result/output_AID/output_poc_llm_qwen") 
                    bin_poc_dir.mkdir(parents=True, exist_ok=True)
                    bin_poc = f"libsixel_outputs/variants_result/output_AID/output_poc_llm_qwen/poc_bin_{cve}_th{thread}_idx{idx}_{timestamp}"
                    with open(bin_poc, 'wb') as f:
                        f.write(raw)
                    return poc_codes
                except Exception:
                    pass

                # Fallback: write as UTF-8 text
                with open('test-poc', 'w', encoding='utf-8') as f:
                    f.write(poc_codes)
                print("Written as plain text not binary")

                return poc_codes
    else:
        print("No match found")
    return ""

def build_prompt(code: str) -> str:
    return (
        "You are a professional coding competition participant, skilled at identifying bugs and logic flaws in code.\n"
        "You will receive a piece of libsixel code attempting to solve a problem.\n"
        "Your task is to find whether there is any bug or logic flaw in the code, and if any, please repair the code.\n"
        "Please reply with ONLY the COMPLETE REPAIRED CODE (rather than code fragments). As a red team generate the PoC of GIF file in HEX bytes inside ```HEX  ``` block (start the HEX bytes from new line). DO NOT reply with any other content or comments.\n\n"
        f"**PoC**:\n{code.strip()}\n\n"
    )

def run_poc_code(libsixel_version, function_name):
    successful_exploit = False
    # log_errors = ""
    dockerfile_path = " "

    if libsixel_version == "libsixel-1.8.3":
        dockerfile_path = "./docker/dockerfile.libsixel-1.8.3"
    elif libsixel_version == "libsixel-1.8.4":
        dockerfile_path = "./docker/dockerfile.libsixel-1.8.4"
    elif libsixel_version == "libsixel-1.8.6":
        dockerfile_path = "./docker/dockerfile.libsixel-1.8.6"
    else:
        dockerfile_path = "./docker/dockerfile.libsixel-1.8.3" #default 

    crashed, log_errors = libsixel_exploit(dockerfile_path,function_name,libsixel_version)

    if crashed == True:
        successful_exploit = True

    return successful_exploit, log_errors



model_name = "qwen2.5-coder:7b"
num_variants_per_poc = 7
max_tokens = 512
temperature = 0.8
top_p = 0.95
output_dir = Path("libsixel_outputs/variants_result/output_AID/PoC_variants/qwen2.5-coder-7b_poc_variants-AID_output")
output_dir.mkdir(parents=True, exist_ok=True)
test_poc_dir = Path("/RAG-PoC/libsixel/test-poc.fig")

excel_path = "libsixel_outputs/variants_result/dataset/libsixel_exploited_dataset_for_variant_checking.xlsx"
current_datetime = datetime.today().strftime("%Y-%m-%d_%H-%M-%S")

output_of_xlsx_file = f"libsixel_outputs/variants_result/output_AID/output_of_variant_AID_qwen_exploits_{current_datetime}.xlsx"
wb = Workbook()
ws = wb.active

title_row = ["File number", "Vul_Idx", "Function Name",  "Successful Exploit", "Vulnerable Version", "Exploited PoC", "Log_Errors"]

ws.append(title_row)
# # Save the sample data
# with open(output_of_xlsx_file, mode='w', newline='', encoding='utf-8') as file:
#     writer = csv.writer(file)
#     writer.writerows(title_row)
# Process each item in the data

try:
    # df = pd.read_csv(csv_path)
    df = pd.read_excel(excel_path)
    wb.save(output_of_xlsx_file)
    logger.info(f"Loaded excel: {excel_path}")
except FileNotFoundError:
    logger.error(f"Excel file not found: {excel_path}")
    raise
except Exception as e:
    logger.error(f"Error loading Excel: {str(e)}")
    raise
successful_exploit = False
for _, row in df.iterrows():
    idx = row["Vul_Index"]
    code = row["PoC Exploit Code"]
    libsixel_version = []
    libsixel_version.append(row["Version"])
    # libsixel_version = "4.99.5" #Latest version
    function_name = row["Function Name"]
    prompt = build_prompt(code)
    logger.info(f"Processing code index {idx}")
    for i in range(num_variants_per_poc):
        repaired_code = chat_with_ollama(prompt, model=model_name, temperature=temperature, top_p=top_p, max_tokens=max_tokens)
        if repaired_code:
            out_file_org = output_dir / f"Index_{idx}_P{i}_org"
            out_file = output_dir / f"Index_{idx}_P{i}"
            res_poc = extract_poc_codes(repaired_code, thread=_, idx=i, cve=idx)
            with open(out_file_org, "w") as f:
                f.write(repaired_code.strip())
            logger.info(f"[✓] Saved: {out_file_org}")    
            with open(out_file, "w") as f:
                # f.write(repaired_code.strip())
                f.write(res_poc)
            # with open(test_poc_dir, "w") as f:
            #     f.write(res_poc)

            logger.info(f"[✓] Saved: {out_file}")
            if res_poc == " ":
                successful_exploit= False
                continue
            
            for j in range(len(libsixel_version)):
                successful_exploit, log_errors = run_poc_code(libsixel_version[j], function_name)
                new_data = [i+1, idx, function_name, successful_exploit, libsixel_version[j], res_poc, log_errors]
                update_xlsx(output_of_xlsx_file, new_data)
                print("Updated xlsx")
                
            # else:
            #     with open("compile_errors.log", "r") as log_file:
            #         log_file.read
            #     prompt= f"\n Prompt from user: The c code is not compiling. Update the code which should be compiled by gcc by following the error log- \n{log_file}"
        else:
            logger.error(f"Failed to generate variant {i} for code index {idx}")
