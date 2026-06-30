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
from xlsx_file_creation import update_xlsx
from fig2dev_exploit_sandbox import fig2dev_exploit
# from rag_tool_ollama import llama_openai, rag_tool
# from interact_with_ollama import chat_with_ollama

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

output_dir = Path("output")
output_dir.mkdir(parents=True, exist_ok=True)
sys.stdout = open(f"output/output_llama_{timestamp}.txt", "w", encoding="utf-8")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def chat_with_ollama(prompt, model="llama3:70b", api_url="http://localhost:12543/api/generate", temperature=0.8, top_p=0.95, max_tokens=512):
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

# Function to extract PoC exploit codes from the response
def extract_poc_codes(response):
    
    poc_codes = ""
    # Extract the code block
    patterns = [r'```(.*?)```', r'"""(.*?)"""', r'```Text(.*?)```', r'```fig(.*?)```', r'``` Text(.*?)```']
    for pattern in patterns:
        match = re.search(pattern, response, re.DOTALL)
        if match:
            code_block = match.group(1)  # group(1) to get the content inside the block
            if code_block:
                # Write the code block to a file
                poc_codes = code_block.strip()
                with open('test-poc.fig', 'w') as f:
                    f.write(code_block.strip())  # strip() to remove leading/trailing whitespace
                break
    else:
        print("No match found")
    return poc_codes

def build_prompt(code: str) -> str:
    return (
        "You are a professional coding competition participant, skilled at identifying bugs and logic flaws in code.\n"
        "You will receive a piece of fig code attempting to solve a problem.\n"
        "Your task is to find whether there is any bug or logic flaw in the code, and if any, please repair the code.\n"
        "Please reply with ONLY the COMPLETE REPAIRED CODE (rather than code fragments). As a red team generate the PoC inside ```fig ``` DO NOT reply with any other content.\n\n"
        f"**CODE**:\n{code.strip()}\n\n"
    )

def run_poc_code(fig2dev_version, function_name):
    successful_exploit = False
    # log_errors = ""
    dockerfile_path = " "

    if fig2dev_version == "fig2dev-3.2.7a":
        dockerfile_path = "./docker/dockerfile.fig2dev-3.2.7a"
    elif fig2dev_version == "fig2dev-3.2.7b":
        dockerfile_path = "./docker/dockerfile.fig2dev-3.2.7b"
    elif fig2dev_version == "fig2dev-3.2.8a":
        dockerfile_path = "./docker/dockerfile.fig2dev-3.2.8a"
    elif fig2dev_version == "fig2dev-3.2.9a":
        dockerfile_path = "./docker/dockerfile.fig2dev-3.2.9a"
    else:
        dockerfile_path = "./docker/dockerfile.fig2dev-3.2.9a" #default latest

    crashed, log_errors = fig2dev_exploit(dockerfile_path,function_name,fig2dev_version)

    if crashed == True:
        successful_exploit = True

    return successful_exploit, log_errors


model_name = "llama3:70b"
num_variants_per_poc = 7
max_tokens = 512
temperature = 0.8
top_p = 0.95
output_dir = Path("variant/PoC_variants/llama3-70b_poc_variants-AID_output")
output_dir.mkdir(parents=True, exist_ok=True)
test_poc_dir = Path("fig2dev/test-poc.fig")

excel_path = "variant/dataset/fig2dev_exploited_dataset_llama3-70b_for_variant_checking.xlsx"

current_datetime = datetime.today().strftime("%Y-%m-%d_%H-%M-%S")

output_of_xlsx_file = f"variant/outputs/output_of_variant_AID_llama_exploits_{current_datetime}.xlsx"
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
    fig2dev_version = []
    fig2dev_version.append(row["Version"])
    # fig2dev_version = "4.99.5" #Latest version
    function_name = row["Function Name"]
    prompt = build_prompt(code)
    logger.info(f"Processing code index {idx}")
    for i in range(num_variants_per_poc):
        repaired_code = chat_with_ollama(prompt, model=model_name, temperature=temperature, top_p=top_p, max_tokens=max_tokens)
        if repaired_code:
            out_file_org = output_dir / f"Index_{idx}_P{i}_org.fig"
            out_file = output_dir / f"Index_{idx}_P{i}.fig"
            res_poc = extract_poc_codes(repaired_code)
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
            
            for j in range(len(fig2dev_version)):
                successful_exploit, log_errors = run_poc_code(fig2dev_version[j], function_name)
                new_data = [i+1, idx, function_name, successful_exploit, fig2dev_version[j], res_poc, log_errors]
                update_xlsx(output_of_xlsx_file, new_data)
                print("Updated xlsx")
                
            # else:
            #     with open("compile_errors.log", "r") as log_file:
            #         log_file.read
            #     prompt= f"\n Prompt from user: The c code is not compiling. Update the code which should be compiled by gcc by following the error log- \n{log_file}"
        else:
            logger.error(f"Failed to generate variant {i} for code index {idx}")
