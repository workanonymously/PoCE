import os
import pandas as pd
from pathlib import Path
import requests
import logging
import re

import sys

from datetime import datetime
import csv
# from csv_file_creation import update_csv
from openpyxl import Workbook
from xlsx_file_creation import update_xlsx
from fig2dev_exploit_sandbox import fig2dev_exploit


timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

output_dir = Path("new_outputs/fig2dev_outputs/variant_our/outputs/llama")
output_dir.mkdir(parents=True, exist_ok=True)
sys.stdout = open(f"new_outputs/fig2dev_outputs/variant_our/outputs/llama/output_llama_{timestamp}.txt", "w", encoding="utf-8")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def chat_with_ollama(prompt, model="llama3:70b", api_url="http://localhost:12543/api/generate", temperature=0.8, top_p=0.95, max_tokens=512): # llama3:70b
# def chat_with_ollama(prompt, model="qwen2.5-coder:7b", api_url="http://localhost:15678/api/generate", temperature=0.8, top_p=0.95, max_tokens=512): # qwen2.5-coder:7b
# def chat_with_ollama(prompt, model="deepseek-r1:70b", api_url="http://localhost:23567/api/generate", temperature=0.8, top_p=0.95, max_tokens=512): # deepseek-r1:70b
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

# def build_prompt(PoC) -> str:
def build_prompt(code: str, cve, bug_type, crash_position, access_type, offset, access_size) -> str:
    prompt = f"""I am analyzing a memory corruption vulnerability in the fig2dev parser. 
    Here is a baseline PoC {code}.

Role: You are a vulnerability analysis assistant generating PoC variants. Your task is to modify an existing crashing input to expose additional bug impacts of the same root cause. You must preserve input structure and semantics. Do not invent new formats or logic. All changes must be minimal and localized. No need to execute from your end.

Your task: 
    Please generate a variant of this file that test the following edge cases: (Randomly choose one of the strategies / edge cases for each variant you generate)
    1. Integer Wrap-around: Modify the 'number of points' field (the 10th parameter in the object line) to a value near 2^(31)-1 or 2^(64)-1 while keeping the actual coordinate list short.
    2. Boundary Condition Mutation: Keep the large string of 'A's but significantly decrease the declared 'number of points' or 'comment length' to trigger a heap overflow during the read_objects loop.
    3. Recursive/Nested Objects: Wrap these malformed polylines inside a compound object (Type 6) with an invalid number of sub-objects to test deep recursion or pointer mismanagement.
    Please provide the output in raw FIG 3.2 format. Provide only the modified PoC variants inside ``` ``` in your response, without additional commentary. And give me one variant at a time.
   
Background Information:
    Approved Crash summary

    - Bug type: {bug_type}
    - Crash position: {crash_position}    #can be derived from ASAN report
    - Access type: {access_type} #can be derived from ASAN report
    - Offset beyond boundary: {offset} #can be derived from ASAN report
    - Access size: {access_size} #can be derived from ASAN report Read/write of size

    This crash behavior is confirmed and represents the root bug.

    Exploration Mode:

    In-depth mode:
    - Reach the same vulnerable code location
    - Modify numeric values to change memory offset, size, or access type
    - Keep control flow unchanged

    Breadth mode
    - Trigger the same root bug via different execution paths
    - Modify control-related numeric values (flags, counters, selectors)
    - Operate on the same or derived memory objects only


    Variant constraints:

    - Only modify existing numeric values
    - Apply small, localized changes (±1, ±2, boundaries, sign flips)
    - Do not add or remove required fields
    - Do not randomize the input
    - Do not fix/handle the vulnerability
    - Preserve parsing validity

    Now you’ll analyze the PoC and here’s your tasks

    - Generate the variant
    - Each variant must use a different mutation pattern
    - Output each variant clearly separated
    - For each variant, explain:
    #Numeric fields changed
    #Why parsing should still succeed
    #Expected new impact

    Provide only the modified PoC variant inside ``` ``` in your response, without additional commentary. The PoC should be start with a valid FIG 3.2 header such as "#FIG 3.2", don't start with anything else like "plaintext" or "fig" and give me one variant at a time.
    """

    # prompt = f"""I am analyzing a memory corruption vulnerability in the fig2dev parser. 
    # Here is a baseline PoC {PoC}.
    # Please generate a variant of this file that test the following edge cases: (Randomly choose one of the strategies / edge cases for each variant you generate)
    # 1. Integer Wrap-around: Modify the 'number of points' field (the 10th parameter in the object line) to a value near 2^(31)-1 or 2^(64)-1 while keeping the actual coordinate list short.
    # 2. Boundary Condition Mutation: Keep the large string of 'A's but significantly decrease the declared 'number of points' or 'comment length' to trigger a heap overflow during the read_objects loop.
    # 3. Recursive/Nested Objects: Wrap these malformed polylines inside a compound object (Type 6) with an invalid number of sub-objects to test deep recursion or pointer mismanagement.
    # Please provide the output in raw FIG 3.2 format. Provide only the modified PoC variants inside ``` ``` in your response, without additional commentary. And give me one variant at a time.
    # """
    return prompt

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

variant_dir = Path("new_outputs/fig2dev_outputs/variant_our/outputs/llama")
variant_dir.mkdir(parents=True, exist_ok=True)
output_dir = Path("new_outputs/fig2dev_outputs/variant_our/PoC_variants/llama")
output_dir.mkdir(parents=True, exist_ok=True)
test_poc_dir = Path("test-poc.fig")

excel_path = "fig2dev/fig2dev_variant_our/variant_dataset/fig2dev_exploited_dataset_llama3-70b_for_variant_checking.xlsx"

current_datetime = datetime.today().strftime("%Y-%m-%d_%H-%M-%S")


output_of_xlsx_file = f"new_outputs/fig2dev_outputs/variant_our/outputs/llama/output_of_variant_our_llama3-70b_exploits_{current_datetime}.xlsx"
wb = Workbook()
ws = wb.active

title_row = ["File number", "Vul_Idx", "Function Name",  "Successful Exploit", "Vulnerable Version", "Exploited PoC", "Log_Errors"]

ws.append(title_row)


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
    bug_type =row["Bug Type"]
    crash_position = row["Crash Position"]
    access_type = row["Access Type"]
    offset = row["Offset"]
    access_size = row["Access Size"]
    fig2dev_version = []
    fig2dev_version.append(row["Version"])
    # fig2dev_version = "4.99.5" #Latest version
    function_name = row["Function Name"]
    # prompt = build_prompt(code)
    prompt = build_prompt(code, idx, bug_type, crash_position, access_type, offset, access_size)
    logger.info(f"Processing code index {idx}")
    for i in range(num_variants_per_poc):
        # repaired_code = chat_with_ollama(prompt, model=model_name, temperature=temperature, top_p=top_p, max_tokens=max_tokens)
        repaired_code = chat_with_ollama(prompt, model=model_name)
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
            with open(test_poc_dir, "w") as f:
                f.write(res_poc)

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
