import os
import signal
import re
import pandas as pd
from openai import AzureOpenAI
import glob
import logging
from new_sandbox import run_in_sandbox, extract_crash_type
from extract_feature_newv2 import extract_poc_features
from Combined_frameworks.interact_with_ollama import chat_with_ollama
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug_log.txt', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# TensorFlow version mapping
TF_VERSION_ENV = {
    "2.4.0": "testing2",
    "2.5.0": "testing25",
    "2.6.0": "testing26",
    "2.8.0": "testing1"
}

# Prompt Template for LLM Retry
def run_internal_sandbox(poc_code, tensorflow_version, file_path):
    """Integrated sandbox execution logic mirroring the original script's style."""
    # Strip markers
    poc_code_cleaned = re.sub(r'^```python\n|```$', '', poc_code, flags=re.MULTILINE).strip()
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(poc_code_cleaned)

    # Replicating the command chain from your provided example
    conda_init = 'eval "$(conda shell.bash hook)"'
    env_name = TF_VERSION_ENV.get(tensorflow_version)
    if not env_name:
        return False, f"No Conda environment configured for TensorFlow {tensorflow_version}"

    activate_command = f"conda activate {env_name}"
    run_script_command = f"python {file_path}"
    full_command = f"{conda_init} && {activate_command} && {run_script_command}"

    #run_script_command = f"python {file_path}"
    
    # Chain them exactly like the example
    full_command = f"{conda_init} && {activate_command} && {run_script_command}"

    try:
        # Crucial: Specify executable='/bin/bash' so the 'eval' and 'activate' work
        process = subprocess.Popen(
            full_command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            preexec_fn=os.setsid,
            executable='/bin/bash' 
        )
        
        try:
            # 10 second timeout as used in both scripts
            stdout, stderr = process.communicate(timeout=10)
            log_error = stderr.decode().strip()
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return False, "TimeoutExpired: No crash after 10 seconds"
            
    except Exception as e:
        return False, f"Execution error: {str(e)}"

    # Check for crash keywords
    keywords = ["abort", "segmentation fault", "check failed", "killed"]
    success = any(keyword in log_error.lower() for keyword in keywords)

    return success, log_error

def get_crash_type(log_text):
    """Integrated crash type extractor."""
    log_text = log_text.lower()
    if "segmentation fault" in log_text or "sigsegv" in log_text: return "SIGSEGV"
    if "abort" in log_text or "sigabrt" in log_text: return "SIGABRT"
    if "check failed" in log_text: return "Internal Check Failed"
    return "None"
def regenerate_variant_with_llm(original_code):
    logger.debug("Generating new variant with LLM")
    prompt_template = '''
You're an expert in machine learning vulnerability testing.

Given this failing TensorFlow PoC:
```python
{original_code}
```

Generate a modified variant to trigger:
- segmentation faults
- aborts (SIGABRT)
- heap/stack corruption
- TensorFlow raw_ops misuse
- check failed

Avoid try except block

Respond ONLY with Python code wrapped like:
```python
# Variant - [brief reason]
<code>
```
'''
    prompt = prompt_template.format(original_code=original_code)
    try:
        content = chat_with_ollama(prompt)
        logger.debug(f"LLM response for regeneration:\n{content[:500]}...")
        match = re.search(r"```python\n(.*?)```", content, re.DOTALL)
        if match:
            variant_code = match.group(1).strip()
            logger.debug(f"Parsed regenerated variant:\n{variant_code}")
            return variant_code
        else:
            logger.error("No valid code block found in LLM response")
            return None
    except Exception as e:
        logger.error(f"Azure OpenAI error: {e}")
        return None

# Prompt Template for Generating Mutants from Successful Variant Structure
def generate_mutants_from_structure(successful_code, output_dir, variant_count):
    logger.debug("Generating mutants from successful variant structure")
    prompt_template = '''
You're a security researcher specializing in machine learning vulnerability exploitation.

Given this successful TensorFlow PoC that triggered a crash:
```python
{successful_code}
```

Extract its structure (e.g., function calls, TensorFlow operations, data flows) and generate 3 new unique Python PoC variants that follow the same structure but introduce modifications to trigger:
- segmentation faults
- heap or stack corruption
- memory access violations
- aborts (SIGABRT)
- assertion failures
- misuse of TensorFlow raw_ops

Avoid try except block

Output the variants using this format:
```python
# Variant {num1} - [brief description]
<variant code>

# Variant {num2} - [brief description]
<variant code>

# Variant {num3} - [brief description]
<variant code>
```
Only include runnable Python code in each block. Ensure each variant is standalone, crash-oriented, and enclosed in ```python and ``` code blocks.
'''
    num1 = variant_count + 1
    num2 = variant_count + 2
    num3 = variant_count + 3
    prompt = prompt_template.format(
        successful_code=successful_code,
        num1=num1,
        num2=num2,
        num3=num3
    )
    try:
        output = chat_with_ollama(prompt_template)
        logger.debug(f"LLM response for mutant generation:\n{output[:500]}...")

        # Parse new mutants
        variant_pattern = re.compile(
            r"#\s*Variant\s*(\d+)\s*[-:–—]*\s*(.*?)\n+```python\n(.*?)\n*```",
            re.DOTALL | re.MULTILINE
        )
        matches = variant_pattern.findall(output)
        new_variants = []
        for num, desc, code in matches:
            filename = f"{output_dir}/Index_P{num}.py"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# Variant {num} - {desc.strip()}\n\n")
                f.write(code.strip() + "\n")
            logger.info(f"Saved new mutant: {filename}")
            new_variants.append((f"variant_{num}", f"# Variant {num} - {desc.strip()}\n\n{code.strip()}"))
        if not matches:
            logger.error(f"Could not parse mutants from LLM output. Sample:\n{output[:500]}")
        else:
            logger.info(f"Generated and saved {len(matches)} new mutants")
        return new_variants
    except Exception as e:
        logger.error(f"Error generating mutants: {e}")
        return []



# Load and parse variants from combined variants file
def load_variants(file_path):
    logger.debug(f"Loading variants from {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    logger.debug(f"File content (first 500 chars):\n{content[:500]}...")
    variant_pattern = re.compile(
        r"#\s*Variant\s*(\d+)\s*[-:–—]*\s*(.*?)(?:\n+```python\n(.*?)\n*```|\n+([\s\S]*?)(?=\n# Variant|\Z))",
        re.DOTALL | re.MULTILINE
    )
    matches = variant_pattern.findall(content)
    poc_dict = {}
    for num, desc, code_with_backticks, code_without_backticks in matches:
        name = f"variant_{num}"
        code = code_with_backticks if code_with_backticks else code_without_backticks
        poc_dict[name] = f"# Variant {num} - {desc.strip()}\n\n{code.strip()}"
        logger.debug(f"Parsed variant {name}: Description: {desc.strip()}\nCode (first 200 chars):\n{code.strip()[:200]}...")
    if not matches:
        logger.error(f"Failed to parse variants in {file_path}. Content sample:\n{content[:500]}")
    else:
        logger.info(f"Successfully parsed {len(matches)} variants from {file_path}")
    return poc_dict

# Save results to Excel
def save_to_excel(results, filename="sandbox_variant_results.xlsx"):
    logger.debug(f"Saving results to {filename}")
    df = pd.DataFrame(results, columns=[
        "Source File", "Variant", "TensorFlow Version", "Attempt",
        "Exploit Successful", "Crash Type", "Log Snippet", "Variant Code"
    ])
    df.to_excel(filename, index=False)
    logger.info(f"Results saved to {filename}")

# Main processing function
def process_pocs():
    csv_file = "tf_poc.csv"
    logger.debug(f"Reading CSV file: {csv_file}")
    try:
        df = pd.read_csv(csv_file)
        if "PoC Exploit Code" not in df.columns:
            raise ValueError("CSV file must contain a 'PoC Exploit Code' column")
        logger.info(f"Successfully loaded CSV with {len(df)} PoCs")
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        exit(1)

    results = []
    output_dir = "TF_generated_ourtool_40"
    os.makedirs(output_dir, exist_ok=True)

    for idx, row in df.iterrows():
        poc_code = row["PoC Exploit Code"]
        poc_id = row["Index"]
        if poc_id>40:
            continue
        logger.info(f"\nProcessing PoC {idx + 1}...")
        print(f"\nProcessing PoC {idx + 1}...")

        # Generate variants using LLM
        try:
            logger.debug(f"Sending LLM request for PoC {idx + 1}")
            prompt_poc = extract_poc_features(poc_code)
            prompt = prompt_poc['prompt_template']
            output = chat_with_ollama(prompt)
            logger.debug(f"LLM response for PoC {idx + 1} (first 500 chars):\n{output[:500]}...")
            print(f"Generated variants for PoC {idx + 1}")

            # Save combined variants
            combined_file = f"{output_dir}/all_variants_combined_{poc_id}.txt"
            with open(combined_file, "w", encoding="utf-8") as f:
                f.write(output)
            logger.info(f"Saved combined variants: {combined_file}")
            print(f"Saved combined variants: {combined_file}")

            # Parse and save individual variants
            variant_pattern = re.compile(
                r"#\s*Variant\s*(\d+)\s*[-:–—]*\s*(.*?)\n+```python\n(.*?)\n*```",
                re.DOTALL | re.MULTILINE
            )
            matches = variant_pattern.findall(output)

            if not matches:
                logger.error(f"Could not parse individual variants for PoC {idx + 1}. Output sample:\n{output[:500]}")
                print(f"[!] Could not parse individual variants for PoC {idx + 1}. Output sample:\n{output[:500]}")
                continue

            for var_idx, (number, description, code) in enumerate(matches, 0):
                filename = f"{output_dir}/Index_P{var_idx}.py"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"# Variant {number} - {description.strip()}\n\n")
                    f.write(code.strip() + "\n")
                logger.info(f"Saved: {filename}")
                print(f"Saved: {filename}")

        except Exception as e:
            logger.error(f"Error processing PoC {idx + 1}: {e}")
            print(f"Error processing PoC {idx + 1}: {e}")
            continue

        # Process variants from the combined file
        txt_file = combined_file
        logger.info(f"\nProcessing file: {os.path.basename(txt_file)}")
        print(f"\n[+] Processing file: {os.path.basename(txt_file)}")
        poc_dict = load_variants(txt_file)

        if not poc_dict:
            logger.error(f"No variants loaded from {txt_file}, skipping.")
            print(f"[!] No variants loaded from {txt_file}, skipping.")
            continue

        variant_count = len(matches)  # Track number of existing variants for naming new mutants
        for name, original_code in poc_dict.items():
            for tf_version in TF_VERSION_ENV:
                logger.info(f"\nTesting {name} on TensorFlow {tf_version}")
                print(f"\n[+] Testing {name} on TensorFlow {tf_version}")
                current_code = original_code
                final_result = {}

                for attempt in range(1, 4):
                    logger.debug(f"Attempt {attempt}/3 for {name} on TensorFlow {tf_version}")
                    print(f"  -> Attempt {attempt}/3")

                    if attempt == 1:
                        variant_code = current_code
                        logger.debug("Running original variant")
                        print("  [*] Running original variant")
                    else:
                        variant_code = regenerate_variant_with_llm(current_code)
                        if not variant_code:
                            logger.error("No variant generated, skipping.")
                            print("    [!] No variant generated, skipping.")
                            continue
                        current_code = variant_code

                    logger.debug(f"Variant code being tested:\n{variant_code}")
                    print("===== Variant Code Being Tested =====")
                    print(variant_code)
                    print("=====================================")

                    temp_file = "temp_variant_exec.py"
                    #success, logs = run_in_sandbox(variant_code, tf_version, temp_file)
                    success, logs = run_internal_sandbox(variant_code, tf_version, temp_file)
                    #crash_type = extract_crash_type(logs) if success else "None"
                    crash_type = get_crash_type(logs) if success else "None"

                    logger.debug(f"Crash Detected: {crash_type}\nLog Snippet: {logs[:300]}")
                    print(f"    -> Crash Detected: {crash_type}")

                    final_result = {
                        "Source File": os.path.basename(txt_file),
                        "Variant": name,
                        "TensorFlow Version": tf_version,
                        "Attempt": attempt,
                        "Exploit Successful": success,
                        "Crash Type": crash_type,
                        "Log Snippet": logs[:300].replace("\n", " "),
                        "Variant Code": variant_code
                    }

                    results.append(final_result)

                    if success:
                        logger.info(f"Successful crash detected for {name} on attempt {attempt}")
                        print(f"[*] Successful crash detected for {name} on attempt {attempt}")

                        # Generate and test new mutants based on successful variant structure
                        logger.info(f"Generating mutants for successful variant {name} on TensorFlow {tf_version}")
                        print(f"[*] Generating mutants for successful variant {name} on TensorFlow {tf_version}")
                        new_variants = generate_mutants_from_structure(variant_code, output_dir, variant_count)
                        variant_count += len(new_variants)  # Update variant count for next mutants

                        for mutant_name, mutant_code in new_variants:
                            logger.info(f"Testing new mutant {mutant_name} on TensorFlow {tf_version}")
                            print(f"[*] Testing new mutant {mutant_name} on TensorFlow {tf_version}")
                            temp_file = "temp_variant_exec.py"
                            success, logs = run_in_sandbox(mutant_code, tf_version, temp_file)
                            crash_type = extract_crash_type(logs) if success else "None"

                            logger.debug(f"Mutant {mutant_name} Crash Detected: {crash_type}\nLog Snippet: {logs[:300]}")
                            print(f"    -> Mutant Crash Detected: {crash_type}")

                            if success:
                                logger.info(f"Mutant {mutant_name} triggered a crash, adding as new variant")
                                print(f"[*] Mutant {mutant_name} triggered a crash, added as new variant")
                                poc_dict[mutant_name] = mutant_code  # Add to poc_dict for further processing
                                results.append({
                                    "Source File": os.path.basename(txt_file),
                                    "Variant": mutant_name,
                                    "TensorFlow Version": tf_version,
                                    "Attempt": 1,  # Mutants are treated as first attempt
                                    "Exploit Successful": success,
                                    "Crash Type": crash_type,
                                    "Log Snippet": logs[:300].replace("\n", " "),
                                    "Variant Code": mutant_code
                                })

                        break

    save_to_excel(results)
    logger.info(f"\nResults saved to 'sandbox_variant_results.xlsx'")
    print(f"\n[✓] Results saved to 'sandbox_variant_results.xlsx'")

if __name__ == "__main__":
    process_pocs()
