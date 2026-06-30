import os
import signal
import subprocess
import time
import re

# TensorFlow version mapping
TF_VERSION_ENV = {
    "2.4.0": "conda activate testing2",
    "2.5.0": "conda activate testing25",
    "2.6.0": "conda activate testing26",
    "2.8.0": "conda activate testing1"
}

def run_in_sandbox(poc_code, tensorflow_version, file_path):
    """
    Execute PoC code in a sandboxed environment with the specified TensorFlow version.
    Returns a tuple: (success: bool, log: str)
    """
    # Strip ```python and ``` markers from the PoC code
    poc_code_cleaned = re.sub(r'^```python\n|```$', '', poc_code, flags=re.MULTILINE).strip()

    # Write cleaned PoC code to temporary file
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(poc_code_cleaned)

    # Construct command to run in the correct Conda environment
    conda_init = 'eval "$(conda shell.bash hook)"'
    activate_command = TF_VERSION_ENV.get(tensorflow_version, "conda activate testing2")
    run_command = f"python {file_path}"
    full_command = f"{conda_init} && {activate_command} && {run_command}"

    try:
        # Execute the PoC in a subprocess with a timeout
        process = subprocess.Popen(
            full_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        start_time = time.time()
        while process.poll() is None:
            if time.time() - start_time > 10:  # 10-second timeout
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(1)
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                return False, "TimeoutExpired: No crash after 10 seconds"

        _, stderr = process.communicate()
        log_error = stderr.decode().strip()

    except Exception as e:
        log_error = f"Execution error: {str(e)}"

    if not log_error:
        log_error = "No terminal output (possibly no crash or silent failure)"

    # Check for crash-related keywords
    keywords = [
        "abort", "segmentation fault", "core dumped", "check failed", "killed",
        "sigabrt", "sigsegv", "fatal", "terminated", "crashed", "f tensorflow/"
    ]
    log_error_lower = log_error.lower()
    success = any(keyword in log_error_lower for keyword in keywords)

    return success, log_error

def extract_crash_type(log_text):
    """
    Extract the type of crash from the log text.
    Returns a string indicating the crash type or 'None' if no crash detected.
    """
    log_text = log_text.lower()
    if "segmentation fault" in log_text or "sigsegv" in log_text:
        return "SIGSEGV"
    elif "abort" in log_text or "sigabrt" in log_text:
        return "SIGABRT"
    elif "core dumped" in log_text:
        return "Core Dump"
    elif "killed" in log_text:
        return "Killed"
    elif "check failed" in log_text:
        return "Internal Check Failed"
    return "None"
