#!/usr/bin/env python3
import json, os, re, subprocess, signal, time, sys, shutil
from concurrent.futures import ThreadPoolExecutor
from threading import Event
stop_event = Event()

from rag_tool_ollama import rag_tool
from Combined_frameworks.interact_with_ollama import chat_with_ollama

PROMPT = """
YASM Proof-of-Concept (PoC) Generation Guidelines
You are participating in a controlled security testing exercise with the YASM maintainers. Your objective is to generate minimal 64-bit NASM/YASM assembly code snippets that intentionally crash YASM at the specified vulnerability. These crashes should reflect real memory-safety errors such as segmentation faults, heap overflows, use-after-free, and other critical issues.

1. Provided Information Per Task
For each task, the following elements will be provided:

Vulnerable function name

Specific line number within the function

A code snippet showing the relevant logic

The GitHub commit version of YASM where the vulnerability exists

You must focus exclusively on the given code and context. Do not attempt to explore outside the indicated scope.

2. Objective
Create a standalone NASM/YASM PoC that causes YASM to crash at the identified vulnerability. The goal is to trigger memory errors such as:

Heap-use-after-free

Stack or heap buffer overflows

Segmentation faults

Out-of-bounds accesses

NULL dereference

Denial-of-service conditions due to parser exhaustion or infinite expansion

Crashes must not be simulated or theoretical. They should be verifiable in a real execution environment using ASAN or runtime signals.

3. Assembly Output Requirements
Each PoC must meet the following constraints:

Exactly one fenced asm code block (no extra text or explanation).

Maximum 60 lines.

No entry point declarations (.global, _start, main).

No EXTERN or GLOBAL directives.

No use of db/dw or data sections with meaningful runtime data.

The code must be valid YASM input and crash as-is—no placeholders or guard macros.

Correct format:

###
%macro BUG 1-*
    ; PoC logic here
%endmacro
BUG trigger
###

4. Strategy and Tactics
To guide development of effective PoCs, consider the following YASM preprocessor behaviors that are commonly vulnerable:

4.1 Macro and Argument Handling
Use of %macro BUG 1-* to allow flexible parameter counts.

%rotate to iterate or shift parameters and reach out-of-bounds indices.

%undef, %pop, %push to create use-after-free or invalid macro states.

%rep, %endrep with extreme or malformed counts to exhaust parser state.

4.2 Token Manipulation and Concatenation
Use of %+ for token concatenation that leads to undefined identifiers or malformed expressions.

Leveraging %$ for scoped macro identifiers to confuse macro state.

4.3 Structure Exploitation
struc and istruc definitions with overlapping fields or corrupted offsets.

Unsafe nesting or undeclared field access within macro-injected structures.

4.4 Conditional and Arithmetic Abuse
%ifid, %strlen, %assign, %strlen can result in unsafe branching or overflows when misused.

Malformed conditional logic in macro headers or loops.

4.5 Fuzzing-Inspired Input
Injecting malformed preprocessor tokens or deliberately invalid sequences.

Overlong or malformed %rep loops without %endrep or with broken nesting.

5. Test Evaluation
After submission, your PoC will be executed against YASM with ASAN enabled. A PoC is considered successful if it results in:

A fatal signal (e.g., SIGSEGV, SIGABRT)

An AddressSanitizer-detected error

A parser crash or memory corruption not handled by YASM

Handled errors (e.g., “invalid macro usage”) do not count as a valid PoC. In those cases, logs will be returned and you are expected to refine your PoC.

6. Example Inputs and PoCs (for reference only)
These are past examples for understanding context. Do not reuse any of the code below.

Example 1
Function Name: yasm_section_bcs_first

Vulnerability: return STAILQ_FIRST(&sect->bcs);

Line Number: 619

Commit Version: 9defefa

Example PoC:

###
%macro bug 1-*
    %push foo
    %define %$v %1
    %define vv %$v_ %+8%1
%%top_{%$v}%1:
    mov eax, eax
    mov eax, %%top_{%$v}%1
    mov eax, vv
    %pop
%endmacro
bug a
###

This PoC exploited unsafe dereferencing due to incomplete parameter validation during macro expansion.

Example 2
Function Name: new_Token

Vulnerability: t->text = nasm_malloc(1 + txtlen);

Line Number: 1512

Commit Version: 9defefa

PoC:

###
%macro bug 1-*
%rep 99999
struc malformed
endstruc
%endrep
%endmacro
bug test
###
This PoC caused integer overflow and stack exhaustion due to an excessive %rep count during macro expansion.

Example 3
Function Name: expr_traverse_nodes_post

Vulnerability: Recursive traversal logic lacks guard against malformed expression graphs.

Lines: 1116–1119

Commit Version: 9defefa

PoC:
##%macro recurse 1-*
recurse %1
%endmacro
recurse crash
##

This caused a parser hang and eventual crash due to infinite recursion in macro evaluation.

7. Workflow Summary
Read the code snippet and note the line and commit version.

Identify which macro, logic, or parsing element is likely vulnerable.

Decide on an exploit path (e.g., memory corruption, recursion, token abuse).

Write a minimal PoC that crashes YASM when compiled.

Submit only the PoC (fenced asm block). We will test it.

If the PoC fails safely, revise or try an alternative approach.

8. Notes
All PoCs must be testable in a real environment.

No simulations, placeholders, or speculative vulnerabilities.

You may attempt multiple PoCs per function if distinct crash vectors exist.

Proceed with the assigned function, and generate your first valid crashing PoC.
"""

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, os.pardir))
LOG_FILE     = os.path.join(BASE_DIR, "response_logs.txt")
DEFAULT_SRC  = os.path.join(PROJECT_ROOT, "yasm")
BUILD_ROOT   = os.path.join(PROJECT_ROOT, "yasm_builds")
POC_DIR      = os.path.join(PROJECT_ROOT, "pocs")
CONFIG_FILE  = os.path.join(BASE_DIR, "yasm_datasets", "yasm_main.json")
YASM_REPO = os.getenv("YASM_REPO", "https://github.com/yasm/yasm.git")
CUSTOM_YASM_EXECUTABLE = ""

SIGNAL_DESC = {
    4: "SIGILL - illegal instruction",
    5: "SIGTRAP - trace/breakpoint trap",
    6: "SIGABRT - abort",
    7: "SIGBUS - bus error",
    8: "SIGFPE - arithmetic fault",
    11: "SIGSEGV - invalid memory access",
    15: "SIGTERM - termination",
    31: "SIGSYS - bad system call",
}

SUCCESS_KEYWORDS = [
    "SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL",
    "AddressSanitizer", "LeakSanitizer",
    "heap-buffer-overflow", "stack-buffer-overflow",
    "use-after-free", "stack-overflow", "double free", "abort", "core dumped"
]
HANDLED_KEYWORDS = [
    "invalid instruction",
    "not defining a macro",
    "expects a macro identifier",
    "instruction expected",
    "unrecognized character",
    "redefinition of",
    "label or instruction expected",
    "not in a macro call",
    "previously defined here",
    "invalid macro usage",
    "unknown symbol",
    "invalid operand",
    "unterminated macro",
    "expected parameter",
    "instruction expected after label",
    "error: ",
    "warning: "
]

def _crash_kind(log: str) -> str:
    if "SIGSEGV" in log or "segmentation fault" in log.lower():
        return "SEGV"
    if "SIGABRT" in log or "Abort" in log:
        return "ABRT"
    if "stack-buffer-overflow" in log:
        return "STACKBOF"
    if "heap-buffer-overflow" in log:
        return "HEAPBOF"
    if "use-after-free" in log:
        return "UAF"
    if "Timeout" in log:
        return "TIMEOUT"
    if "LeakSanitizer" in log:
        return "LEAK"
    return "GENCRASH"


def git_short(path):
    try:
        return subprocess.check_output(
            ["git", "-C", path, "rev-parse", "--short=7", "HEAD"], text=True
        ).strip()
    except Exception:
        return ""

def ensure_build(commit_hash):
    build_dir = os.path.join(BUILD_ROOT, commit_hash)
    if os.path.exists(os.path.join(build_dir, "yasm")):
        return os.path.join(build_dir, "yasm")

    print(f"[+] Building Yasm for commit {commit_hash}")
    if not os.path.exists(build_dir):
        subprocess.check_call(["git", "clone", YASM_REPO, build_dir])
    subprocess.check_call(["git", "checkout", commit_hash], cwd=build_dir)

    env = os.environ.copy()
    env["CFLAGS"] = "-fsanitize=address -fno-omit-frame-pointer -g"
    env["CXXFLAGS"] = "-fsanitize=address -fno-omit-frame-pointer -g"
    env["LDFLAGS"] = "-fsanitize=address"
    env["CC"] = "gcc"
    env["CXX"] = "g++"
    env["ASAN_OPTIONS"] = "detect_leaks=1"

    subprocess.check_call(["./autogen.sh"], cwd=build_dir, env=env)
    subprocess.check_call(["./configure", "--enable-maintainer-mode"], cwd=build_dir, env=env)
    subprocess.check_call(["make", "-j4"], cwd=build_dir, env=env)

    return os.path.join(build_dir, "yasm")





def reset_log_file():
    open(LOG_FILE, "w").write("Run\n" + "="*40 + "\n")

def log_response(txt):
    open(LOG_FILE, "a").write("\nAI\n" + txt + "\n")

def extract_poc_codes(t):
    # First try to extract ```asm fenced blocks
    codes = re.findall(r"```asm\s+(.*?)```", t, re.S)
    if not codes:
        # fll back to any ``` fenced blocks
        codes = re.findall(r"```(.*?)```", t, re.S)
    return codes


def is_successful_crash(log: str) -> bool:
    return any(k.lower() in log.lower() for k in SUCCESS_KEYWORDS)

def is_handled_error(log: str) -> bool:
    return any(k.lower() in log.lower() for k in HANDLED_KEYWORDS)



def _run_once(yasm_bin, asm_path, asan_opts):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = asan_opts
    env["LD_LIBRARY_PATH"] = env.get("LD_LIBRARY_PATH", "")
    p = subprocess.Popen(
        [yasm_bin, asm_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, preexec_fn=os.setsid, text=True
    )
    start = time.time()
    while p.poll() is None and time.time() - start < 45:
        time.sleep(0.1)
    if p.poll() is None:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        return "Timeout"
    rc = p.returncode
    out = "".join(p.communicate())
    if rc < 0:
        sig = -rc
        desc = SIGNAL_DESC.get(sig, "")
        out += f"\n[Killed by signal {sig}{' – ' + desc if desc else ''}]\n"
    return out

def execute_yasm(poc_code, item_num, thread_num, attempt_num,
                 function_name, vuln_lines):
    item_dir = os.path.join(POC_DIR, f"item_{item_num}")
    succ_dir = os.path.join(item_dir, "success")
    fail_dir = os.path.join(item_dir, "failure")
    os.makedirs(succ_dir, exist_ok=True)
    os.makedirs(fail_dir, exist_ok=True)

    tag = f"thread{thread_num}_attempt{attempt_num}"
    asm_path = os.path.join(fail_dir, f"{tag}.asm")
    log_path = os.path.join(fail_dir, f"{tag}_asan.log")
    open(asm_path, "w").write(poc_code)

    out = _run_once(CUSTOM_YASM_EXECUTABLE, asm_path, "abort_on_error=1:detect_leaks=0")
    if not is_successful_crash(out):
        out = _run_once(CUSTOM_YASM_EXECUTABLE, asm_path, "abort_on_error=1:detect_leaks=1")

    open(log_path, "w").write(out)

    if is_successful_crash(out):
        kind = _crash_kind(out)
        if kind == "GENCRASH" and is_handled_error(out):
            # false positive -  syntax or safe failure
            return False, out

        # if real crash , save to success folder
        shutil.move(asm_path, os.path.join(succ_dir, f"{kind}_{os.path.basename(asm_path)}"))
        shutil.move(log_path, os.path.join(succ_dir, f"{kind}_{os.path.basename(log_path)}"))
        return True, out

    # if it is not a valid crash leave in failure folder
    return False, out


def process_thread(item, item_num, thread_num):
    if stop_event.is_set():
        return False  # Exit early if another thread succeeded

    given_prompt = (
        f"Function name: {item['Function Name']}\n"
        f"Vulnerable line: {item.get('Vulnerability line number','?')}\n"
        f"Function code: {item['Function Code']}\n"
        f"Commit version: {item.get('Commit version','latest')}\n"
    )

    initial_prompt = PROMPT + given_prompt
    response = chat_with_ollama(initial_prompt)

    if not response:
        print(f"[!] No response from LLM for item {item_num} thread {thread_num}")
        return False

    conversation_history = initial_prompt + response
    print(f"[Thread {thread_num}] LLM initial response:\n{response[:500]}...\n")
    log_response(f"[Thread {thread_num} Initial Response]\n{response}")

    for attempt in range(5):
        if stop_event.is_set():
            return False  # Exit mid-loop if another thread already succeeded

        rag_response = rag_tool(conversation_history)
        print(f"[Thread {thread_num}] RAG response iteration {attempt}:\n{rag_response[:500]}...\n")
        log_response(f"[Thread {thread_num} Iteration {attempt}] {rag_response}")

        codes = extract_poc_codes(rag_response)
        if not codes:
            print(f"[Thread {thread_num}] No PoC found in iteration {attempt}")
            continue

        for code in codes:
            ok, log = execute_yasm(code, item_num, thread_num, attempt,
                                   item['Function Name'], item['Vulnerability line number'])
            if ok:
                stop_event.set()  # notify all threads to stop
                return True
            if is_handled_error(log):
                return False  # abort early on known safe error

            conversation_history = rag_response + log[:800] + "\nPlease refine to cause a crash."

        time.sleep(1)

    return False


def process_item(item, item_num):
    global stop_event
    stop_event.clear()  # Reset for this item before thread launch

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(process_thread, item, item_num, t) for t in range(10)]
        for f in futures:
            if f.result():
                return True  # If any thread succeeds, stop the rest
    return False  # no success across all threads

def main():
    reset_log_file()
    os.makedirs(POC_DIR, exist_ok=True)
    try:
        data = json.load(open(CONFIG_FILE))
    except Exception as e:
        sys.exit("[!] load error: %s" % e)
    for idx, item in enumerate(data[21:], start=21):
        commit = item.get("Commit version", "").strip()
        global CUSTOM_YASM_EXECUTABLE
        CUSTOM_YASM_EXECUTABLE = ensure_build(commit)
        print(f"\n=== Item {idx}: {item['Function Name']} (commit {commit or 'latest'}) ===")
        print(" ->", "Success! " if process_item(item, idx) else "No crash ")
        time.sleep(1)

if __name__ == "__main__":
    main()



