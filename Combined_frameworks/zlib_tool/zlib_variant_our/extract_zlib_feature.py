import re
import subprocess
import io
import contextlib
from pathlib import Path

def parse_zlib_h(file_path):
    """
    Parse zlib.h to extract function descriptions and error codes.
    
    Args:
        file_path (str): Path to zlib.h header file.
    
    Returns:
        dict: Contains 'functions' (dict of function names to descriptions)
              and 'error_codes' (list of error code names).
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: {file_path} not found. Using fallback descriptions.")
        # Fallback to minimal function descriptions
        return {
            'functions': {
                'gzopen': 'opens a gzip file for reading or writing',
                'gzfread': 'reads data from a gzip file',
                'gzfwrite': 'writes data to a gzip file',
                'gzclose': 'closes a gzip file',
                'gzread': 'reads uncompressed data from a gzip file',
                'gzwrite': 'writes uncompressed data to a gzip file',
                'compress': 'compresses data into a buffer',
                'uncompress': 'decompresses data from a buffer'
            },
            'error_codes': ['OK', 'STREAM_ERROR', 'MEM_ERROR', 'BUF_ERROR', 'DATA_ERROR', 'ERRNO', 'STREAM_END', 'VERSION_ERROR']
        }

    content = content.replace('\r\n', '\n').replace('\r', '\n')
    func_pattern = r'/\*\s*(.*?)\s*\*/\s*(?:Z_EXTERN\s+[\w\s*]+Z_EXPORT\s+(\w+)\s*\([^)]*\)\s*;)'
    func_matches = re.finditer(func_pattern, content, re.DOTALL)
    functions = {}
    for match in func_matches:
        comment = match.group(1).strip()
        comment = ' '.join(comment.split()).replace(' * ', ' ')
        func_name = match.group(2)
        if func_name:
            functions[func_name] = comment

    error_pattern = r'#define\s+Z_(\w+)\s+\(-?\d+\)'
    error_matches = re.findall(error_pattern, content)
    error_codes = sorted(error_matches)

    return {
        'functions': functions,
        'error_codes': error_codes
    }

def get_zlib_functions(zlib_h_path):
    zlib_info = parse_zlib_h(zlib_h_path)
    return zlib_info['functions']

def suggest_function_variants(zlib_func_name, func_map, max_results=5):
    base_summary = func_map.get(zlib_func_name, "")
    if not base_summary:
        return []

    base_words = set(base_summary.split())
    candidates = []

    for name, summary in func_map.items():
        if name == zlib_func_name:
            continue
        overlap = len(base_words & set(summary.split()))
        if overlap > 0:
            candidates.append((name, overlap, summary))

    candidates.sort(key=lambda x: -x[1])
    return [name for name, _, _ in candidates[:max_results]]

def extract_zlib_operations(file_path, zlib_h_path):
    print("\n1. Extracting zlib Operations (String-based):")
    with open(file_path, 'r') as f:
        code = f.read()

    zlib_calls = set()
    zlib_func_pattern = r'\b(gzopen|gzfread|gzfwrite|gzclose|gzread|gzwrite|compress|uncompress)\s*\('
    matches = re.finditer(zlib_func_pattern, code)
    for match in matches:
        zlib_calls.add(match.group(1))

    func_map = get_zlib_functions(zlib_h_path)
    if zlib_calls:
        for op in sorted(zlib_calls):
            print(f"- zlib Operation: {op}")
            if op in func_map:
                print(f"  Description: {func_map[op]}")
                variants = suggest_function_variants(op, func_map)
                if variants:
                    print("  Function Variants:")
                    for v in variants:
                        print(f"    - {v}")
    else:
        print("- No zlib operations found.")
    return list(zlib_calls)

def extract_zlib_parameters(file_path):
    print("\n2. Extracting Mutatable Parameters (String-based):")
    with open(file_path, 'r') as f:
        code = f.read()

    features = []
    target_params = {"buffer", "size", "mode"}
    call_pattern = r'(gzopen|gzfread|gzfwrite|gzclose|gzread|gzwrite|compress|uncompress)\s*\((.*?)\)'
    matches = re.finditer(call_pattern, code, re.DOTALL)

    for match in matches:
        func_name = match.group(1)
        args = [arg.strip() for arg in match.group(2).split(',')]
        feature = {'function': func_name}
        for i, arg in enumerate(args):
            if 'buffer' in arg.lower() or '[' in arg:
                feature['buffer'] = arg
            elif arg.isdigit() or 'sizeof' in arg or '[' in arg or '*' in arg:
                feature['size'] = arg
            elif '"' in arg and ('r' in arg or 'w' in arg or 'a' in arg):
                feature['mode'] = arg
            elif func_name in ('gzfread', 'gzread', 'gzfwrite', 'gzwrite', 'compress', 'uncompress'):
                # Assign size based on parameter position for specific functions
                if i == 1 and func_name in ('gzfread', 'gzread', 'gzfwrite', 'gzwrite'):
                    feature['size'] = arg
                elif i == 1 and func_name in ('compress', 'uncompress'):
                    feature['destLen'] = arg
        if len(feature) > 1:
            features.append(feature)

    if features:
        for f in features:
            print(f"- Function: {f['function']}")
            for key, value in f.items():
                if key != 'function':
                    print(f"  - {key}: {value}")
    else:
        print("- No relevant mutable parameters found.")
    return features

def guess_exceptions_for_call(func_name, error_codes):
    # Map zlib functions to likely error conditions based on error codes
    error_mappings = {
        'gzopen': ['ERRNO', 'MEM_ERROR', 'STREAM_ERROR'],
        'gzfread': ['BUF_ERROR', 'DATA_ERROR', 'STREAM_ERROR'],
        'gzfwrite': ['BUF_ERROR', 'DATA_ERROR', 'STREAM_ERROR'],
        'gzclose': ['ERRNO', 'STREAM_ERROR'],
        'gzread': ['BUF_ERROR', 'DATA_ERROR', 'STREAM_ERROR'],
        'gzwrite': ['BUF_ERROR', 'DATA_ERROR', 'STREAM_ERROR'],
        'compress': ['BUF_ERROR', 'MEM_ERROR'],
        'uncompress': ['BUF_ERROR', 'DATA_ERROR']
    }
    possible = [f"Z_{code}" for code in error_mappings.get(func_name, ['ERRNO'])]
    # Include generic crash conditions for misuse
    possible.extend(['Buffer overflow', 'Segmentation fault'])
    return sorted(set(possible))



def extract_poc_features(poc_code):
    
    file_path = "temp_poc.c"
    with open(file_path, 'w') as f:
        f.write(poc_code)

    zlib_h_path = "zlib.h"  # Replace with actual path to zlib.h
    print(f"Analyzing zlib PoC: {file_path}")
    zlib_ops = extract_zlib_operations(file_path, zlib_h_path)
    parameters = extract_zlib_parameters(file_path)
   

    func_map = get_zlib_functions(zlib_h_path)
    variant_suggestions = {}
    for op in zlib_ops:
        variants = suggest_function_variants(op, func_map)
        variant_suggestions[op] = variants

    mutatable_buffers = set()
    mutatable_sizes = set()
    mutatable_modes = set()
    for feat in parameters:
        for key, val in feat.items():
            if key == 'buffer':
                mutatable_buffers.add(val)
            elif key == 'size':
                mutatable_sizes.add(val)
            elif key == 'mode':
                mutatable_modes.add(val)

    prompt_template = f'''
You're a security researcher specializing in low-level vulnerability exploitation.

Given this successful zlib PoC that triggered a crash:
```c
{poc_code.strip()}
```
Generate unique C PoC variants taking care of mutating under these conditions but not limited to:
# Possible variants for the zlib operation variants of given PoC are {variant_suggestions}
# Mutatable buffers: {list(mutatable_buffers)}
# Mutable sizes: {list(mutatable_sizes)}
# Mutable modes: {list(mutatable_modes)}

The PoC variants must introduce modifications to trigger:
- Segmentation faults
- Heap or stack corruption
- Memory access violations
- Aborts (SIGABRT)
- Assertion failures
- Misuse of zlib functions

Avoid error handling (e.g., if checks or try-catch blocks).

Output the variants using this format:
```c
// Variant {{num1}} - [brief description]
<variant code>

// Variant {{num2}} - [brief description]
<variant code>

// Variant {{num3}} - [brief description]
<variant code>
```
Only include runnable C code in each block. Ensure each variant is standalone, crash-oriented, and enclosed in ```c and ``` code blocks.
'''

    print("\n=================== Prompt Template ===================")
    print(prompt_template)
    return {
        "prompt_template":prompt_template
    }   



if __name__ == "__main__":
    poc_code = '''
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

int main(void) {
    gzFile gzfp;
    char buffer[16];

    gzfp = gzopen("fuzzed.gz", "rb");
    if (!gzfp) {
        printf("[!] Can't open fuzzed file\\n");
        return 1;
    }

    printf("[*] Reading fuzzed gzip file...\\n");
    // Intentionally large read, forcing internal overflow scenario
    int n = gzfread(buffer, 1024, 1024, gzfp); // (1MB read into 16 bytes buffer)
    printf("[+] Bytes read: %d\\n", n);

    gzclose(gzfp);
    return 0;
}
'''
    extract_poc_features(poc_code)
