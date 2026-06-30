import re
from pycparser import c_parser
from RAG_module import LiblouisRAG  # RAG module integration

import re
from pycparser import c_parser

def strip_preprocessor_directives(code):
    """
    Remove only the first opening ```c (or ```) and the last ``` fence at the end,
    keeping everything else, including #include lines, typedefs, comments, etc.
    """
    if not isinstance(code, str):
        return ""

    # Remove first opening fence, only the ```c or ``` at the very start
    # Use more precise pattern to avoid matching #include lines
    code = re.sub(r'^\s*```(?:c|C)?\s*\n', '', code, count=1, flags=re.MULTILINE)

    # Remove last closing fence, only if it is at the very end
    code = re.sub(r'\n\s*```\s*$', '', code, count=1, flags=re.MULTILINE)

    return code


def extract_mutatable_fields_from_ast(c_code):
    """
    Extract fuzzing-relevant fields from C code using AST with original code context
    """
    parser = c_parser.CParser()
    clean_code = strip_preprocessor_directives(c_code)

    # Initialize mutatables here so it's always defined
    mutatables = {
        "struct_fields": [],
        "string_constants": [],
        "table_buffer_fields": [],
        "lou_call_buffers": [],
        "pointer_operations": []
    }

    try:
        ast = parser.parse(clean_code, filename='<none>')
    except Exception as e:
        print(f"AST parsing failed: {e}")
        # Return empty mutatables or use regex fallback if you want
        return mutatables  # or return extract_mutatables_by_regex(c_code) if you uncomment the import

    # Store original code lines for precise extraction
    code_lines = c_code.split('\n')

    def get_code_from_coord(coord):
        """Extract actual code using coordinate information"""
        if coord is None:
            return ""
        try:
            line_num = coord.line - 1  # Convert to 0-based index
            if 0 <= line_num < len(code_lines):
                return code_lines[line_num].strip()
        except:
            pass
        return ""

    def get_node_actual_code(node):
        """Get the actual source code for a node"""
        if hasattr(node, 'coord') and node.coord:
            return get_code_from_coord(node.coord)
        
        # Fallback: try to reconstruct from node properties
        if hasattr(node, 'name'):
            return str(node.name)
        if hasattr(node, 'value'):
            return str(node.value)
        return str(node)

    class Visitor:
        def __init__(self):
            self.current_function = None
            
        def visit(self, node):
            if node is None:
                return
            method = 'visit_' + node.__class__.__name__
            visitor = getattr(self, method, self.generic_visit)
            visitor(node)
            
        def generic_visit(self, node):
            for _, child in node.children():
                self.visit(child)
                
        def visit_FuncDef(self, node):
            # Track which function we're in
            if hasattr(node.decl, 'name'):
                self.current_function = get_node_actual_code(node.decl)
            self.generic_visit(node)
            self.current_function = None
            
        def visit_Decl(self, node):
            """Capture variable declarations with actual code"""
            if hasattr(node, 'type') and hasattr(node, 'name'):
                decl_code = get_node_actual_code(node)
                
                # Capture string constants from declarations
                if 'char' in decl_code and '=' in decl_code:
                    var_name = get_node_actual_code(node.name)
                    if '"' in decl_code:
                        # Extract the actual string value from source
                        match = re.search(r'=\s*"([^"]*)"', decl_code)
                        if match:
                            mutatables['string_constants'].append(
                                (var_name, match.group(1), self.current_function, decl_code)
                            )
                
                # Capture array declarations
                if '[' in decl_code and ']' in decl_code:
                    if any(buf_type in decl_code for buf_type in 
                          ['char', 'uint8_t', 'byte', 'BUFFER']):
                        mutatables['table_buffer_fields'].append(
                            (get_node_actual_code(node.name), "array_decl", decl_code, self.current_function)
                        )
            
            self.generic_visit(node)
            
        def visit_Assignment(self, node):
            """Capture assignments with actual source code"""
            assignment_code = get_node_actual_code(node)
            lname = getattr(node.lvalue, '__class__', None).__name__ if node.lvalue else None
            
            if lname == 'StructRef':
                field = getattr(getattr(node.lvalue, 'field', None), 'name', 
                               get_node_actual_code(node.lvalue.field))
                value_code = get_node_actual_code(node.rvalue)
                mutatables['struct_fields'].append(
                    (field, value_code, self.current_function, assignment_code)
                )
                
            elif lname == 'ArrayRef':
                target = get_node_actual_code(getattr(node.lvalue, 'name', None))
                index = get_node_actual_code(getattr(node.lvalue, 'subscript', None))
                value_code = get_node_actual_code(node.rvalue)
                
                # Broaden buffer detection for liblouis
                buffer_indicators = ["table", "buf", "data", "input", "str", "name", "ptr", "mem", 
                                   "inbuf", "outbuf", "forward", "backward", "braille"]
                if target and any(k in target.lower() for k in buffer_indicators):
                    mutatables['table_buffer_fields'].append(
                        (target, index or "unknown", value_code, self.current_function, assignment_code)
                    )

        def visit_FuncCall(self, node):
            """Capture function calls with actual arguments"""
            call_code = get_node_actual_code(node)
            fname = getattr(getattr(node, 'name', None), 'name', 
                           get_node_actual_code(node.name) if node.name else "")
            
            # More specific liblouis function detection
            liblouis_funcs = ['lou_translate', 'lou_backTranslate', 'lou_setDataPath', 
                            'lou_getTable', 'lou_free', 'lou_compileString', 'lou_hyphenate']
            
            is_liblouis_call = (fname and (fname.startswith("lou_") or 
                             any(func in fname for func in liblouis_funcs) or
                             "louis" in fname.lower()))
            
            if is_liblouis_call:
                args = []
                if getattr(node, 'args', None) and getattr(node.args, 'exprs', None):
                    args = [get_node_actual_code(a) for a in node.args.exprs]
                    
                for i, a in enumerate(args):
                    # Focus on arguments that are likely to be buffers/strings
                    arg_indicators = ["data", "buf", "table", "str", "name", "input", 
                                    "file", "path", "inbuf", "outbuf", "forward", "backward"]
                    if any(indicator in a.lower() for indicator in arg_indicators):
                        mutatables['lou_call_buffers'].append(
                            (fname, i, a, self.current_function, call_code)
                        )

        def visit_BinaryOp(self, node):
            """Capture pointer arithmetic operations"""
            op_code = get_node_actual_code(node)
            if node.op in ['+', '-']:
                left = get_node_actual_code(node.left)
                right = get_node_actual_code(node.right)
                
                ptr_indicators = ["ptr", "buf", "data", "table", "inbuf", "outbuf", 
                                "forward", "backward", "alloc", "malloc"]
                if any(indicator in left.lower() for indicator in ptr_indicators):
                    mutatables['pointer_operations'].append(
                        (left, node.op, right, self.current_function, op_code)
                    )
            self.generic_visit(node)

        def visit_ArrayRef(self, node):
            """Capture array accesses that might be overflow targets"""
            array_code = get_node_actual_code(node)
            array_name = get_node_actual_code(getattr(node, 'name', None))
            subscript = get_node_actual_code(getattr(node, 'subscript', None))
            
            # Track array accesses in buffer-like variables
            buffer_vars = ["buf", "data", "input", "table", "inbuf", "outbuf"]
            if any(buf in array_name.lower() for buf in buffer_vars):
                mutatables['pointer_operations'].append(
                    (array_name, f"[{subscript}]", "array_access", self.current_function, array_code)
                )
            
            self.generic_visit(node)

    Visitor().visit(ast)
    
    return mutatables



def build_liblouis_prompt(c_code, mutatables, rag_context=None):
    """
    Build a strict prompt that asks the model to emit 3+ fuzzer-style C variants (NO main),
    in exact format the runner expects.
    """
    context_text = rag_context or ""
    # small helpful summary of discovered mutation points to include in prompt
    summary_lines = []
    if mutatables.get('struct_fields'):
        summary_lines.append("Struct fields detected: " + ", ".join([f[0] for f in mutatables['struct_fields'][:10]]))
    if mutatables.get('string_constants'):
        summary_lines.append("String/byte constants: " + ", ".join([s[0] for s in mutatables['string_constants'][:10]]))
    if mutatables.get('table_buffer_fields'):
        summary_lines.append("Buffers from fuzz input: " + ", ".join([t[0] for t in mutatables['table_buffer_fields'][:10]]))
    if mutatables.get('lou_call_buffers'):
        summary_lines.append("liblouis call buffers: " + ", ".join([f"{x[0]}@arg{x[1]}({x[2]})" for x in mutatables['lou_call_buffers'][:10]]))

    mut_summary = "\n".join(summary_lines)

    prompt = f'''
You're a vulnerability researcher focusing on liblouis fuzzing and crash discovery.
{context_text}

Mutation summary:
{mut_summary}

Given the following PoC (FUZZER-style driver, NO main function) in C:

```c
{c_code.strip()}


```

Generate C-based PoC variants that mutate:
- segmentation faults
- unaligned memory access
- buffer overflows
- abort
- core dumped




Output at least 3 FUZZER (NO main function) C code variants in this format:
```c
// Variant 1 - [short explanation]
<variant code>

// Variant 2 - [short explanation]
<variant code>

// Variant 3 - [short explanation]
<variant code>
```

Do not add explanations outside the code blocks. Keep code minimal and crash-focused.
Each variant must be suitable for plugging into an LLVMFuzzerTestOneInput-like harness (i.e., implement LLVMFuzzerTestOneInput or be a helper that the harness can call). Keep code minimal and crash-focused. Use discovered mutation points (buffers, lou_* arguments, string constants) where applicable.
'''
    print("\n=================== Liblouis Prompt Template ===================")
    print("Mutatables detected:", {k: len(v) for k, v in mutatables.items()})
    return prompt





def extract_liblouis_features_from_code(c_code):
    mutatables = extract_mutatable_fields_from_ast(c_code)
    # build a field list for RAG queries (take first element of each tuple)
    fields = []
    fields += [f[0] for f in mutatables.get('struct_fields', [])]
    fields += [s[0] for s in mutatables.get('string_constants', [])]
    fields += [t[0] for t in mutatables.get('table_buffer_fields', [])]
    # include names found in lou_call_buffers
    fields += [x[2] for x in mutatables.get('lou_call_buffers', [])]

    # Build RAG context and attach to prompt
    rag = LiblouisRAG(doc_folder="documents2")
    rag.load_documents()
    rag.build_index()
    rag_context = rag.get_rag_context_for_fields(fields, prefix="liblouis", top_k=3)

    prompt = build_liblouis_prompt(c_code, mutatables, rag_context)
    return {
        "mutatables": mutatables,
        "prompt_template": prompt
    }


if __name__ == '__main__':
    c_code =  """#include "liblouis.h"
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
    /* louis_functions: lou_logFile */
    lou_logFile(fileName);  /* string_arguments: fileName */
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
    /* buffer_sizes: pt_size - dynamically calculated buffer size */
    size_t pt_size = (Size - minimum_size) / 1;
    if (pt_size < sizeof(char) ) { return -1; }
    
    /* string_arguments: fileName - main string argument for louis function */
    char * fileName;
    /* buffer_sizes: pt_size+1 - allocated buffer size */
    fileName = (char *)malloc(pt_size+1);
    AFG_alloc_list[AFG_alloc_cnt++] = (void*) fileName;
    
    /* string_arguments: fileName - populated with fuzzer data */
    memcpy((void *)fileName, AFG_Data+AFG_offset, pt_size);
    fileName[pt_size] = '\0';
    AFG_offset+=pt_size;

    /* louis_functions: AFG_func -> lou_logFile */
    AFG_func(fileName);  /* string_arguments: fileName passed to louis function */

AFG_fail:
    for(int AFG_free_i = 0; AFG_free_i < AFG_alloc_cnt; AFG_free_i++)
        free(AFG_alloc_list[AFG_free_i]);
    for(int AFG_free_i = 0; AFG_free_i < AFG_fopen_cnt; AFG_free_i++)
        fclose(AFG_fopen_list[AFG_free_i]);
    AFG_alloc_cnt = 0;
    AFG_fopen_cnt = 0;

    return 0;
}"""
    result = extract_liblouis_features_from_code(c_code)
