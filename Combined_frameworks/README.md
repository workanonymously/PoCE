## Research Project | Proof-of-concept Exploit Generation with LLMs
This repository contains tools for generating proof-of-concept exploits for different software frameworks using LLMs, as well as their associated testing data in JSON format.

## Prepare and Run the following Steps:

1. First install ollama by following the Ollama_installation_instructions.pdf.

2. Set the llm version in interact_with_ollama.py file
   default llm is llama3:70b

3. In one terminal run the following commands to start ollama server -
   export OLLAMA_HOST=127.0.0.1:12345
   ollama serve

4. Then in another terminal download your prefered llm in the same ollama port
   export OLLAMA_HOST=127.0.0.1:12345
   ollama run llama3:70b 

5. Then install or create separate conda environment for each framework by running the requirements file from each framework folders.
  
6. Then stop running the llm in the terminal and run the following command to run PoCE tool
   python3 main.py --framework 'framework_name'   # For example: fig2dev (write the framework_name in lowercase.)
   python3 main.py --variant 'framework_variant'  # For example: fig2dev_variant

7. Before running step 5, change the documents path based on the framework in rag_tool_ollama.py. You can find the documents' path in each framework folder.
   Also, if want to use any new dataset, please create a dataset like our dataset and provide that path in framework_tool.py file.
   
   
