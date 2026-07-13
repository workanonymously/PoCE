## Research Project | Proof-of-concept Exploit Generation with LLMs
This repository contains tools for generating proof-of-concept exploits for different software using LLMs, as well as their associated testing data in JSON format.

## Prepare and Run the following Steps:

1. First install ollama by following the Ollama_installation_instructions.pdf.

2. Set the LLM version in interact_with_ollama.py file:
   
   default LLM is llama3:70b

3. In one terminal run the following commands to start ollama server:

   #The following port is a default port. If this port becomes busy then you can change it to another port and have to install the LLM model on that port again by running step 4. And also update the port in interact_with_ollama.py file to run the PoCE tool properly.
   
   export OLLAMA_HOST=127.0.0.1:12543 
   
   ollama serve

4. Then in another terminal download your preferred LLM in the same ollama port:
   
   export OLLAMA_HOST=127.0.0.1:12543
   
   ollama run llama3:70b 

5. Then install the requirements file from each software folders.
  
6. Then stop running the LLM in the terminal and run the following command to run PoCE tool:
    
   python3 main.py --framework 'software_name'   # For example: fig2dev (write the software_name in lowercase.)
   
   python3 main.py --variant 'software_variant'  # For example: fig2dev_variant

7. Before running step 6, change the documents path based on the software in rag_tool_ollama.py. You can find the documents' path in each software folder.
   Also, if you want to use any new dataset, please create a dataset like our dataset and provide that path in the framework_tool.py file.

8. If it needs to run on subset, each folder has a separate test.json file and in the dataset/main.json has all the files.
