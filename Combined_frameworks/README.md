## Research Project | Proof-of-concept Exploit Generation with LLMs
This repository contains tools for generating proof-of-concept exploits for different software frameworks using LLMs, as well as their associated testing data in JSON format.

## Prepare and Run the following Steps:

1. First install ollama by following the Ollama_installation_instructions.pdf.

2. Set the llm version in interact_with_ollama.py file:
   
   default llm is llama3:70b

4. In one terminal run the following commands to start ollama server:

   #The following port is a default port. If this port becomes busy then you can change it to other port and have to install the llm model on that port again by running step 4. And also update the port in interact_with_ollama.py file to run PoCE tool properly.
   
   export OLLAMA_HOST=127.0.0.1:12543 
   
   ollama serve

6. Then in another terminal download your prefered llm in the same ollama port:
   
   export OLLAMA_HOST=127.0.0.1:12543
   
   ollama run llama3:70b 

8. Then install the requirements file from each framework folders.
  
9. Then stop running the llm in the terminal and run the following command to run PoCE tool:
    
   python3 main.py --framework 'framework_name'   # For example: fig2dev (write the framework_name in lowercase.)
   
   python3 main.py --variant 'framework_variant'  # For example: fig2dev_variant

11. Before running step 5, change the documents path based on the framework in rag_tool_ollama.py. You can find the documents' path in each framework folder.
   Also, if want to use any new dataset, please create a dataset like our dataset and provide that path in framework_tool.py file.
   
   
