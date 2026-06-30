import requests
import os

# IMP: Must need to run the ollama server in the background. 
# We are using llama3:70b, deepseek-r1:70b and qwen2.5-coder:7b

def chat_with_ollama(prompt, model="llama3:70b"):

    url = "http://localhost:12543/api/generate"  #llama3:70b
    #url = os.getenv("OLLAMA_URL", "http://localhost:12543/api/generate")
    #set ollama port by running this - export OLLAMA_HOST=127.0.0.1:12543 ollama serve]
    #To run in different port we need to say that while running, otherwise it will try to connect default port (11434)
    #export OLLAMA_HOST=127.0.0.1:12543
    #ollama run qwen2.5-coder:7b
    headers = {"Content-Type": "application/json"}
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False  # We can use different port for different models. Then it will not clash with others.
    }

    response = requests.post(url, headers=headers, json=data)
    if response.ok:
        output = response.json()
        return output.get("response", "")
    else:
        print("Error:", response.status_code, response.text)
        return None
