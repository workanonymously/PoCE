import os
import fitz  # PyMuPDF
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
# from openai import OpenAI
import json
from interact_with_ollama import chat_with_ollama


def extract_text_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text


def chunk_text(text, chunk_size=500):
    words = text.split()
    return [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]

# Main pipeline to process all PDFs in a folder
def process_pdf_folder(folder_path, faiss_index_path="all_pdf_index.faiss"):
    model = SentenceTransformer("intfloat/e5-base-v2", device="cuda:5")
    # all_chunks = []
    id_to_text = {}
    file_chunk_map = {}
    index_counter = 0

    for filename in os.listdir(folder_path):
        if filename.endswith(".pdf"):
            pdf_path = os.path.join(folder_path, filename)
            print(f"Processing: {filename}")

            text = extract_text_from_pdf(pdf_path)
            chunks = chunk_text(text)
            embeddings = model.encode(chunks, convert_to_numpy=True)

            if index_counter == 0:
                embedding_dim = embeddings.shape[1]
                index = faiss.IndexFlatL2(embedding_dim)

            index.add(embeddings)

            # Track chunk metadata
            for i, chunk in enumerate(chunks):
                global_id = index_counter
                id_to_text[global_id] = chunk
                file_chunk_map[global_id] = {
                    "file": filename,
                    "chunk_index": i
                }
                index_counter += 1

    # Save all chunks into FAISS index
    faiss.write_index(index, faiss_index_path)


    print(f"Saved {index_counter} chunks to {faiss_index_path}")
    return model, index, id_to_text, file_chunk_map


def chunk_embeddings(model, index, id_to_text, query):
    
    prompt = json.dumps(query, indent=2)
    # print(f"Query: {query}")
    prompt = ' """ ' + query + ' """ '
    # print(f"Query: {prompt}, Type: {type(prompt)}")

    if not isinstance(query, str) or not query.strip():
        raise ValueError(f"Invalid query input to model.encode: {query}")
    

    query_embedding = model.encode([query])
    D, I = index.search(np.array(query_embedding), k=3)

    for idx in I[0]:
        if idx == -1:
            print("No relevant chunk found.")
            return prompt 
        print("Chunk:", id_to_text[idx])
 

    context = "\n".join([id_to_text[idx] for idx in I[0]])

    prompt = f"""
    You are a helpful coding assistant.
    Use the following context to write the relevant PoC. But don't limit yourself with the context, explore your knowledge too in generating the PoC. 

    Context:
    {context}

    Question: {query}

    """

    print("RAG prompt Example:", prompt)
    return prompt



def rag_tool(query):
    # documents path
    folder_path = "fig2dev/fig2dev_documents" #change this path based on frameworks
    model, index, id_to_text, file_chunk_map = process_pdf_folder(folder_path)
    # combined_content = "\n".join([f"{msg['role']}: {msg['content']}" for msg in query])
    prompt = chunk_embeddings(model, index, id_to_text, query)
    # response = llama_openai(prompt)
    response = chat_with_ollama(prompt)
    # print(f"Final Response: {response}")
    return response
    # return prompt

if __name__ == "__main__":
    
    query = "Generate a PoC for CVE-2018-14465" #This is an example. But not actual query. We are mainly calling rag_tool() from our main.py file.

    rag_tool(query) 
