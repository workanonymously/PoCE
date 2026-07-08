import math
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

import json
from interact_with_ollama import chat_with_ollama


def extract_text_from_pdf(pdf_path):
    try:
        import fitz
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    except ImportError:
        return ""


def chunk_text(text, chunk_size=500):
    words = text.split()
    return [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]


def process_pdf_folder(folder_path, faiss_index_path="all_pdf_index.faiss"):
    try:
        from sentence_transformers import SentenceTransformer
        import faiss
        import numpy as np
    except ImportError:
        return None, None, {}, {}

    model = SentenceTransformer("intfloat/e5-base-v2")
    id_to_text = {}
    file_chunk_map = {}
    index_counter = 0
    index = None

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
            for i, chunk in enumerate(chunks):
                global_id = index_counter
                id_to_text[global_id] = chunk
                file_chunk_map[global_id] = {"file": filename, "chunk_index": i}
                index_counter += 1

    if index is not None:
        faiss.write_index(index, faiss_index_path)
        print(f"Saved {index_counter} chunks to {faiss_index_path}")
    return model, index, id_to_text, file_chunk_map


def chunk_embeddings(model, index, id_to_text, query):
    import numpy as np
    prompt = ' """ ' + query + ' """ '
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
    folder_path = "fig2dev/fig2dev_documents"
    model, index, id_to_text, file_chunk_map = process_pdf_folder(folder_path)
    prompt = chunk_embeddings(model, index, id_to_text, query)
    response = chat_with_ollama(prompt)
    return response


def _words(text):
    return re.findall('[a-zA-Z0-9_\\-\\.]+', text.lower())


def _chunk(text, size=500):
    words = text.split()
    return [' '.join(words[i:i + size]) for i in range(0, len(words), size)] or [text]


def build_index(docs, chunk_size=500, docs_path=None):
    raw = dict(docs)
    if docs_path and Path(docs_path).is_dir():
        for fp in sorted(Path(docs_path).iterdir()):
            if fp.suffix == '.txt':
                try:
                    raw[fp.stem] = fp.read_text(errors='replace')
                except Exception:
                    pass
    try:
        from sentence_transformers import SentenceTransformer
        import faiss
        import numpy as np
        chunks, chunk_ids = [], []
        for doc_id, text in raw.items():
            for ch in _chunk(text, chunk_size):
                chunks.append(ch)
                chunk_ids.append(doc_id)
        model = SentenceTransformer('intfloat/e5-base-v2')
        vecs = model.encode(['passage: ' + c for c in chunks], show_progress_bar=False, convert_to_numpy=True).astype('float32')
        faiss.normalize_L2(vecs)
        index = faiss.IndexFlatIP(vecs.shape[1])
        index.add(vecs)
        return {'backend': 'faiss', 'model': model, 'index': index, 'chunks': chunks, 'chunk_ids': chunk_ids}
    except ImportError:
        pass
    chunks, chunk_ids = [], []
    for doc_id, text in raw.items():
        for ch in _chunk(text, chunk_size):
            chunks.append(ch)
            chunk_ids.append(doc_id)
    vocab: dict = {}
    for ch in chunks:
        for tok in _words(ch):
            if tok not in vocab:
                vocab[tok] = len(vocab)
    V, N = len(vocab), len(chunks)
    df: dict = defaultdict(int)
    tfs = []
    for ch in chunks:
        vec = [0.0] * V
        toks = _words(ch)
        total = max(len(toks), 1)
        for tok in toks:
            if tok in vocab:
                vec[vocab[tok]] += 1.0 / total
        tfs.append(vec)
        for i, v in enumerate(vec):
            if v > 0:
                df[i] += 1
    idf = [math.log((N + 1) / (df[i] + 1)) + 1.0 for i in range(V)]
    tfidf = [[v * idf[i] for i, v in enumerate(row)] for row in tfs]
    return {'backend': 'tfidf', 'tfidf': tfidf, 'vocab': vocab, 'idf': idf, 'chunks': chunks, 'chunk_ids': chunk_ids}


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb + 1e-09)


def retrieve(query, index, top_k=3, exclude_id=None):
    chunks, chunk_ids = index['chunks'], index['chunk_ids']
    if index['backend'] == 'faiss':
        import faiss
        import numpy as np
        model = index['model']
        idx = index['index']
        qvec = model.encode(['query: ' + query], convert_to_numpy=True).astype('float32')
        faiss.normalize_L2(qvec)
        k = min(top_k * 5, len(chunks))
        scores, idxs = idx.search(qvec, k)
        seen: dict = {}
        for score, i in zip(scores[0], idxs[0]):
            doc_id = chunk_ids[i]
            if doc_id == exclude_id:
                continue
            if doc_id not in seen or score > seen[doc_id][1]:
                seen[doc_id] = (chunks[i], float(score))
        results = sorted(seen.items(), key=lambda x: x[1][1], reverse=True)
        return [(doc_id, text, sc) for doc_id, (text, sc) in results[:top_k]]
    vocab, idf = index['vocab'], index['idf']
    toks = _words(query)
    total = max(len(toks), 1)
    qvec = [0.0] * len(vocab)
    for tok in toks:
        if tok in vocab:
            qvec[vocab[tok]] += 1.0 / total
    qvec = [v * idf[i] for i, v in enumerate(qvec)]
    raw = [(chunk_ids[i], chunks[i], _cosine(qvec, index['tfidf'][i])) for i in range(len(chunks))]
    raw.sort(key=lambda x: x[2], reverse=True)
    seen_ids: dict = {}
    for doc_id, text, sc in raw:
        if doc_id == exclude_id:
            continue
        if doc_id not in seen_ids:
            seen_ids[doc_id] = (text, sc)
        if len(seen_ids) >= top_k:
            break
    return [(doc_id, text, sc) for doc_id, (text, sc) in seen_ids.items()]


if __name__ == "__main__":
    query = "Generate a PoC for CVE-2018-14465"
    rag_tool(query)
