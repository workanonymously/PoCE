#!/usr/bin/env python3
import os
import subprocess
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:12543')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3:70b')
OLLAMA_TIMEOUT = int(os.getenv('OLLAMA_TIMEOUT', '300'))


def chat_with_ollama(prompt, model=None):
    mdl = model or OLLAMA_MODEL
    base = OLLAMA_BASE_URL
    if HAS_REQUESTS:
        try:
            r = requests.post(f'{base}/api/generate',
                              headers={"Content-Type": "application/json"},
                              json={"model": mdl, "prompt": prompt, "stream": False},
                              timeout=OLLAMA_TIMEOUT)
            if r.ok:
                return r.json().get("response", "")
            print("Error:", r.status_code, r.text)
            return None
        except Exception as e:
            print("Error:", e)
            return None
    try:
        r = subprocess.run(['ollama', 'run', mdl, prompt], capture_output=True, text=True, timeout=OLLAMA_TIMEOUT)
        return (r.stdout or '').strip() or None
    except Exception:
        return None


def check_ollama(url=None):
    base = url or OLLAMA_BASE_URL
    if not HAS_REQUESTS:
        return False
    try:
        r = requests.get(f'{base}/api/tags', timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def call_ollama(prompt, temperature=0.2, url=None, model=None, timeout=None):
    base = url or OLLAMA_BASE_URL
    mdl = model or OLLAMA_MODEL
    tout = timeout or OLLAMA_TIMEOUT
    if HAS_REQUESTS:
        try:
            r = requests.post(f'{base}/api/generate',
                              json={'model': mdl, 'prompt': prompt, 'stream': False,
                                    'options': {'temperature': temperature, 'top_p': 0.1, 'num_predict': 3000}},
                              timeout=tout)
            r.raise_for_status()
            text = r.json().get('response', '').strip()
            return text if text else None
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None
    try:
        r = subprocess.run(['ollama', 'run', mdl, prompt], capture_output=True, text=True, timeout=tout)
        text = (r.stdout or '').strip()
        return text if text else None
    except Exception:
        return None
