#!/usr/bin/env python3
"""Run this first: python backend/test_chat.py"""
import sys, socket, urllib.request, json

print(f"Python: {sys.version}")

# 1. Check port 8773 free
try:
    s = socket.socket()
    s.bind(("0.0.0.0", 8773))
    s.close()
    print("Port 8773: FREE ✓")
except OSError as e:
    print(f"Port 8773: IN USE — {e}")
    print("  Fix: change PORT in chatbot_server.py to 8774 or kill the process using 8773")

# 2. Check internet
try:
    urllib.request.urlopen("https://www.google.com", timeout=5)
    print("Internet: OK ✓")
except Exception as e:
    print(f"Internet: FAILED — {e}")

# 3. Check Gemini key
from chatbot_server import PROVIDER, GEMINI_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY, chat
print(f"Provider: {PROVIDER}")

if PROVIDER == "gemini":
    if GEMINI_API_KEY == "YOUR_GEMINI_KEY_HERE":
        print("Gemini key: NOT SET — open chatbot_server.py and paste your key")
        sys.exit(1)
    print(f"Gemini key: {GEMINI_API_KEY[:8]}...")
elif PROVIDER == "groq":
    if not GROQ_API_KEY:
        print("Groq key: NOT SET")
        sys.exit(1)
    print(f"Groq key: {GROQ_API_KEY[:8]}...")
elif PROVIDER == "openrouter":
    if OPENROUTER_API_KEY == "YOUR_OPENROUTER_KEY_HERE":
        print("OpenRouter key: NOT SET")
        sys.exit(1)
    print(f"OpenRouter key: {OPENROUTER_API_KEY[:8]}...")

# 4. Test actual API call
print("Testing API call...")
try:
    reply = chat([{"role": "user", "content": "Say OK"}])
    print(f"API call: OK ✓ — got reply: {reply[:60]}")
except Exception as e:
    print(f"API call: FAILED — {e}")