# BlackShield — Cybersecurity Platform

## Quick Start

```bash
# One command to start everything:
npm run dev
```

This starts:
- **Vite** (frontend) → http://localhost:8080
- **Auth Server** (SQLite login/signup) → http://localhost:8766
- **SSL Analyzer** → http://localhost:8765
- **Subdomain Finder** → subdomain_server.py
- **Directory Scanner** → gobuster_server.py
- **SQLi Scanner** → sqlmap_server.py
- **Sniper Tool** → sniper_server.py
- **AI Chatbot** (Groq/LLaMA) → http://localhost:8000

## First-time Setup

```bash
# Install Node dependencies
npm install

# Install Python dependencies
pip install cryptography fastapi uvicorn groq pydantic

# Then run:
npm run dev
```

## Database
SQLite database is auto-created at `backend/blackshield.db` on first run.
No setup needed — just start and register an account.

## Tech Stack
- Frontend: React + TypeScript + Vite + Tailwind + shadcn/ui
- Auth: Local SQLite (no cloud dependency)
- Backend: Python (stdlib + FastAPI for chatbot)
- AI: Groq API (LLaMA 3)
