# Hexora

This is a tool that inspects files of any kind `without executing` them and performs `static analysis` to identify potentially suspicious characteristics.

The concepts behind it are `hashing`, `entropy checks`, `metadata extraction`, `signature matching` and `heuristic scoring`, these ideas have been around for years.

I just wanted to build my own version from scratch, understand each concept while building it, `and end up with something of my own that I'd actually use myself`, so I built [Hexora](https://hexora.shaivarth.com).

It doesn't run binaries. It doesn't emulate malware. It just reads bytes, fingerprints the file, extracts whatever metadata it can, looks for suspicious patterns, and tries to answer one question:

 `"Does this deserve a closer look?"`

#### What it does

* Computes `SHA-256`, `SHA-1` and `MD5` hashes
* Detects file types using `signatures` instead of `extensions`
* Extracts `metadata` from common formats
* Calculates `entropy` and runs a simple `heuristic` risk engine
* Looks for suspicious `strings`, `URLs` and `IP addresses`
* Generates a detailed report

Everything is static analysis. Nothing gets executed.

#### note-

Uploaded files are isolated by browser session.

#### Running it

You can just use the hosted version: **[Hexora](https://hexora.shaivarth.com)**

If you'd rather run it yourself:

```bash
git clone https://github.com/Shaivarth/Hexora.git
cd Hexora
docker compose up --build
```

Or without Docker:

```bash
cd backend
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `http://localhost:8000`.

#### Tech

`FastAPI`, `SQLAlchemy`, `SQLite`, `HTML/CSS/JS`, `Docker`

#### Hexora is not a malware detector

Hexora is a triage tool.

> A high score doesn't prove something is malicious. A low score doesn't prove it's safe.

The idea is to give a clearer starting point to decide where to focus or how to move ahead.

#### License

MIT.
