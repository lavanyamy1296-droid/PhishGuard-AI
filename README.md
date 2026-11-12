# PhishGuard AI — Phishing Website Detector

A beginner-friendly cybersecurity + machine-learning project. Enter a URL and the app extracts URL-based features, runs a Random Forest classifier, and displays a risk score with understandable warning indicators.

## Features
- URL parsing and feature extraction
- Random Forest classification
- Transparent warning indicators (HTTPS absence, IP-based host, URL shortener, suspicious words, etc.)
- Streamlit dashboard
- No API key, database, hardware, or network access to submitted websites

## Important limitations
**This is an educational prototype, not a production phishing detector.** Its bundled model is trained on reproducible synthetic demonstration examples. The displayed holdout accuracy measures performance on that synthetic dataset only and must not be interpreted as real-world detection accuracy. For a serious project, replace the synthetic generator with a properly licensed, dated, representative dataset of benign and phishing URLs, document the source, prevent train/test leakage, and evaluate precision, recall, F1, ROC-AUC, and false-positive rates.

The app analyzes the URL text only. It does not visit the site, inspect page content, resolve redirects, or check live reputation. A low score does not prove a URL is safe. HTTPS alone does not mean a site is trustworthy.

## Run on Windows (PowerShell)

1. Install Python 3.11 or 3.12 (recommended).
2. Open this folder in VS Code.
3. In the terminal, create a virtual environment:

```powershell
py -3.12 -m venv .venv
```

If that version is unavailable, check installed versions with `py --list` and use the matching launcher, e.g. `py -3.11 -m venv .venv`.

4. Activate it:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If activation is blocked, skip activation and use `.venv\Scripts\python.exe` in the commands below.

5. Install packages:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

6. Start the app:

```powershell
python -m streamlit run app.py
```

Open the local address shown in the terminal (usually http://localhost:8501).

## Example URLs to try
- `https://www.wikipedia.org`
- `http://secure-account-verify.example-login.test/signin?account=12345678`
- `http://192.0.2.10/verify-account`

These are illustrative test strings. Do not visit suspicious URLs.

## Project structure

```text
PhishGuard-AI/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── data/
│   └── README.txt
└── phishguard/
    ├── __init__.py
    └── detector.py
```

## GitHub upload

Create an empty GitHub repository named `PhishGuard-AI`, then run these commands from this project folder:

```powershell
git init
git add .
git commit -m "Initial commit - PhishGuard AI"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/PhishGuard-AI.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Do not upload your `.venv` folder.
