# PostgreSQL Function Deployment Manager

A local Flask app for comparing and deploying PostgreSQL function and table changes between a T&D/test database and a Live database.

## Overview

This repository contains a PostgreSQL comparison and deployment tool for reviewing object differences, generating SQL scripts, and performing approved function or table deployments safely.

### Main app

The main project is located here:

```text
deployment_tool/Script/postgres_function_deployer/
```

### Full detailed setup guide

For the complete developer setup, environment configuration, database requirements, troubleshooting, and startup instructions, see:

```text
deployment_tool/Script/postgres_function_deployer/README.md
```

## Quick start

```powershell
cd "C:\DB Deployment Tool\Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Important notes

- Use the project virtual environment instead of the system Python; start with `.\.venv\Scripts\python.exe app.py` from the app folder.
- Keep `.env` local and do not commit it.
- Do not commit `.venv/` or generated SQL files.
- If `psycopg2` fails on Windows, install the Microsoft Visual C++ Redistributable and retry the venv install.

## Repository structure

```text
DB-Deployment-Tool/
├── README.md

├── deployment_tool/
│   └── Script/
│       └── postgres_function_deployer/
│           ├── README.md
│           ├── app.py
│           ├── config.py
│           ├── requirements.txt
│           ├── .env.example
│           ├── services/
│           ├── static/
│           ├── templates/
│           └── generated_scripts/
```

# ==========================================================
# DB Deployment Tool - Git Workflow
# ==========================================================

# 1. Go to project
cd "C:\DB Deployment Tool\Deployment-Tool"

# 2. Check status
git status

# 3. Switch to T&D
git checkout "t&d"

# 4. Get latest T&D
git pull origin "t&d"

# 5. Add changes
git add .

# 6. Verify changes
git status

# 7. Commit
git commit -m "perf: optimize database connection and registry access"

# 8. Push T&D
git push origin "t&d"

# ==========================================================
# TEST T&D
# ==========================================================
# Review and test the T&D deployment before merging to main.


# ==========================================================
# MERGE T&D -> MAIN
# ==========================================================

# 9. Switch to main
git checkout main

# 10. Get latest main
git pull origin main

# 11. Merge T&D
git merge "t&d"

# 12. Push main
git push origin main

# ==========================================================
# VERIFY
# ==========================================================

git status
git branch
git log --oneline -5

## Documentation policy

For long-form project setup, environment guidance, and troubleshooting, the detailed guide stays in the project folder README. The repository root README is kept short and focused so GitHub remains clean and easy to scan.
