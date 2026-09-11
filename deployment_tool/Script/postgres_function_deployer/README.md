# PostgreSQL Function Deployment Manager

A Flask dashboard for comparing and deploying PostgreSQL functions and tables between a T&D/test database and a Live database. Existing comparison, SQL generation, deployment, backup, registry, history, and notification workflows are preserved.

The application uses Brevo SMTP and environment variables. Gmail OAuth, `credentials.json`, and `token.json` are not required.

## 1. Project Structure

```text
Deployment-Tool/
├── README.md
└── deployment_tool/Script/postgres_function_deployer/
    ├── app.py
    ├── config.py
    ├── requirements.txt
    ├── .env.example
    ├── test_notification.py
    ├── services/
    ├── templates/
    ├── static/
    └── generated_scripts/
```

`app.py` exposes the Flask object named `app`. `config.py` loads local `.env` values with `python-dotenv`, while Render supplies the same values through its Environment Variables settings.

## 2. Requirements

Install:

- Git
- PowerShell
- Python 3.11 (recommended; `.python-version` records this choice)
- PostgreSQL access to both T&D/test and Live databases
- A Brevo account for email notifications

Python 3.10 or newer is recommended. No Google or Brevo SDK is needed; SMTP uses Python's standard library.

## 3. Windows Setup

Run these commands from the application directory:

```powershell
cd "C:\DB Deployment Tool\Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If activation is blocked, run the `Set-ExecutionPolicy` command again in the same PowerShell session. The venv can also be used without activation:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Verify dependencies:

```powershell
.\.venv\Scripts\python.exe -c "import flask, psycopg2, dotenv; print('dependencies OK')"
```

## 4. Environment Configuration

Create a local file from the template:

```powershell
Copy-Item .env.example .env
```

Edit `.env` locally. It may contain secrets and must never be pushed to GitHub. The template contains names only and no real credentials.

### Application variables

```env
FLASK_SECRET_KEY=
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
EXPECTED_FUNCTIONS=
EXPECTED_TABLES=
TABLE_NAME_PATTERN=%
CREDENTIALS_DB=database_credentials.sqlite3
APP_USER=developer
APP_DATABASE_URL=
```

`APP_DATABASE_URL` is the PostgreSQL database used for saved connection metadata and `tbl_deployment_backup_registry`. When it is set, the backup list and backup metadata are stored there. If it is empty, the registry falls back to the connected Live database for backward compatibility.

Authentication and the database-driven sidebar also use `APP_DATABASE_URL`. Run `database_security.sql` once against that database, then create the first administrator interactively:

```powershell
.\.venv\Scripts\python.exe init_security.py
.\.venv\Scripts\python.exe create_admin.py
```

The admin menu at `/admin/menus` stores internal routes and external links in PostgreSQL. New menu records appear in the sidebar after the next request; internal routes must point to an existing Flask endpoint. Users without the corresponding database permission receive `403`, including on direct URL and API access.

### Database variables

The current workflow also supports saving database metadata through the application's SQLite credential registry. These variables document the established T&D and Live configuration names:

```env
TD_DB_HOST=
TD_DB_PORT=5432
TD_DB_NAME=
TD_DB_USER=
TD_DB_PASSWORD=
TD_DB_SSLMODE=require

LIVE_DB_HOST=
LIVE_DB_PORT=5432
LIVE_DB_NAME=
LIVE_DB_USER=
LIVE_DB_PASSWORD=
LIVE_DB_SSLMODE=require
```

Never put actual database passwords in source code or documentation. Use a least-privilege deployment account. Do not use `localhost` for a production database unless PostgreSQL is running on the same Render service, which is normally not the case.

### Brevo SMTP variables

```env
NOTIFICATION_EMAIL_TO=
BREVO_SMTP_HOST=smtp-relay.brevo.com
BREVO_SMTP_PORT=587
BREVO_SMTP_USERNAME=
BREVO_SMTP_PASSWORD=
NOTIFICATION_EMAIL_FROM=
NOTIFICATION_EMAIL_FROM_NAME=PostgreSQL Deployment Manager
```

The SMTP username, password/key, sender, and recipients are read only when notification sending is used. They are not required for application startup. Brevo credentials belong in local `.env` or Render Environment Variables, never in GitHub.

### Optional mobile notification variables

```env
NOTIFICATION_MOBILE_TO=
MOBILE_NOTIFICATION_WEBHOOK=
```

These are required only when the existing mobile notification integration is enabled.

## 5. Local Notification Test

Run:

```powershell
.\.venv\Scripts\python.exe test_notification.py
```

The script checks the same `BREVO_SMTP_*` names used by the application and never prints the password. A configured test reports:

```text
Email configured: YES
SMTP host configured: YES
SMTP username configured: YES
SMTP password configured: YES
Recipient configured: YES
Email: SENT
```

`Email: FAILED` includes a safe error summary. `Email: NOT_CONFIGURED` means no recipient or complete SMTP configuration was supplied. This test does not create a backup; notification code only attaches backup files already created by deployment.

## 6. Run Locally

Development server:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000`.

Health check:

```powershell
.\.venv\Scripts\python.exe -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5000/health').read().decode())"
```

Expected response:

```json
{"status":"ok"}
```

The server uses `FLASK_HOST` locally and Render's `PORT` when available. When `RENDER` is set without an explicit host, it binds to `0.0.0.0`.

Production-style local startup:

```powershell
python -m gunicorn app:app
```

The same command is used on Render. Stop a development server with `Ctrl+C` before starting another process on the same port.

## 7. Deployment and Backup Behavior

The existing deployment logic remains responsible for:

- function and table comparison
- overloaded function identification
- SQL generation
- deployment confirmation and execution
- pre-deployment backup creation
- backup registry and deployment history

The notification service does not create backups. It only references or attaches files already present in the deployment result. Render's local filesystem is ephemeral, so generated SQL, backups, and the local SQLite registry can disappear after restart or redeploy. Use durable external storage or a durable database if those artifacts must survive; this project does not upload them automatically.

A successful database deployment remains successful if email or mobile notification fails. Failure notification is attempted when a deployment returns a failure result, and notification errors are returned separately.

## 8. Render Deployment - After GitHub Push

Deployment is intentionally not performed by this guide.

1. Push the reviewed project to GitHub.
2. Create a Render Web Service.
3. Connect the GitHub repository.
4. Select the intended branch.
5. Set Root Directory to `deployment_tool/Script/postgres_function_deployer`.
6. Set Build Command to `pip install -r requirements.txt`.
7. Set Start Command to `gunicorn app:app`.
8. Add the application, database, Brevo, and optional mobile variables in Render Environment Variables.
9. Confirm the production PostgreSQL hosts are reachable from Render.
10. Deploy from the Render dashboard.
11. Check Render build and runtime logs.
12. Test `https://YOUR-RENDER-SERVICE.onrender.com/health`.
13. Run a controlled notification test with configured Brevo values.
14. Test T&D and Live database connections.
15. Perform a controlled deployment test with approved objects.

Do not upload `.env`. Do not push Brevo credentials, database passwords, API keys, `credentials.json`, or `token.json`. Render Environment Variables are the production secret store.

Render supplies `PORT`; do not hard-code the production port. The web service must be able to reach both PostgreSQL servers through their real network addresses and firewall rules.

## 9. Render Environment Variable Names

Configure names only through the Render dashboard:

```text
FLASK_SECRET_KEY
FLASK_HOST (optional; Render can use 0.0.0.0 automatically)
FLASK_DEBUG (false)
CREDENTIALS_DB (optional)
APP_USER (optional)
APP_DATABASE_URL
TD_DB_HOST, TD_DB_PORT, TD_DB_NAME, TD_DB_USER, TD_DB_PASSWORD, TD_DB_SSLMODE
LIVE_DB_HOST, LIVE_DB_PORT, LIVE_DB_NAME, LIVE_DB_USER, LIVE_DB_PASSWORD, LIVE_DB_SSLMODE
NOTIFICATION_EMAIL_TO
BREVO_SMTP_HOST, BREVO_SMTP_PORT, BREVO_SMTP_USERNAME, BREVO_SMTP_PASSWORD
NOTIFICATION_EMAIL_FROM, NOTIFICATION_EMAIL_FROM_NAME
NOTIFICATION_MOBILE_TO, MOBILE_NOTIFICATION_WEBHOOK (optional)
```

## 10. Git Security

The application directory `.gitignore` protects `.env`, `credentials.json`, `token.json`, `.venv/`, `__pycache__/`, `*.pyc`, `database_credentials.sqlite3`, `generated_scripts/`, and backups. Check before a future push:

```powershell
git status --short
git ls-files | Select-String -Pattern '(^|/)(\.env|credentials\.json|token\.json|database_credentials\.sqlite3)$'
```

If a secret has ever been committed, rotate it and remove it from Git history using your organization's approved process. Do not print secrets while diagnosing configuration.

## 11. Troubleshooting

### Python not found

- Error: `python is not recognized`.
- Cause: Python is not installed or is not on `PATH`.
- Check: `py --version`.
- Fix: install Python 3.11 and enable the PATH option, then recreate the venv.

### Virtual environment activation failure

- Error: script execution is disabled.
- Cause: PowerShell execution policy.
- Check: `Get-ExecutionPolicy -List`.
- Fix: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then run `..\.venv\Scripts\Activate.ps1`.

### pip missing

- Error: `No module named pip`.
- Cause: incomplete venv.
- Check: `..\.venv\Scripts\python.exe -m pip --version`.
- Fix: `..\.venv\Scripts\python.exe -m ensurepip --upgrade` followed by `..\.venv\Scripts\python.exe -m pip install --upgrade pip`.

### Requirements installation failure

- Error: package installation fails.
- Cause: wrong interpreter, network issue, or stale package cache.
- Check: `..\.venv\Scripts\python.exe -m pip --version`.
- Fix: activate the venv, upgrade pip, and retry `python -m pip install -r requirements.txt`.

### psycopg2 DLL error on Windows

- Error: `ImportError: DLL load failed` while importing psycopg2.
- Cause: incompatible interpreter or missing Microsoft runtime.
- Check: `..\.venv\Scripts\python.exe -c "import psycopg2; print('psycopg2 OK')"`.
- Fix: reinstall `psycopg2-binary` in the venv and install the Microsoft Visual C++ Redistributable if required.

```powershell
.\.venv\Scripts\python.exe -m pip install --no-cache-dir --force-reinstall psycopg2-binary==2.9.9
```

### Missing module

- Error: `ModuleNotFoundError`.
- Cause: dependencies were installed into another Python environment.
- Check: `..\.venv\Scripts\python.exe -m pip show Flask psycopg2-binary python-dotenv gunicorn`.
- Fix: run the application with the venv interpreter and reinstall requirements.

### Gunicorn startup failure

- Error: `Failed to find attribute 'app'` or import error.
- Cause: wrong working directory or target.
- Check: run from `deployment_tool/Script/postgres_function_deployer`.
- Fix: use `python -m gunicorn app:app` locally or `gunicorn app:app` on Render.

### Port already in use

- Error: address or port already in use.
- Cause: another Flask/Gunicorn process owns the port.
- Check: `Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue`.
- Fix: stop the owning process or change local `FLASK_PORT`; never override Render's `PORT`.

### .env not loading

- Error: values appear unconfigured.
- Cause: `.env` is missing, in the wrong directory, or has malformed lines.
- Check: `Test-Path .env` and compare names with `.env.example`.
- Fix: run `Copy-Item .env.example .env`, edit it, and restart the process. Never print secret values.

### Brevo SMTP configuration failure

- Error: `NOT_CONFIGURED` or SMTP authentication failure.
- Cause: missing recipient, sender, host, username, password, or unverified sender.
- Check: `python test_notification.py`; it prints presence checks only.
- Fix: set the exact `BREVO_SMTP_*` and `NOTIFICATION_EMAIL_*` names and verify the sender in Brevo.

### Database connection failure

- Error: connection refused, timeout, authentication, or SSL error.
- Cause: incorrect host, port, database, account, SSL mode, firewall, or Render network access.
- Check: test each T&D and Live connection in the application and verify the host is not an unintended `localhost`.
- Fix: correct the environment values and provider firewall rules. Do not fabricate credentials or change a production database from this project.

### Health check failure

- Error: `/health` returns 404 or cannot connect.
- Cause: stale process, wrong port, wrong root directory, or wrong Gunicorn target.
- Check: open `/health` on the actual local or Render URL and inspect logs.
- Fix: restart from the app directory with `python app.py` locally or `gunicorn app:app` on Render.

### Render build failure

- Error: dependency installation fails in Render logs.
- Cause: incorrect Root Directory or Build Command.
- Check: confirm Root Directory is `deployment_tool/Script/postgres_function_deployer`.
- Fix: use `pip install -r requirements.txt` and check the Python version/runtime settings.

### Render start failure

- Error: service exits during startup.
- Cause: incorrect Start Command, missing required import, or invalid configuration.
- Check: review runtime logs and verify `gunicorn app:app` from the configured root.
- Fix: correct the command or dependency; database and SMTP values are only needed when those features are used.

## 12. Validation Commands

Run before a future commit:

```powershell
.\.venv\Scripts\python.exe -m compileall .
.\.venv\Scripts\python.exe test_notification.py
python -m gunicorn app:app
```

With the server running, check `/health`. Database tests are skipped when real credentials have not been supplied. Do not create fake production credentials or connect to a real production database during local validation.

## 13. Maintenance

Update this README whenever dependencies, environment variables, database privileges, deployment requirements, backup behavior, or troubleshooting steps change. Preserve the existing comparison, deployment, backup, registry, and notification contracts when making future changes.
