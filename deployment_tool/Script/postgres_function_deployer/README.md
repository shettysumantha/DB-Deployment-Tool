# PostgreSQL Function Deployment Manager

A local Flask dashboard for comparing and deploying PostgreSQL functions and tables between a T&D/test database and a Live/production database. It treats overloaded functions as separate objects by schema, name, and identity arguments and includes comparison, script generation, deploy confirmation, and backup tracking.

This README is the main developer setup guide for the project in this folder. It is intentionally detailed so a new developer can set up the app on a fresh machine without needing additional instructions.

---

## 1. Project purpose

This application allows a developer to:

- connect to a T&D/test PostgreSQL database
- connect to a Live PostgreSQL database
- compare functions and tables between environments
- review differences before deployment
- generate SQL deployment scripts
- confirm deployment actions before execution
- keep a record of deployment backups and metadata

---

## 2. Minimum requirements

Before setting up the project, ensure the following are installed:

- Git
- Python 3.8 or newer
- pip
- PostgreSQL client connectivity
- a local terminal or PowerShell shell
- VS Code or another editor
- access to a T&D database and a Live database

### Recommended versions

- Python: 3.8+; 3.10 or 3.11 recommended
- Git: 2.x+
- pip: latest available for the installed Python
- PostgreSQL: 12+ preferred
- VS Code: current stable version

---

## 3. Required tools and dependencies

### Python packages required

The project dependency file is:

```text
requirements.txt
```

It contains:

```text
Flask>=3.0,<4
psycopg2-binary==2.9.9
python-dotenv>=1.0,<2
```

### Recommended tools

- VS Code
- Python extension
- Pylance
- pgAdmin or DBeaver
- psql (optional)

### Windows-specific dependency

On Windows, `psycopg2` may fail with:

```text
ImportError: DLL load failed while importing _psycopg
```

Install the Microsoft Visual C++ Redistributable (x64) and retry the install.

---

## 4. Project structure

```text
postgres_function_deployer/
├── app.py
├── config.py
├── requirements.txt
├── .env.example
├── .gitignore
├── __init__.py
├── generated_scripts/
├── static/
│   ├── css/
│   └── js/
├── templates/
│   └── index.html
└── services/
    ├── __init__.py
    ├── backup_service.py
    ├── comparison_service.py
    ├── credential_service.py
    ├── db_service.py
    ├── deployment_service.py
    ├── function_service.py
    ├── registry_service.py
    ├── sql_generator.py
    ├── table_deployment_service.py
    ├── table_service.py
    └── ...
```

### Important files

- `app.py` — application entry point
- `config.py` — environment configuration
- `requirements.txt` — Python dependencies
- `.env.example` — sample environment file
- `services/db_service.py` — database connection logic
- `services/function_service.py` — function comparison logic
- `services/registry_service.py` — backup registry table creation and record tracking
- `services/credential_service.py` — SQLite metadata for saved DB configs

---

## 5. Clone the project and open the folder

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool"
```

Then open the app folder:

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
```

---

## 6. Create and activate the virtual environment

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Windows CMD

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> Use the project venv, not the system Python.

---

## 7. Install dependencies

From the project folder with the venv active:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

You can also install the exact packages directly:

```powershell
python -m pip install Flask>=3.0,<4 psycopg2-binary==2.9.9 python-dotenv>=1.0,<2
```

### Verify dependencies are available

```powershell
python -c "import flask, psycopg2, dotenv; print('dependencies ok')"
```

If this fails with a `psycopg2` DLL error, confirm that the project venv is being used and reinstall the pinned Windows wheel:

```powershell
python -m pip uninstall -y psycopg2-binary
python -m pip install --no-cache-dir psycopg2-binary==2.9.9
```

If the error continues, install the Microsoft Visual C++ Redistributable (x64) and retry.

---

## 8. Configure environment settings

Copy the sample environment file:

```powershell
Copy-Item .env.example .env
```

On Linux/macOS:

```bash
cp .env.example .env
```

### `.env.example`

```text
FLASK_SECRET_KEY=replace-with-a-long-random-value
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
# Optional comma-separated or one-per-line names, in addition to %idatum% matches.
EXPECTED_FUNCTIONS=
```

### Required variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | Yes | Flask session secret; use a strong random value |
| `FLASK_HOST` | Recommended | Local host, usually `127.0.0.1` |
| `FLASK_PORT` | Recommended | Dev port, default `5000` |
| `FLASK_DEBUG` | Optional | Enables debug mode when `true` |
| `EXPECTED_FUNCTIONS` | Optional | Function names to match or highlight |
| `EXPECTED_TABLES` | Optional | Table names to include in comparison scope |
| `TABLE_NAME_PATTERN` | Optional | Table filter pattern, default `%` |
| `CREDENTIALS_DB` | Optional | Alternate path for SQLite saved DB metadata |
| `APP_USER` | Optional | Audit identity for saved database records |
| `NOTIFICATION_EMAIL_TO` | Optional | Deployment email recipient |
| `NOTIFICATION_MOBILE_TO` | Optional | Deployment mobile recipient |
| `SMTP_HOST` | Optional | SMTP server; leave blank to disable email |
| `SMTP_PORT` | Optional | SMTP port, default `587` |
| `SMTP_USERNAME` | Optional | SMTP username |
| `SMTP_PASSWORD` | Optional | SMTP password; keep local and uncommitted |
| `GOOGLE_CREDENTIALS_FILE` | Optional | Local Google OAuth client JSON path; never commit it |
| `GOOGLE_TOKEN_FILE` | Optional | Local OAuth token path created after consent; never commit it |
| `MOBILE_NOTIFICATION_WEBHOOK` | Optional | Server-side webhook for mobile notifications |

### Example `.env`

```text
FLASK_SECRET_KEY=replace-with-a-long-random-value-32-plus-chars
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
EXPECTED_FUNCTIONS=fn_example_one,fn_example_two
EXPECTED_TABLES=customer,order_header
TABLE_NAME_PATTERN=%
CREDENTIALS_DB=C:/secure/path/database_credentials.sqlite3
APP_USER=developer-name
NOTIFICATION_EMAIL_TO=SUMANTHASHETTYTECH@GMAIL.COM
NOTIFICATION_MOBILE_TO=1111111111
SMTP_HOST=
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_FROM=database-deployer@localhost
SMTP_USERNAME=
SMTP_PASSWORD=
MOBILE_NOTIFICATION_WEBHOOK=
```

> Never commit `.env` to Git.

Deployment notifications are optional and server-side. Email is sent only when
`SMTP_HOST` is configured, and mobile delivery is sent only when
`MOBILE_NOTIFICATION_WEBHOOK` is configured. Notification errors are reported
after deployment and do not roll back a successful database deployment.

### Google email credentials

`credentials.json` is an OAuth client configuration, not an email password. It
does not identify an email account or authorize sending by itself. Gmail email
delivery also requires a one-time OAuth consent flow that creates a local token
file. Keep both files outside Git:

```text
GOOGLE_CREDENTIALS_FILE=C:/Deployment Tool/DB-Deployment-Tool/credentials.json
GOOGLE_TOKEN_FILE=C:/Deployment Tool/DB-Deployment-Tool/token.json
```

Do not place Gmail passwords, app passwords, OAuth tokens, or client secrets in
source code or commit them. A Google OAuth client JSON alone cannot replace the
required account authorization token.

---

## 9. Database setup and requirements

The app compares and deploys PostgreSQL functions and tables between a T&D/test database and a Live database.

### Required database access

You need:

1. a T&D/test database that is reachable and readable
2. a Live database that is reachable and controlled with least-privilege access

### Required PostgreSQL permissions

The connection user should have:

- `CONNECT` rights to the target databases
- access to relevant schemas
- read access to PostgreSQL catalog metadata
- ability to create or replace functions/tables in Live, if deployment is allowed

### PostgreSQL functions used by the app

The comparison code relies on standard PostgreSQL catalog functions such as:

- `pg_get_function_identity_arguments`
- `pg_get_function_arguments`
- `pg_get_function_result`
- `pg_get_functiondef`
- `prosrc`

No custom extension is required by default for basic comparison logic.

### Database objects created at runtime

#### SQLite metadata store

The app uses a local SQLite database for saved connection metadata, such as:

- alias
- host
- port
- database name
- username
- audit metadata

Passwords are not stored.

#### PostgreSQL backup registry table

The app creates a registry table for deployment history when connecting to the Live database:

```sql
CREATE TABLE IF NOT EXISTS public.tbl_deployment_backup_registry (
    backup_id SERIAL PRIMARY KEY,
    deployment_id VARCHAR(255),
    deployment_version VARCHAR(255),
    deployment_status VARCHAR(50),
    object_type VARCHAR(100),
    schema_name VARCHAR(255),
    object_name VARCHAR(255),
    object_signature TEXT,
    backup_file_name VARCHAR(255),
    backup_file_path TEXT,
    backup_created_at TIMESTAMPTZ,
    file_size_bytes BIGINT,
    file_checksum VARCHAR(255)
);
```

And indexes are created for registry usage.

---

## 10. Start the backend

From the project directory, start the app with the project interpreter:

```powershell
.\.venv\Scripts\python.exe app.py
```

Default URL:

```text
http://127.0.0.1:5000
```

### Port configuration

Set the app port in `.env`:

```text
FLASK_PORT=5001
```

If port `5000` is already taken, either stop the conflicting process or change the port.

---

## 11. Frontend

The app serves its own UI from Flask using:

- `templates/index.html`
- `static/css/style.css`
- `static/js/app.js`
- `static/js/tables.js`

No separate Node.js frontend build step is required.

Open the app in your browser at:

```text
http://127.0.0.1:5000
```

---

## 12. API routes

The project exposes routes such as:

- `GET /databases`
- `GET /api/databases`
- `POST /databases/test-connection`
- `POST /api/connect-td`
- `POST /api/test-live-connection`
- `POST /api/compare`
- `GET /api/functions`
- `POST /api/generate-script`
- `POST /api/deploy-function`
- `POST /api/deploy-selected`
- `GET /api/deployment-history`

---

## 13. Git hygiene and repo cleanup

This project should ignore local environment files so Git does not show huge virtual-environment diffs.

Add this to the repository root `.gitignore`:

```text
.venv/
.env
__pycache__/
*.pyc
generated_scripts/
database_credentials.sqlite3
```

If `.venv` is already being tracked, remove it from Git tracking:

```powershell
git rm -r --cached .venv
```

---

## 14. Windows troubleshooting

### A. PowerShell blocks script activation

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### B. `psycopg2` import fails with DLL error

Use the project venv and reinstall the Python 3.8-compatible binary wheel:

```powershell
.\.venv\Scripts\python.exe -m pip install --no-cache-dir --force-reinstall psycopg2-binary==2.9.9
```

Then verify:

```powershell
.\.venv\Scripts\python.exe -c "import psycopg2; print(psycopg2.__version__)"
```

### C. `python app.py` is using the wrong Python

Always run the app like this:

```powershell
.\.venv\Scripts\python.exe app.py
```

---

## 15. Common errors and fixes

### Error: app cannot find `app.py`

Fix:

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
```

### Error: `ModuleNotFoundError: No module named 'psycopg2'`

Fix:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Error: `ImportError: DLL load failed while importing _psycopg`

Fix:

- use the project venv explicitly: `..\\.venv\\Scripts\\python.exe app.py`
- install the Python 3.8-compatible binary wheel: `python -m pip install --no-cache-dir psycopg2-binary==2.9.9`
- install Microsoft Visual C++ Redistributable (x64)
- ensure you are using the venv Python, not the system Python

### Error: `Address already in use`

Fix:

- stop the process using the port, or
- change `FLASK_PORT` in `.env`

### Error: database connection fails

Check:

- host and port are correct
- database name is correct
- username and password are correct
- PostgreSQL is reachable from your machine
- user has required read/deployment rights

---

## 16. Verification checklist

The project is set up correctly when:

- the venv is active
- dependencies install successfully
- `.env` is configured
- `python app.py` starts without import errors
- the app loads at `http://127.0.0.1:5000`
- T&D connection passes
- Live connection passes
- function comparison and script generation work

---

## 17. Maintenance note

When new setup requirements, dependencies, version constraints, database privileges, or troubleshooting steps are identified, update this README to keep the setup instructions current and beginner-friendly.

This document is the source of truth for project setup in this folder.
