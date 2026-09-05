# PostgreSQL Function Deployment Manager

A local Flask dashboard for comparing and deploying PostgreSQL functions and tables between a T&D/test database and a Live/production database. It treats overloaded functions as separate objects by schema, name, and identity arguments, and includes support for SQL generation, comparison, backup tracking, and safe deployment workflows.

This README is intended to be the complete setup and onboarding guide for a new developer or user. The goal is to allow a fresh machine to go from repository clone to a working local application without needing additional hand-holding.

---

## 1. Project purpose

This application helps a developer:

- connect to a T&D/test PostgreSQL database
- connect to a Live PostgreSQL database
- compare functions and tables between the two environments
- review differences and expected objects
- generate deployment SQL scripts
- confirm a deployment before running it
- record deployment audit and backup information

The project is intended for local, developer-controlled workflows and should be used with explicit database permissions and reviewed change approval.

---

## 2. Minimum prerequisites

Before starting, make sure the following are installed and working:

- Git
- Python 3.8 or newer
- pip
- PostgreSQL client connectivity to your target databases
- a text editor or IDE such as VS Code
- access to a T&D database and a Live database
- local permission to create a virtual environment in the project folder
- access to a terminal or PowerShell window

### Recommended versions

- Python: 3.8+; 3.10 or 3.11 recommended
- Git: 2.x+
- pip: latest available for your Python version
- PostgreSQL: 12+ preferred for compatibility, though earlier versions may work if your systems support the needed functions
- VS Code: current stable version

---

## 3. Required tools and dependencies

### Required runtime tools

- Python 3.8+
- pip
- Git
- PostgreSQL client connectivity
- PowerShell or a shell terminal

### Required Python dependencies

The project dependency list is defined in:

```text
deployment_tool/Script/postgres_function_deployer/requirements.txt
```

Current contents:

```text
Flask>=3.0,<4
psycopg2-binary>=2.9,<3
python-dotenv>=1.0,<2
```

### Recommended optional tools

- VS Code with Python extension
- Pylance
- GitLens
- pgAdmin or DBeaver
- psql command-line client

### Required Windows runtime dependency

On Windows, `psycopg2` can fail at import time if the Microsoft Visual C++ Redistributable is missing.

Install:

- Microsoft Visual C++ 2015-2022 Redistributable (x64 recommended)

This is commonly required to fix the error:

```text
ImportError: DLL load failed while importing _psycopg
```

---

## 4. Project structure

```text
DB-Deployment-Tool/
├── README.md
├── deployment_tool/
│   └── Script/
│       └── postgres_function_deployer/
│           ├── app.py
│           ├── config.py
│           ├── requirements.txt
│           ├── .env.example
│           ├── .gitignore
│           ├── __init__.py
│           ├── generated_scripts/
│           ├── sqlite database files (runtime-generated, if configured)
│           ├── static/
│           │   ├── css/
│           │   └── js/
│           ├── templates/
│           │   └── index.html
│           └── services/
│               ├── __init__.py
│               ├── backup_service.py
│               ├── comparison_service.py
│               ├── credential_service.py
│               ├── db_service.py
│               ├── deployment_service.py
│               ├── function_service.py
│               ├── registry_service.py
│               ├── sql_generator.py
│               ├── table_deployment_service.py
│               ├── table_service.py
│               └── ...
```

### Important files

- `app.py` — Flask entry point and route definitions
- `config.py` — environment-driven configuration values
- `requirements.txt` — Python package dependencies
- `.env.example` — sample environment file
- `services/db_service.py` — connection validation and database connection logic
- `services/function_service.py` — function comparison logic
- `services/table_service.py` — table comparison logic
- `services/deployment_service.py` — deployment logic
- `services/registry_service.py` — backup registry for deployment tracking
- `services/credential_service.py` — saved database metadata logic using SQLite
- `templates/index.html` — frontend skeleton
- `static/js/app.js` and `static/js/tables.js` — browser behavior

---

## 5. Clone the repository

```bash
git clone <repository-url>
cd DB-Deployment-Tool
```

If you are working in a Windows environment and already know the project path, the local app folder is:

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
```

On Linux/macOS:

```bash
cd /path/to/DB-Deployment-Tool/deployment_tool/Script/postgres_function_deployer
```

---

## 6. Python virtual environment setup

Create a virtual environment in the project folder itself.

### Windows PowerShell

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
python -m venv .venv
```

### Windows CMD

```cmd
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
python -m venv .venv
```

### Linux/macOS

```bash
cd /path/to/DB-Deployment-Tool/deployment_tool/Script/postgres_function_deployer
python3 -m venv .venv
```

### Activate the virtual environment

#### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

#### Windows CMD

```cmd
.venv\Scripts\activate.bat
```

#### Linux/macOS

```bash
source .venv/bin/activate
```

> Important: always use the project virtual environment and avoid running the app with the system Python unless intentionally testing a different interpreter.

---

## 7. Install dependencies

From the project folder with the virtual environment active:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Alternative explicit install:

```powershell
python -m pip install Flask>=3.0,<4 psycopg2-binary>=2.9,<3 python-dotenv>=1.0,<2
```

### Verify importability

```powershell
python -c "import flask, psycopg2, dotenv; print('dependencies ok')"
```

If this fails with a `psycopg2` DLL error, install the Microsoft VC++ runtime and retry.

---

## 8. Copy and configure the environment file

```powershell
Copy-Item .env.example .env
```

On Linux/macOS:

```bash
cp .env.example .env
```

### Example `.env.example`

```text
FLASK_SECRET_KEY=replace-with-a-long-random-value
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
# Optional comma-separated or one-per-line names, in addition to %idatum% matches.
EXPECTED_FUNCTIONS=
```

### Required and optional environment variables

The app reads values in `config.py` and exposes the following settings:

| Variable | Required | Purpose |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | Yes | Flask session signing key. Use a strong random value. |
| `FLASK_HOST` | Recommended | Host for the app. Usually `127.0.0.1`. |
| `FLASK_PORT` | Recommended | Port used by the Flask app. Default is `5000`. |
| `FLASK_DEBUG` | Optional | Enables debug mode when set to `true`. |
| `EXPECTED_FUNCTIONS` | Optional | Function names to include in comparison results. Accepts comma-separated or newline-separated entries. |
| `EXPECTED_TABLES` | Optional | Table names to include in table comparison scopes. |
| `TABLE_NAME_PATTERN` | Optional | Pattern used when listing tables; default is `%`. |
| `CREDENTIALS_DB` | Optional | Alternate SQLite file location for saved database credentials. |
| `APP_USER` | Optional | Audit identity for saved database records and history. |

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
```

> Never commit a real `.env` file to Git. It may contain local settings and secrets.

---

## 9. Database setup and requirements

This project connects to PostgreSQL databases for both comparison and deployment.

### Required databases

You need at least two PostgreSQL database connections:

1. T&D/test database
   - should be reachable and readable
   - used for comparison and object inspection

2. Live/production database
   - used for validation, comparison, and deployment
   - should be carefully controlled with least-privilege access

### Database privileges required

The app expects database users with enough rights to:

- connect to the database
- read PostgreSQL metadata and catalogs
- query function and table definitions
- run deployment SQL in the Live environment if replacement is required

At minimum, the T&D user should have read access to the relevant schemas and function definitions.

The Live user should have replacement permissions for reviewed objects only.

### PostgreSQL functions and metadata used by the app

The application uses PostgreSQL catalog functions and views such as:

- `pg_get_function_identity_arguments`
- `pg_get_function_arguments`
- `pg_get_function_result`
- `pg_get_functiondef`
- `prosrc`

These are standard PostgreSQL catalog features and do not require custom app-specific DB objects to exist before the app runs.

### Database extension requirements

For this application's function comparison and deployment workflow, no special custom extension is required by default.

However, your PostgreSQL environment must support the functions and catalog metadata being queried. If a database is restricted or uses custom security policies, ensure the application user can still access the necessary metadata.

### Runtime-created database objects

This application creates local SQLite metadata at runtime and also creates a PostgreSQL backup registry table when the app connects to the Live database.

#### Local SQLite metadata

The app uses `database_credentials.sqlite3` as the local credentials store unless overridden.

It stores:

- host
- port
- database name
- username
- alias
- audit metadata

Passwords are never stored.

#### PostgreSQL registry table

`services/registry_service.py` creates a table such as:

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

The code also creates indexes for file name, object name, deployment ID, etc. These are created automatically when the app uses the registry functionality.

### Database migration or initialization

There is no dedicated schema migration system in this repo for PostgreSQL. The app relies on:

- PostgreSQL access rights already granted to the user
- local SQLite file creation for saved database metadata
- runtime creation of the registry table when the Live connection is initialized

Therefore, the main database setup is mostly configuration and privilege verification rather than database bootstrapping.

---

## 10. Configure local environment and secrets

Before the application starts, ensure the `.env` file is populated with safe values:

```text
FLASK_SECRET_KEY=some-long-random-value
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
```

For example:

```powershell
notepad .env
```

Set:

- strong `FLASK_SECRET_KEY`
- correct host and port
- a safe application user name if you are using `APP_USER`
- optional function or table names to highlight in comparison results

---

## 11. Start the backend

From the project directory:

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
```

Then start the Flask app:

```powershell
python app.py
```

Or, if using the venv interpreter explicitly:

```powershell
.\.venv\Scripts\python.exe app.py
```

### Default start URL

The application runs on:

```text
http://127.0.0.1:5000
```

### Port configuration

Change the port in `.env`:

```text
FLASK_PORT=5001
```

Then restart the app.

### Port conflict handling

If port `5000` is already occupied, either:

- stop the process using that port, or
- use a different `FLASK_PORT`

---

## 12. Frontend setup

This project does not use a separate Node.js frontend build chain. The UI is directly served by Flask from:

- `templates/index.html`
- `static/css/style.css`
- `static/js/app.js`
- `static/js/tables.js`

No separate `npm install` or frontend build step is required.

Open the app in a browser:

```text
http://127.0.0.1:5000
```

---

## 13. API routes and backend services

The app exposes routes for:

- database configuration and connection testing
- T&D and Live database connection setup
- comparison requests
- function and table diff retrieval
- script generation
- deployment actions
- deployment history

### Examples

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

No external backend service or app server is required beyond the Flask app itself.

---

## 14. Git setup and repository hygiene

### Configure Git identity

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

### Recommended `.gitignore`

Add the following to the repository root `.gitignore`:

```text
.venv/
.env
__pycache__/
*.pyc
generated_scripts/
database_credentials.sqlite3
```

### Clean unwanted `.venv` noise from Git

If the repo shows a huge list of untracked changes caused by the virtual environment:

```powershell
Set-Location "C:\Deployment Tool\DB-Deployment-Tool"
@'
.venv/
.env
__pycache__/
*.pyc
generated_scripts/
database_credentials.sqlite3
'@ | Out-File -FilePath .gitignore -Encoding UTF8 -Append

git status
```

If `.venv` was already tracked, remove it from Git tracking:

```powershell
git rm -r --cached .venv
```

Then verify the repo is clean apart from intended source edits:

```powershell
git status --short --branch
```

---

## 15. VS Code setup recommendations

### Recommended extensions

- Python
- Pylance
- GitLens
- PostgreSQL or SQL tools (optional)

### Recommended workflow

1. Open the repo root in VS Code
2. Select the Python interpreter in the project venv
3. Open a terminal in the app folder
4. run the app from that terminal

To confirm the selected Python is the venv interpreter:

```powershell
python -c "import sys; print(sys.executable)"
```

It should point to the local `.venv` path rather than the global Python installation.

---

## 16. Full setup sequence for a fresh machine

### Windows PowerShell

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool"

git clone <repository-url>
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"

python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env

# Edit .env before starting the app
# FLASK_SECRET_KEY=your-long-random-secret
# FLASK_HOST=127.0.0.1
# FLASK_PORT=5000
# FLASK_DEBUG=false

python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

### Linux/macOS

```bash
cd /path/to/DB-Deployment-Tool
git clone <repository-url>
cd /path/to/DB-Deployment-Tool/deployment_tool/Script/postgres_function_deployer

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env

python app.py
```

---

## 17. Verification checklist

The setup is working correctly when all of the following are true:

- the app starts without import errors
- `python app.py` runs from the project folder
- the browser opens to `http://127.0.0.1:5000`
- the dashboard loads properly
- the T&D database connects successfully
- the Live database connects successfully
- function comparison results are returned
- SQL script generation succeeds
- deployment confirmation and deployment flow work as expected
- generated script files appear in `generated_scripts/`

---

## 18. Common setup errors and solutions

### Error: `python app.py` says the file cannot be found

Caused by running the command from the wrong directory.

Fix:

```powershell
cd "C:\Deployment Tool\DB-Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
python app.py
```

### Error: PowerShell cannot run `.venv\Scripts\Activate.ps1`

Cause: script execution policy is blocking activation.

Fix:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Error: `ModuleNotFoundError: No module named 'psycopg2'`

Cause: dependencies were installed into the global Python instead of the project venv.

Fix:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Error: `ImportError: DLL load failed while importing _psycopg`

Cause: missing PostgreSQL client runtime / Visual C++ runtime on Windows.

Fix:

- install the Microsoft Visual C++ 2015-2022 Redistributable (x64)
- reinstall `psycopg2-binary` inside the venv

```powershell
.\.venv\Scripts\python.exe -m pip install --force-reinstall psycopg2-binary
```

### Error: `Address already in use`

Cause: port conflict.

Fix:

- stop the process using the port, or
- change `FLASK_PORT` in `.env`

### Error: database connection failed

Check:

- correct host and port
- correct database name
- correct username/password
- firewall restrictions
- remote PostgreSQL not listening on the expected address
- database user lacks privileges

### Error: app starts but comparison returns no data

Check:

- the T&D and Live database credentials are correct
- the user has access to the schemas and catalog metadata
- the expected database objects actually exist
- `EXPECTED_FUNCTIONS` and `EXPECTED_TABLES` are correctly configured

---

## 19. Common compatibility and dependency issues

### Python compatibility

This project is compatible with Python 3.8+.

The environment in which this repository was validated used Python 3.8, but newer versions work as long as the environment is installed correctly and dependencies remain inside the venv.

### Flask compatibility

Required package range:

```text
Flask>=3.0,<4
```

Do not mix very old Flask versions with new dependencies.

### psycopg2 compatibility

`psycopg2-binary` usually works well in local development but may require the Windows VC++ runtime.

---

## 20. Database troubleshooting

If the database connection still fails, validate connectivity outside the app:

### Using psql

```powershell
psql -h <host> -p <port> -U <username> -d <database>
```

### Using pgAdmin or DBeaver

- confirm the server is listening
- confirm the port is open
- confirm login credentials are valid
- confirm the user can access the required schemas

### Permissions to verify

The database user should be able to:

- connect to the DB
- read function definitions
- read table definitions and metadata
- create or replace functions (for Live deployment)
- write deployment backup registry data if required by application logic

---

## 21. Permission and security issues

This app is built to operate in a controlled local environment. Use least-privilege roles.

Recommended approach:

- T&D user: read-only access to comparison data
- Live user: only required rights to replace approved database objects
- do not share production credentials broadly
- do not keep real secrets in the repo

---

## 22. Services that must be running before startup

Before starting the app, ensure the following are available:

- PostgreSQL server for the T&D database
- PostgreSQL server for the Live database
- network access between the machine and the database endpoints
- working credentials for both systems

The app does not run a database server itself; it only connects to existing PostgreSQL instances.

---

## 23. Known issues and workarounds

### Issue: large Git diff caused by `.venv`

Workaround:

- put `.venv/` in `.gitignore`
- do not track local environment files

### Issue: PowerShell activation blocked

Use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Issue: `psycopg2` import fails on Windows

Install the Microsoft C++ Redistributable and reinstall `psycopg2-binary` in the local venv.

### Issue: app binds to the wrong port

Update `.env` and restart the app.

### Issue: Live connection not enabled until database test passes

This is expected behavior. Connect and validate the Live database before using deployment controls.

---

## 24. FAQ

### Is Node.js required?

No. This project is a Python Flask application and does not require a Node build step.

### Is Docker required?

No. The project is designed to run directly on a local machine.

### Do I need a database migration tool?

Not for the app itself. Database setup is mainly about credentials, privileges, and connection validation.

### Can I use a different database port or host?

Yes. Use `FLASK_HOST` and `FLASK_PORT` for the local app, and provide the correct target PostgreSQL host/port when connecting via the UI.

### Can I run this on Linux or macOS?

Yes, the project is cross-platform as long as the dependencies are installed in a working venv.

---

## 25. Final recommended workflow

For a new developer, the expected path is:

1. clone the repo
2. install Python and Git
3. create `.venv` inside the app folder
4. install dependencies using the venv Python
5. copy `.env.example` to `.env`
6. set the required environment variables
7. confirm PostgreSQL connectivity for the T&D and Live databases
8. ensure required privileges are present
9. start the application with `python app.py`
10. open `http://127.0.0.1:5000`
11. verify the dashboard loads and the comparisons work

---

## 26. Maintenance note

This README should be updated whenever the project adds or changes:

- dependencies
- environment variables
- required runtime tools
- database privileges or setup steps
- compatibility issues or version constraints
- installation or startup errors
- configuration requirements for new modules or features

The purpose of this document is to keep setup instructions accurate, reproducible, and maintainable for all future developers and users.
