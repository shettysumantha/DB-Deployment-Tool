# PostgreSQL Function Deployment Manager

A local Flask dashboard for comparing selected PostgreSQL functions between a T&D/test database and a Live/production database. It treats overloaded functions as separate objects by schema, name, and identity arguments.

## Run in VS Code

1. Open a terminal in this folder:

   ```powershell
   cd "MVVNL Replica\postgres_function_deployer"
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

2. Set a strong `FLASK_SECRET_KEY` in `.env`. Optional `EXPECTED_FUNCTIONS` values can be comma-separated or one per line. `%idatum%` matches are always included.

3. Start the application:

   ```powershell
   python app.py
   ```

4. Open `http://127.0.0.1:5000`.

## Safety model

- Passwords are accepted over the local HTTPS-capable Flask deployment boundary and held only in server process memory for the current signed session identifier. They are never returned to the browser, written to SQL, or logged by the application.
- Live must pass its connection test before deployment controls unlock.
- Every deployment requires a confirmation modal.
- Bulk deployment runs in alphabetical order inside one transaction and rolls back on the first SQL failure.
- After a successful deployment, the Live catalog is fetched again and the comparison is rebuilt.
- Generated scripts are written under `generated_scripts/` and ignored by Git.

## Comparison and SQL behavior

The source catalog uses `pg_get_function_identity_arguments`, `pg_get_function_arguments`, `pg_get_function_result`, `pg_get_functiondef`, and `prosrc`. Comparison uses the complete PostgreSQL definition with only line-ending and trailing-whitespace normalization. Deployment SQL preserves the source body and emits `$BODY$` unless that tag occurs in the body, in which case a unique `$FUNCn$` tag is selected.

## API routes

`POST /api/connect-td`, `POST /api/test-live-connection`, `POST /api/compare`, `GET /api/functions`, `GET /api/function/<key>/diff`, `POST /api/generate-script`, `POST /api/deploy-function`, `POST /api/deploy-selected`, and `GET /api/deployment-history`.

Use a least-privilege T&D account for reads and a separately controlled Live account with only the permissions required to replace the approved functions. Do not commit `.env` or generated SQL files.
