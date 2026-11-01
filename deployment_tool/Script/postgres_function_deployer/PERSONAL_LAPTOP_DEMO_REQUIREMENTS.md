# Personal Laptop Demo Requirements

This note is a handoff checklist for continuing the demo setup on a personal laptop. No credentials are included here.

## Current status

- The Ollama model downloaded for this attempt has been removed. The Ollama executable is absent and its local service is not running on the office laptop.
- Ollama-specific application code has been removed from this project. The performance/health dashboard and other unrelated application changes remain.
- The office laptop did not have a usable isolated PostgreSQL server: its PostgreSQL 16 binaries lacked server files, and a PostgreSQL 17 installer attempt was cancelled.
- No local demo database or `admin` account was created. No database was changed.
- The password pasted in the conversation must be rotated. Do not copy the office `.env` to another computer.

## Personal laptop prerequisites

1. A supported Python installation and the project dependencies:
   ```powershell
   cd "C:\DB Deployment Tool\Deployment-Tool\deployment_tool\Script\postgres_function_deployer"
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
2. PostgreSQL **server** (not just `psql`/client tools), available locally or an explicitly approved non-production database. For an isolated demo, use a fresh local PostgreSQL instance and a dedicated demo database/user; do not point at production or the configured office application database.
3. If enabling the AI assistant later: install Ollama on the personal laptop, start its local service, and download the chosen model. The previous planned model was `qwen2.5:3b`; confirm the laptop has enough disk space and memory first. Ollama code is not currently connected in this project and must be implemented and tested again before the assistant can work.
4. Keep secrets in a local, ignored `.env`. Start from `.env.example`; do not reuse/copy the office `.env`. Configure local `PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USER`, `PG_PASSWORD`, `PG_SSLMODE`, a new `FLASK_SECRET_KEY`, `ADMIN_BOOTSTRAP_PASSKEY`, and a generated `DATABASE_CREDENTIALS_ENCRYPTION_KEY`. Set the local Ollama URL/model only when the AI integration has been re-added.

## Safe local application setup

1. Create a fresh `.env` from `.env.example`, then configure it for the isolated local database.
2. Manually run `database\database_security.sql` against that **new demo database** using a PostgreSQL client. The application does not create its security schema automatically. Review the script before execution.
3. Start the Flask app locally and open `http://127.0.0.1:5000/login`.
4. Use **Create Admin Account** with a one-time local bootstrap passkey. The requested `admin` / `admin@123` credentials are weak; use them only if still explicitly required for an offline, loopback-only demo, never on a shared/network-exposed or production deployment. Prefer a unique strong demo password.
5. Demonstrate navigation/permissions, Menu and Module Management, and saved-connection management against demo data only. Removing a saved connection removes its credential record, not the database.
6. To demonstrate real DB Compare safely, prepare two separate disposable non-production databases and add benign sample tables/functions. Get explicit approval before any test that creates or deletes a database/object. Do not use the internal application database as Source or Target.
7. Test local Ollama inference and the reintroduced assistant only after validating that prompts stay on loopback and never contain credentials or SQL definitions.

## Remaining work for the personal-laptop session

- Re-add the optional local Ollama integration and validate model availability and UI behavior end-to-end.
- Provision an isolated local PostgreSQL demo server/database and bootstrap the demo admin with safe credentials.
- Run DB Compare end-to-end against the two approved disposable databases, then remove only the sample objects/databases that were created for the test.
- Expand performance monitoring only with a defined measurement scope. The existing dashboard reports process-local HTTP request timings; it is not PostgreSQL query profiling or a durable multi-worker metrics system.
- Re-run the complete test suite and review the worktree before presenting the client demo.
