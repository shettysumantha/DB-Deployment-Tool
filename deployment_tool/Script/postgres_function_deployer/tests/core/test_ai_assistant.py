import json
import os
import unittest
from unittest.mock import patch

from core.ai_assistant import ollama_service


class FakeOllamaResponse:
    status = 200

    def read(self, _limit):
        return json.dumps({"response": "Use a disposable local demo database."}).encode("utf-8")


class FakeOllamaConnection:
    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_args = None

    def request(self, method, path, body, headers):
        self.request_args = (method, path, json.loads(body), headers)

    def getresponse(self):
        return FakeOllamaResponse()

    def close(self):
        pass


class OllamaServiceTests(unittest.TestCase):
    def test_assistant_is_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(ollama_service.assistant_enabled())

    def test_rejects_credentials_and_sql_definitions(self):
        unsafe_prompts = (
            "PG_PASSWORD=my-secret-value",
            "My password is my-secret-value",
            "postgresql://demo:secret@127.0.0.1/demo_db",
            "CREATE FUNCTION public.demo() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql;",
            "SELECT * FROM app_security.users;",
        )
        for prompt in unsafe_prompts:
            with self.subTest(prompt=prompt), self.assertRaises(
                ollama_service.UnsafePromptError
            ):
                ollama_service._validate_prompt(prompt)

    def test_rejects_non_loopback_ollama_url(self):
        with patch.dict(os.environ, {
            "AI_ASSISTANT_ENABLED": "true",
            "OLLAMA_BASE_URL": "http://example.com:11434",
        }):
            with self.assertRaises(ollama_service.AssistantError):
                ollama_service.generate_answer("How do I prepare a safe demo?")

    def test_sends_question_only_to_loopback_ollama(self):
        connection = FakeOllamaConnection("127.0.0.1", 11434, 30)
        with patch.dict(os.environ, {
            "AI_ASSISTANT_ENABLED": "true",
            "OLLAMA_BASE_URL": "http://127.0.0.1:11434",
            "OLLAMA_MODEL": "qwen2.5:3b",
        }), patch.object(
            ollama_service, "HTTPConnection", return_value=connection
        ) as connect:
            answer = ollama_service.generate_answer("How do I prepare a safe demo?")

        self.assertEqual(answer, "Use a disposable local demo database.")
        connect.assert_called_once_with("127.0.0.1", 11434, timeout=120)
        method, path, payload, headers = connection.request_args
        self.assertEqual((method, path), ("POST", "/api/generate"))
        self.assertEqual(payload["model"], "qwen2.5:3b")
        self.assertFalse(payload["stream"])
        self.assertIn("How do I prepare a safe demo?", payload["prompt"])
        self.assertEqual(headers["Content-Type"], "application/json")


class AssistantRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.security import security_service

        with patch.object(security_service, "initialize_security", return_value=True):
            import app as app_module
        cls.app_module = app_module

    def setUp(self):
        self.patches = [
            patch.object(self.app_module, "ensure_security_initialized", return_value=True),
            patch.object(
                self.app_module,
                "user_session_state",
                return_value={
                    "is_active": True,
                    "session_version": 1,
                    "must_change_password": False,
                },
            ),
        ]
        for active_patch in self.patches:
            active_patch.start()
        self.addCleanup(self._stop_patches)
        self.client = self.app_module.app.test_client()
        with self.client.session_transaction() as user_session:
            user_session["user_id"] = 7
            user_session["session_version"] = 1
            user_session["_csrf_token"] = "test-csrf"

    def _stop_patches(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()

    def test_assistant_chat_requires_csrf_token(self):
        response = self.client.post(
            "/api/assistant/chat",
            json={"message": "How do I prepare a safe demo?"},
        )

        self.assertEqual(response.status_code, 400)

    def test_assistant_chat_returns_local_answer(self):
        with patch.object(self.app_module, "assistant_enabled", return_value=True), patch.object(
            self.app_module, "generate_answer", return_value="Use a disposable database."
        ) as generate:
            response = self.client.post(
                "/api/assistant/chat",
                json={"message": "How do I prepare a safe demo?"},
                headers={"X-CSRFToken": "test-csrf"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"answer": "Use a disposable database."})
        generate.assert_called_once_with("How do I prepare a safe demo?")

    def test_assistant_page_requires_login(self):
        with self.client.session_transaction() as user_session:
            user_session.clear()

        response = self.client.get("/assistant")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_authenticated_assistant_page_renders_demo(self):
        with patch.object(self.app_module, "assistant_enabled", return_value=True), patch.object(
            self.app_module, "configured_model", return_value="qwen2.5:3b"
        ), patch.object(self.app_module, "user_menus", return_value=[]), patch.object(
            self.app_module, "user_roles", return_value=[]
        ):
            response = self.client.get("/assistant")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AUTHENTICATED LOCAL DEMO", response.data)
        self.assertIn(b"Do not submit passwords", response.data)

    def test_dashboard_links_to_authenticated_assistant(self):
        with patch.object(self.app_module, "assistant_enabled", return_value=True), patch.object(
            self.app_module, "user_menus", return_value=[]
        ), patch.object(self.app_module, "user_roles", return_value=[]):
            response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'href="/assistant"', response.data)

    def test_chat_api_requires_login(self):
        with self.client.session_transaction() as user_session:
            user_session.clear()
            user_session["_csrf_token"] = "test-csrf"

        response = self.client.post(
            "/api/assistant/chat",
            json={"message": "How do I prepare a safe demo?"},
            headers={"X-CSRFToken": "test-csrf"},
        )

        self.assertEqual(response.status_code, 401)
