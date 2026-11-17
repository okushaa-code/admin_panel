"""INaRa админ самбарын тест. Supabase-тэй холбогдохгүй — бүх дуудлагыг орлуулна.

Ажиллуулах: python3 -m unittest discover -s tests -v
"""

import os
import re
import sys
import unittest
from unittest import mock

os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SECRET_KEY"] = ""
os.environ["APP_SECRET_KEY"] = "test-secret"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt  # noqa: E402

import app as admin  # noqa: E402

PASSWORD = "Nuuts123"
PASSWORD_HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF токен олдсонгүй"
    return match.group(1)


class BaseCase(unittest.TestCase):
    def setUp(self):
        admin.app.config["TESTING"] = True
        admin._failed_logins.clear()
        self.client = admin.app.test_client()
        self.patches = {
            name: mock.patch.object(admin, name)
            for name in ("supabase_get", "supabase_count", "supabase_patch", "supabase_post", "supabase_delete")
        }
        self.mocks = {name: p.start() for name, p in self.patches.items()}
        self.mocks["supabase_get"].return_value = []
        self.mocks["supabase_count"].return_value = 0

    def tearDown(self):
        for p in self.patches.values():
            p.stop()

    def login(self):
        with self.client.session_transaction() as sess:
            sess["user_email"] = "staff@example.com"
            sess["csrf_token"] = "tok"
        return "tok"


class AuthTests(BaseCase):
    def test_protected_pages_redirect_when_logged_out(self):
        for path in ("/dashboard", "/content", "/bookings", "/chat", "/sales", "/rentals", "/profile", "/facebook"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/"), path)

    def test_protected_actions_rejected_when_logged_out(self):
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "tok"
        response = self.client.post("/messages/1/delete", data={"csrf_token": "tok", "confirm": "yes"})
        self.assertEqual(response.status_code, 302)
        self.mocks["supabase_delete"].assert_not_called()

    def test_post_without_csrf_is_rejected(self):
        self.login()
        response = self.client.post("/bookings/1/status", data={"status": "approved"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Хуудасны хугацаа дууссан", response.get_data(as_text=True))
        self.mocks["supabase_patch"].assert_not_called()

    def test_login_success(self):
        page = self.client.get("/").get_data(as_text=True)
        self.mocks["supabase_get"].return_value = [{"email": "staff@example.com", "password_hash": PASSWORD_HASH}]
        response = self.client.post(
            "/login", data={"csrf_token": csrf_from(page), "email": "Staff@Example.com ", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))
        query = self.mocks["supabase_get"].call_args.args[1]
        self.assertEqual(query["email"], "eq.staff@example.com")

    def test_login_accepts_php_style_2y_hash(self):
        page = self.client.get("/").get_data(as_text=True)
        hash_2y = PASSWORD_HASH.replace("$2b$", "$2y$", 1)
        self.mocks["supabase_get"].return_value = [{"email": "a@b.mn", "password_hash": hash_2y}]
        response = self.client.post("/login", data={"csrf_token": csrf_from(page), "email": "a@b.mn", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)

    def test_login_wrong_password_and_unknown_user_same_message(self):
        page = self.client.get("/").get_data(as_text=True)
        token = csrf_from(page)
        self.mocks["supabase_get"].return_value = [{"email": "a@b.mn", "password_hash": PASSWORD_HASH}]
        wrong = self.client.post("/login", data={"csrf_token": token, "email": "a@b.mn", "password": "buruu"})
        self.mocks["supabase_get"].return_value = []
        unknown = self.client.post("/login", data={"csrf_token": token, "email": "x@b.mn", "password": "buruu"})
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertIn("И-мэйл эсвэл нууц үг буруу байна.", wrong.get_data(as_text=True))
        self.assertIn("И-мэйл эсвэл нууц үг буруу байна.", unknown.get_data(as_text=True))

    def test_login_lockout_after_repeated_failures(self):
        token = csrf_from(self.client.get("/").get_data(as_text=True))
        self.mocks["supabase_get"].return_value = []
        for _ in range(admin.LOGIN_MAX_FAILURES):
            self.client.post("/login", data={"csrf_token": token, "email": "a@b.mn", "password": "x"})
        response = self.client.post("/login", data={"csrf_token": token, "email": "a@b.mn", "password": "x"})
        self.assertEqual(response.status_code, 429)

    def test_login_db_error_does_not_leak_config(self):
        token = csrf_from(self.client.get("/").get_data(as_text=True))
        self.mocks["supabase_get"].side_effect = admin.SupabaseError(401)
        response = self.client.post("/login", data={"csrf_token": token, "email": "a@b.mn", "password": "x"})
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("SUPABASE", body)
        self.assertNotIn(".env", body)

    def test_logout_clears_session(self):
        token = self.login()
        response = self.client.post("/logout", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)


class PasswordTests(BaseCase):
    def post(self, current, new, confirm):
        token = self.login()
        return self.client.post(
            "/profile/password",
            data={"csrf_token": token, "current_password": current, "new_password": new, "confirm_password": confirm},
        )

    def test_rules_enforced(self):
        for new in ("short1", "abcdefgh", "12345678", "a1" * 40):
            response = self.post(PASSWORD, new, new)
            self.assertEqual(response.status_code, 400, new)
        self.mocks["supabase_patch"].assert_not_called()

    def test_mismatch_and_same_password(self):
        self.assertEqual(self.post(PASSWORD, "Shine1234", "Shine12345").status_code, 400)
        self.assertEqual(self.post(PASSWORD, PASSWORD, PASSWORD).status_code, 400)

    def test_wrong_current_password(self):
        self.mocks["supabase_get"].return_value = [{"password_hash": PASSWORD_HASH}]
        response = self.post("Buruu1234", "Shine1234", "Shine1234")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Одоогийн нууц үг буруу", response.get_data(as_text=True))
        self.mocks["supabase_patch"].assert_not_called()

    def test_success_stores_bcrypt_hash(self):
        self.mocks["supabase_get"].return_value = [{"password_hash": PASSWORD_HASH}]
        self.mocks["supabase_patch"].return_value = [{"email": "staff@example.com"}]
        response = self.post(PASSWORD, "Shine1234", "Shine1234")
        self.assertEqual(response.status_code, 302)
        stored = self.mocks["supabase_patch"].call_args.args[2]["password_hash"]
        self.assertTrue(bcrypt.checkpw(b"Shine1234", stored.encode()))


class PropertyTests(BaseCase):
    VALID = {"title": "Шинэ байр", "location": "Хан-Уул", "price": "185 000 000", "area_sqm": "68,5", "bedrooms": "3", "description": "Тайлбар"}

    def test_validation_normalises_values(self):
        values = admin.property_values(self.VALID)
        self.assertEqual(values["price"], 185000000)
        self.assertEqual(values["area_sqm"], 68.5)
        self.assertEqual(values["bedrooms"], 3)

    def test_validation_rejects_bad_values(self):
        bad_cases = [
            {"title": ""},
            {"title": "ab"},
            {"location": ""},
            {"price": "0"},
            {"price": "-5"},
            {"price": "1e9"},
            {"price": str(admin.PRICE_MAX + 1)},
            {"area_sqm": "0"},
            {"area_sqm": "nan"},
            {"area_sqm": "inf"},
            {"area_sqm": "100000000"},
            {"bedrooms": "31"},
            {"bedrooms": "-1"},
            {"bedrooms": "2.5"},
            {"description": "x" * 5001},
        ]
        for override in bad_cases:
            with self.assertRaises(admin.PropertyValidationError, msg=override):
                admin.property_values({**self.VALID, **override})

    def test_invalid_create_keeps_submitted_values(self):
        token = self.login()
        response = self.client.post("/properties/sales/new", data={**self.VALID, "price": "abc", "csrf_token": token})
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 400)
        self.assertIn('value="Шинэ байр"', body)
        self.assertIn("property-create\" open", body)
        self.mocks["supabase_post"].assert_not_called()

    def test_create_success(self):
        token = self.login()
        self.mocks["supabase_post"].return_value = [{"id": 1}]
        response = self.client.post("/properties/rentals/new", data={**self.VALID, "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.mocks["supabase_post"].call_args.args[0], "properties_for_rent")

    def test_duplicate_shows_clear_error(self):
        token = self.login()
        self.mocks["supabase_post"].side_effect = admin.SupabaseError(409, "23505")
        response = self.client.post("/properties/sales/new", data={**self.VALID, "csrf_token": token})
        self.assertEqual(response.status_code, 409)
        self.assertIn("аль хэдийн бүртгэлтэй", response.get_data(as_text=True))

    def test_unknown_section_404(self):
        token = self.login()
        response = self.client.post("/properties/hack/new", data={**self.VALID, "csrf_token": token})
        self.assertEqual(response.status_code, 404)

    def test_delete_requires_confirmation(self):
        token = self.login()
        response = self.client.post("/properties/sales/5/delete", data={"csrf_token": token})
        self.assertEqual(response.status_code, 400)
        self.mocks["supabase_delete"].assert_not_called()
        self.mocks["supabase_delete"].return_value = [{"id": 5}]
        response = self.client.post("/properties/sales/5/delete", data={"csrf_token": token, "confirm": "yes"})
        self.assertEqual(response.status_code, 302)

    def test_search_filters_and_escapes(self):
        self.login()
        self.mocks["supabase_get"].return_value = [
            {"id": 1, "title": "<script>alert(1)</script> Зайсан", "location": "Хан-Уул", "price": 1, "area_sqm": 50, "bedrooms": 2, "description": ""},
            {"id": 2, "title": "Төв", "location": "Сүхбаатар", "price": 1, "area_sqm": 50, "bedrooms": 2, "description": ""},
        ]
        body = self.client.get("/sales?q=зайсан").get_data(as_text=True)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>alert", body)
        self.assertNotIn("Сүхбаатар", body)


class BookingAndMessageTests(BaseCase):
    def test_booking_decision_only_targets_pending(self):
        token = self.login()
        self.mocks["supabase_patch"].return_value = [{"id": 1}]
        response = self.client.post("/bookings/1/status", data={"csrf_token": token, "status": "approved"})
        self.assertEqual(response.status_code, 302)
        table, query, values = self.mocks["supabase_patch"].call_args.args
        self.assertEqual(table, "bookings")
        self.assertEqual(query["status"], "eq.pending")
        self.assertEqual(values, {"status": "approved"})

    def test_decided_booking_cannot_change(self):
        token = self.login()
        self.mocks["supabase_patch"].return_value = []
        response = self.client.post("/bookings/1/status", data={"csrf_token": token, "status": "rejected"})
        self.assertEqual(response.status_code, 409)

    def test_invalid_booking_status(self):
        token = self.login()
        response = self.client.post("/bookings/1/status", data={"csrf_token": token, "status": "pending"})
        self.assertEqual(response.status_code, 400)

    def test_message_status_and_delete(self):
        token = self.login()
        self.mocks["supabase_patch"].return_value = [{"id": 3}]
        self.client.post("/messages/3/status", data={"csrf_token": token, "status": "read"})
        self.assertEqual(self.mocks["supabase_patch"].call_args.args[1]["status"], "eq.unread")
        self.assertEqual(
            self.client.post("/messages/3/status", data={"csrf_token": token, "status": "unread"}).status_code, 400
        )
        self.assertEqual(self.client.post("/messages/3/delete", data={"csrf_token": token}).status_code, 400)
        self.mocks["supabase_delete"].assert_not_called()

    def test_messages_ordered_and_filtered(self):
        self.login()
        self.client.get("/chat?status=unread")
        query = self.mocks["supabase_get"].call_args.args[1]
        self.assertEqual(query["order"], "created_at.desc")
        self.assertEqual(query["status"], "eq.unread")
        self.client.get("/chat?status=evil")
        self.assertNotIn("status", self.mocks["supabase_get"].call_args.args[1])


class PageTests(BaseCase):
    def test_dashboard_counts_and_headers(self):
        self.login()
        self.mocks["supabase_count"].side_effect = [3, 4, 5, 6, 2]
        self.mocks["supabase_get"].return_value = [{"status": "pending"}, {"status": "approved"}]
        response = self.client.get("/dashboard")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Уншаагүй зурвас", body)
        self.assertIn("Хүлээгдэж буй", body)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_dashboard_reports_partial_failure(self):
        self.login()
        self.mocks["supabase_count"].side_effect = admin.SupabaseError(404, "PGRST205")
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("уншиж чадсангүй", response.get_data(as_text=True))

    def test_list_failure_shows_error(self):
        self.login()
        self.mocks["supabase_get"].side_effect = admin.SupabaseError(code="network")
        response = self.client.get("/bookings")
        self.assertEqual(response.status_code, 503)
        self.assertIn("холбогдож чадсангүй", response.get_data(as_text=True))

    def test_all_pages_render(self):
        self.login()
        for path in ("/content", "/bookings", "/chat", "/sales", "/rentals", "/profile", "/facebook"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
        self.assertIn("Хэрэгжээгүй", self.client.get("/facebook").get_data(as_text=True))

    def test_404_page_mongolian(self):
        response = self.client.get("/baihgui")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Хуудас олдсонгүй", response.get_data(as_text=True))

    def test_secret_key_never_rendered(self):
        with mock.patch.object(admin, "SUPABASE_SECRET_KEY", "sb_secret_TESTVALUE"):
            self.login()
            for path in ("/dashboard", "/sales", "/chat", "/profile"):
                self.assertNotIn("sb_secret_TESTVALUE", self.client.get(path).get_data(as_text=True))


class SupabaseClientTests(unittest.TestCase):
    def test_authorization_header_uses_real_key(self):
        captured = {}

        class FakeResponse:
            headers = {"Content-Range": "0-0/7"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"[]"

        def fake_urlopen(req, **_kwargs):
            captured["auth"] = req.get_header("Authorization")
            captured["apikey"] = req.get_header("Apikey")
            captured["method"] = req.get_method()
            return FakeResponse()

        with mock.patch.object(admin, "SUPABASE_URL", "https://example.supabase.co"), \
             mock.patch.object(admin, "SUPABASE_SECRET_KEY", "k123"), \
             mock.patch.object(admin, "urlopen", fake_urlopen):
            admin.supabase_patch("bookings", {"id": "eq.1"}, {"status": "approved"})
            self.assertEqual(captured["auth"], "Bearer k123")
            self.assertEqual(captured["apikey"], "k123")
            self.assertEqual(captured["method"], "PATCH")
            self.assertEqual(admin.supabase_count("bookings"), 7)
            self.assertEqual(captured["method"], "HEAD")

    def test_missing_config_raises(self):
        with mock.patch.object(admin, "SUPABASE_URL", ""):
            with self.assertRaises(admin.SupabaseError):
                admin.supabase_get("users", {})


if __name__ == "__main__":
    unittest.main()
