import os
import unittest
from unittest.mock import patch


class PasswordResetWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/cybervantage_test.db")

        from config.app_config import create_app, db
        from routes.auth_routes import auth_bp

        cls.db = db
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.register_blueprint(auth_bp)

        # base.html references these endpoints
        cls.app.add_url_rule("/", endpoint="index", view_func=lambda: "OK")
        cls.app.add_url_rule("/about", endpoint="about", view_func=lambda: "OK")
        cls.app.add_url_rule("/dashboard", endpoint="dashboard", view_func=lambda: "OK")

        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.client = self.app.test_client()

        from models.database import User

        with self.app.app_context():
            # Keep tests deterministic / isolated
            self.db.session.query(User).delete()
            self.db.session.commit()

            user = User(name="Reset Test", email="resettest@gmail.com")
            user.set_password("Password1")
            self.db.session.add(user)
            self.db.session.commit()

    @patch("routes.auth_routes.send_password_reset_email")
    def test_password_reset_end_to_end(self, send_password_reset_email):
        send_password_reset_email.return_value = {"success": True, "message": "sent"}

        from models.database import User

        # 1) Request reset (email send invoked + token stored)
        resp = self.client.post(
            "/reset_password_request",
            data={"email": "resettest@gmail.com"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)

        with self.app.app_context():
            user = User.query.filter_by(email="resettest@gmail.com").first()
            self.assertIsNotNone(user.password_reset_token)
            token = user.password_reset_token

        send_password_reset_email.assert_called_once()
        self.assertEqual(send_password_reset_email.call_args.args[0], "resettest@gmail.com")
        self.assertEqual(send_password_reset_email.call_args.args[1], token)

        # Legacy link format should redirect properly
        resp = self.client.get(f"/reset-password?token={token}", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn(f"/reset_password/{token}".encode(), resp.headers["Location"].encode())

        # 2) Open reset form
        resp = self.client.get(f"/reset_password/{token}")
        self.assertEqual(resp.status_code, 200)

        # 3) Submit new password, token cleared
        resp = self.client.post(
            f"/reset_password/{token}",
            data={"password": "NewPassword1", "confirm_password": "NewPassword1"},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)

        with self.app.app_context():
            user = User.query.filter_by(email="resettest@gmail.com").first()
            self.assertIsNone(user.password_reset_token)
            self.assertTrue(user.check_password("NewPassword1"))

    def test_register_duplicate_email_returns_html_not_json(self):
        resp = self.client.post(
            "/register",
            data={
                "name": "Someone",
                "email": "resettest@gmail.com",
                "password": "Password1",
                "confirm_password": "Password1",
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Email already registered", resp.data)


if __name__ == "__main__":
    unittest.main()
