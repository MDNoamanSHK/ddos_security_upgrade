"""Create a local .env file with strong dashboard credentials."""
from pathlib import Path
import secrets
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
env_path = BASE_DIR / ".env"

if env_path.exists():
    print(f"{env_path} already exists. It was not overwritten.")
    print("If you need to reset the admin password, edit .env and replace ADMIN_PASSWORD_HASH.")
else:
    username = "admin"
    password = secrets.token_urlsafe(15)
    secret_key = secrets.token_urlsafe(48)
    password_hash = generate_password_hash(password)
    content = (
        "# Keep this file private. Do not commit it or share it.\n"
        f"SECRET_KEY={secret_key}\n"
        f"ADMIN_USERNAME={username}\n"
        f"ADMIN_PASSWORD_HASH={password_hash}\n"
        "COOKIE_SECURE=false\n"
        "RATELIMIT_STORAGE_URI=memory://\n"
    )
    env_path.write_text(content, encoding="utf-8")
    print("\nSECURITY SETUP COMPLETE")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print("\nSave this password in a password manager. It is shown only this time.")
    print("Do not upload or share your .env file.")
