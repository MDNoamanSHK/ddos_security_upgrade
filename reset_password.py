from pathlib import Path
from werkzeug.security import generate_password_hash

base_dir = Path(__file__).resolve().parent
env_file = base_dir / ".env"

# Set your own password here (12+ characters).
new_password = "noaman@1345A"

if not env_file.exists():
    print(".env file not found.")
    raise SystemExit(1)

lines = env_file.read_text(encoding="utf-8").splitlines()
new_hash = "ADMIN_PASSWORD_HASH=" + generate_password_hash(new_password)

for i, line in enumerate(lines):
    if line.startswith("ADMIN_PASSWORD_HASH="):
        lines[i] = new_hash
        break
else:
    lines.append(new_hash)

env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("Password reset successfully.")