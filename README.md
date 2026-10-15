# DDoS Detection ML — Security Upgrade

This is a replacement set for the Flask backend and frontend. It preserves your trained model files:
- `model/ddos_model.joblib`
- `model/model_features.json`

**The package does not include, retrain, rename, or modify either model file.** The app reads the exact feature names from `model/model_features.json` at startup.

## Expected folder layout

Place these files in the root of your existing project, next to your existing `model` folder:

```text
your-project/
├── app.py
├── setup_security.py
├── index.html
├── style.css
├── script.js
├── requirements-security.txt
├── .gitignore
├── model/
│   ├── ddos_model.joblib          # keep your existing file
│   └── model_features.json        # keep your existing file
├── logs/                          # created automatically
└── .env                           # created by setup_security.py
```

If your current project uses `requirements.txt`, merge the packages in `requirements-security.txt` into it, or install with the command below.

## Windows / VS Code steps

1. **Back up your project folder first.** Do not delete the `model` folder.
2. Extract this ZIP. Copy `app.py`, `setup_security.py`, `index.html`, `style.css`, `script.js`, `.gitignore`, and `requirements-security.txt` into the root of your existing project. If Windows asks whether to replace frontend files, choose replace only after making your backup.
3. Open the project folder in VS Code.
4. Open Terminal → New Terminal. Activate your existing virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   If your terminal is Command Prompt instead of PowerShell:
   ```bat
   .venv\Scripts\activate.bat
   ```
5. Install dependencies:
   ```powershell
   python -m pip install -r requirements-security.txt
   ```
6. Generate your local admin login:
   ```powershell
   python setup_security.py
   ```
   Save the username and password printed in the terminal. The password is shown only during first-time setup. This creates `.env`; do not share or upload it.
7. Confirm these two existing files still exist:
   - `model/ddos_model.joblib`
   - `model/model_features.json`
8. Start the app:
   ```powershell
   python app.py
   ```
9. Open `http://127.0.0.1:5000` in your browser and sign in using the generated credentials.

## Included protections

- Admin authentication with Werkzeug password hashing.
- HTTP-only, SameSite session cookie and CSRF token checks for state-changing API requests.
- CSV extension check, 25 MB request/file cap, maximum 100,000 rows, maximum 250 columns, duplicate/blank column checks, numeric validation and finite-value checks.
- Required features are read from the saved `model/model_features.json`. Missing features cause a clear error; the app does not invent features or silently rename columns.
- API rate limits on login, analysis, and evaluation.
- Security headers and a restrictive Content Security Policy.
- Rotating audit log at `logs/security.log`; passwords and uploaded CSV contents are not logged.
- Results export, benign/attack summary, optional model confidence, and model evaluation metrics.

## CSV requirements

### Analyze
The CSV must include **every exact feature name** listed in `model/model_features.json`. Extra columns are allowed, and are ignored for model input. If `src_ip` / `Source IP` and `dst_ip` / `Destination IP` columns exist, they may be displayed as optional context; they are not model features unless the saved feature list says they are.

### Evaluate
The labelled test CSV must contain the same required feature columns and an additional column named `label`. Supported labels are:
- Benign: `BENIGN`, `NORMAL`, `LEGITIMATE`, or `0`
- DDoS/attack: `DDOS`, `DOS`, `ATTACK`, `DDOS/ATTACK`, or `1`

The evaluation endpoint intentionally rejects other labels such as `PORT_SCAN` or `BRUTE_FORCE`, because this dashboard expects a binary model (0=Benign, 1=DDoS/Attack). Do not use the synthetic multi-class dataset for evaluation unless you filter it to the two classes and ensure its features match the model's exact feature schema.

## Important notes

- `python setup_security.py` does not overwrite an existing `.env`. To reset credentials, update the `.env` values deliberately.
- The app binds to `127.0.0.1` by default so it is local-only. Do not expose it to the internet as-is.
- The default rate-limit storage is in-memory and suitable for local testing. It resets when the app restarts and is not shared across multiple worker processes. Use Redis for a deployed multi-worker setup.
- Model evaluation is meaningful only when the labelled test file is representative and separate from training data. A high score on a tiny or synthetic dataset is not proof of real-world detection performance.
- If `model/ddos_model.joblib` was trained with a different label encoding than 0=Benign / 1=DDoS, review the class mapping before using this replacement. The code intentionally fails on unsupported model classes rather than guessing.
