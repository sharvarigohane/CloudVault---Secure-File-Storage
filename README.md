# CloudVault – Secure File Storage

A multi-user cloud file manager built with Python and Flask. Users sign up, log in, and upload, search, download, and delete their own files, with access control that keeps one user from ever touching another user's data.

File storage sits behind a pluggable interface, so the app can use local disk or Azure Blob Storage without any application code changes.

<!-- Add 2-3 screenshots here (login, file list, upload) -->
<!-- ![CloudVault file list](screenshots/files.png) -->

## Features

- User accounts with signup, login, and logout
- Upload, list, search by filename, download, and delete files
- **Owner-scoped access control:** users can only see and modify their own files
- Passwords and security answers stored as salted scrypt hashes, never in plaintext
- Password reset without an email service, using a hashed security question
- SHA-256 content hash and size recorded for every upload
- Pluggable storage layer: local disk or Azure Blob Storage
- In-page modals and toasts instead of browser `alert()` and `confirm()` dialogs

## Architecture

```
Browser / curl
      │
      ▼
Flask app (app.py)
      │
      ├── SQLite → users table, files table (owner_id foreign key)
      └── storage_backend/ → one interface: put / get / delete / exists
             ├── LocalStorage       (disk, used for development and testing)
             └── AzureBlobStorage   (Azure Blob REST API with Shared Key signing)
```

`app.py` only ever calls the storage interface. Switching from local disk to Azure Blob Storage is a matter of setting environment variables.

**Note on Azure:** `AzureBlobStorage` is written directly against Microsoft's Blob REST API (Shared Key request signing with PUT, GET, DELETE, and HEAD). It has not been run against a live Azure Storage account. All testing below ran against `LocalStorage`. Validate the Azure path against a real storage account before relying on it.

## Access Control Model

- Every file route is wrapped in a `@login_required` decorator, so requests without a valid session get a 401 before any file logic runs.
- Every file query is scoped with `WHERE owner_id = ?`. Ownership is enforced in the database query itself, not by trusting anything the client sends.
- A request for a file that belongs to someone else returns the **same 404** as a file that doesn't exist, so a file ID can't be probed to learn whether it exists.
- Passwords are salted and hashed with `werkzeug.security` (scrypt) before they reach the database.

## Password Reset Without Email

At signup, the user sets a security question and answer. The answer is normalized (lowercased) and stored hashed, like a password. To reset a password, the user answers the question correctly and then sets a new one. This is a practical alternative to email reset links when no email service is configured.

## What Was Tested

Tested against `LocalStorage` and a real SQLite database:

- Two separate users signed up
- Uploading while logged out returned 401
- User A uploaded a file, listed it, and searched for it by filename
- **User B, in a separate logged-in session, tried to download and delete User A's file. Both returned 404, and User A's file was still intact and downloadable.**
- A wrong password on login returned 401
- After logout, the file list returned 401
- The SQLite file showed passwords stored as salted scrypt hashes, with each file row's `owner_id` matching the uploader
- The full password reset flow worked: a wrong answer was rejected, a correct answer with different capitalization was accepted, the old password stopped working, and the new one worked

## Getting Started

```bash
git clone https://github.com/sharvarigohane/cloudvault.git
cd cloudvault
pip install -r requirements.txt
python app.py
```

Open <http://localhost:5001>, sign up, and start uploading files.

Set a real secret key for anything beyond local use:

```bash
export SECRET_KEY="your-long-random-string"
```

### Using Azure Blob Storage

```bash
export AZURE_STORAGE_ACCOUNT=youraccount
export AZURE_STORAGE_KEY=yourkey
export AZURE_CONTAINER=cloudvault
python app.py
```

## API Reference

| Method | Path | Auth | Purpose |
|--------|------|:---:|---------|
| POST | `/api/signup` | No | Create an account with a security question |
| POST | `/api/login` | No | Log in and start a session |
| POST | `/api/logout` | Yes | End the session |
| GET | `/api/whoami` | No | Check current login state |
| GET | `/api/security-question` | No | Get an account's reset question |
| POST | `/api/reset-password` | No | Verify the answer and set a new password |
| GET | `/api/files` | Yes | List your files |
| GET | `/api/files/search?q=` | Yes | Search your files by name |
| POST | `/api/files` | Yes | Upload a file (multipart form) |
| GET | `/api/files/<id>` | Yes | Download a file you own |
| DELETE | `/api/files/<id>` | Yes | Delete a file you own |

## Project Structure

```
├── app.py                  # Flask app: auth, routes, access control
├── storage_backend/
│   ├── __init__.py
│   └── backend.py          # Storage interface, LocalStorage, AzureBlobStorage
├── templates/
│   └── index.html          # Single-page UI
├── requirements.txt
└── README.md
```

The SQLite database (`cloudvault.db`) and the `data/` folder are created on first run.

## Limitations

- The Azure Blob backend hasn't been tested against a live storage account.
- The app runs Flask's development server with `debug=True`. Use a production server such as Gunicorn, and turn debug off, before deploying.
- The security-question lookup reveals whether a username exists. A production app would use an email reset link as well.

## Tech Stack

Python · Flask · SQLite · Azure Blob Storage (REST) · Werkzeug (scrypt) · HTML, CSS, JavaScript
