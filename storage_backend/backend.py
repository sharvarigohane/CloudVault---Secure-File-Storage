"""
Storage backend abstraction.

Two implementations behind one interface:
- LocalStorage: writes to local disk. This is what's actually tested in
  this project (no Azure credentials available in dev).
- AzureBlobStorage: talks to the real Azure Blob Storage REST API using
  Shared Key auth. Written against Microsoft's documented API, but NOT
  exercised against a live Azure account here — validate against a real
  storage account before relying on it in production.

The app only ever calls methods on `Backend` (put/get/delete/exists), so
switching from local disk to Azure is a one-line config change with zero
changes to app.py.
"""

import os
import base64
import hashlib
import hmac
import shutil
from datetime import datetime, timezone
import requests


class Backend:
    def put(self, key: str, data: bytes) -> int:
        raise NotImplementedError

    def get(self, key: str) -> bytes:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError


class LocalStorage(Backend):
    def __init__(self, root="data/blobs"):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def _path(self, key):
        return os.path.join(self.root, key)

    def put(self, key, data: bytes) -> int:
        path = self._path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return len(data)

    def get(self, key) -> bytes:
        with open(self._path(key), "rb") as f:
            return f.read()

    def delete(self, key) -> None:
        path = self._path(key)
        if os.path.exists(path):
            os.remove(path)

    def exists(self, key) -> bool:
        return os.path.exists(self._path(key))


class AzureBlobStorage(Backend):
    """
    Talks directly to the Azure Blob Storage REST API using Shared Key
    signing, rather than pulling in the full azure-storage-blob SDK, to
    keep the dependency footprint small and the auth flow auditable.

    NOTE (honest framing): implemented against Microsoft's documented
    REST API and Shared Key signing scheme, but not run against a live
    Azure Storage account in this environment. Test against a real
    account before using in production.
    """

    def __init__(self, account_name, account_key, container_name):
        self.account_name = account_name
        self.account_key = account_key
        self.container_name = container_name

    def _url(self, key):
        return f"https://{self.account_name}.blob.core.windows.net/{self.container_name}/{key}"

    def _sign(self, method, key, content_length=0, blob_type=None):
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        headers = {"x-ms-date": date, "x-ms-version": "2021-08-06"}
        canon_headers = ""
        if blob_type:
            headers["x-ms-blob-type"] = blob_type
            canon_headers += f"x-ms-blob-type:{blob_type}\n"
        canon_headers += f"x-ms-date:{date}\nx-ms-version:2021-08-06\n"
        canon_resource = f"/{self.account_name}/{self.container_name}/{key}"
        cl = str(content_length) if content_length else ""
        string_to_sign = "\n".join([
            method, "", "", cl, "", "", "", "", "", "", "",
            canon_headers, canon_resource,
        ])
        sig_key = base64.b64decode(self.account_key)
        signature = base64.b64encode(
            hmac.new(sig_key, string_to_sign.encode(), hashlib.sha256).digest()
        ).decode()
        headers["Authorization"] = f"SharedKey {self.account_name}:{signature}"
        return headers

    def put(self, key, data: bytes) -> int:
        headers = self._sign("PUT", key, content_length=len(data), blob_type="BlockBlob")
        resp = requests.put(self._url(key), data=data, headers=headers)
        resp.raise_for_status()
        return len(data)

    def get(self, key) -> bytes:
        headers = self._sign("GET", key)
        resp = requests.get(self._url(key), headers=headers)
        resp.raise_for_status()
        return resp.content

    def delete(self, key) -> None:
        headers = self._sign("DELETE", key)
        resp = requests.delete(self._url(key), headers=headers)
        if resp.status_code not in (200, 202, 404):
            resp.raise_for_status()

    def exists(self, key) -> bool:
        headers = self._sign("HEAD", key)
        resp = requests.head(self._url(key), headers=headers)
        return resp.status_code == 200


def get_backend():
    """Selects Azure if creds are set in the environment, else local disk."""
    account = os.environ.get("AZURE_STORAGE_ACCOUNT")
    if account:
        key = os.environ.get("AZURE_STORAGE_KEY")
        container = os.environ.get("AZURE_CONTAINER", "cloudvault")
        return AzureBlobStorage(account, key, container)
    return LocalStorage()
