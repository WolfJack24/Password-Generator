import os
import json
import base64
from typing import Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class PasswordVault:
    def __init__(self, file_path: str = "vault.dat", salt_size: int = 16, remake_loc: bool = False) -> None:
        self.file_path = file_path

        if not os.path.exists("./vault.loc") or remake_loc:
            with open("./vault.loc", "w") as f:
                f.write(self.file_path)
        else:
            with open("./vault.loc", "r") as f:
                self.file_path = f.read()

        self.salt_size = salt_size

    # ---------- KEY DERIVATION ----------
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,  # strong default
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))


    # ---------- CREATE VAULT ----------
    def create_vault(self, master_password: str) -> None:
        if os.path.isfile(self.file_path):
            raise FileExistsError("Vault already exists.")

        salt: bytes = os.urandom(self.salt_size)
        key: bytes = self.derive_key(master_password, salt)
        f: Fernet = Fernet(key)

        empty_data: bytes = json.dumps({}).encode()
        encrypted: bytes = f.encrypt(empty_data)

        with open(self.file_path, "wb") as file:
            file.write(salt + encrypted)

        print("Vault created.")


    # ---------- LOAD VAULT ----------
    def load_vault(self, master_password: str) -> dict:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError("Vault does not exist. Create one first.")

        with open(self.file_path, "rb") as file:
            data: bytes = file.read()

        salt: bytes = data[:self.salt_size]
        encrypted: bytes = data[self.salt_size:]

        key: bytes = self.derive_key(master_password, salt)
        f: Fernet = Fernet(key)

        try:
            decrypted: bytes = f.decrypt(encrypted)
        except InvalidToken:
            raise ValueError("Incorrect master password.")

        return json.loads(decrypted.decode())


    # ---------- SAVE VAULT ----------
    def save_vault(self, master_password: str, vault_data: dict) -> None:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError("Vault does not exist. Create one first.")

        with open(self.file_path, "rb") as file:
            data: bytes = file.read()

        salt: bytes = data[:self.salt_size]

        key: bytes = self.derive_key(master_password, salt)
        f: Fernet = Fernet(key)

        encrypted: bytes = f.encrypt(json.dumps(vault_data).encode())

        with open(self.file_path, "wb") as file:
            file.write(salt + encrypted)


    # ---------- ADD PASSWORD ----------
    def add_password(self, master_password: str, site: str, password: str) -> None:
        vault: Any = self.load_vault(master_password)
        vault[site] = password
        self.save_vault(master_password, vault)


    # ---------- GET PASSWORD ----------
    def get_password(self, master_password: str, site: str) -> str:
        vault: dict = self.load_vault(master_password)
        return vault.get(site, "Not found")