import secrets
import string
from math import log2, floor
from zxcvbn import zxcvbn
from tkinter import Menu
from customtkinter import (
    CTk,
    CTkFrame,
    CTkEntry,
    CTkCheckBox,
    CTkLabel,
    CTkButton,
    CTkInputDialog
)

from dialogs import PasswordDialog, MessageBox
from passwords import PasswordVault


class App(CTk):
    def __init__(self):
        super().__init__()

        self.vault = PasswordVault()

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.title("Password Generator")
        self.geometry("500x220")
        self.resizable(True, False)

        self.menu_bar = Menu(self)

        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Make New Vault", command=self._make_new_vault)
        self.file_menu.add_command(label="Save Current Password", command=self._save_current_password)
        self.file_menu.add_command(label="Load Passwords", command=self._load_saved_passwords)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit Application", command=self.quit)

        self.menu_bar.add_cascade(label="File", menu=self.file_menu)

        # Password Length (Min and Max), Hardcoded, of course!
        self.min_value: int = 14
        self.max_value: int = 64
        # The Amount the Entry goes up and down by
        self.step: int = 1

        self.length_frame = CTkFrame(self)
        self.length_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(15, 5), sticky="ew")
        self.length_frame.grid_columnconfigure(1, weight=1)

        CTkLabel(master=self.length_frame, text="Password Length (14 - 64)", height=14).grid(
            row=0, column=0, padx=(10, 10), sticky="w"
        )

        validate_cmd: str = self.register(self._validate)
        self.length_entry = CTkEntry(master=self.length_frame,
                                     validate="key",
                                     validatecommand=(validate_cmd, "%P"))
        self.length_entry.grid(row=0, column=1, padx=(0, 5), pady=(5, 5), sticky="ew")
        self._set_entry(self.min_value)

        self.length_entry.bind("<Up>", lambda e: self._increase())
        self.length_entry.bind("<Down>", lambda e: self._decrease())
        self.length_entry.bind("<MouseWheel>", self._on_mousewheel)

        self.checkboxes = CTkFrame(master=self)
        self.checkboxes.grid(row=1, column=0, padx=(20, 10), pady=10, sticky="nsew")

        self.uppercase = CTkCheckBox(master=self.checkboxes,
                                     text="Include Uppercase",
                                     onvalue=1, offvalue=0)
        self.uppercase.grid(row=0, column=0, padx=(10, 0), pady=(5, 5), sticky="w")

        self.numbers = CTkCheckBox(master=self.checkboxes,
                                   text="Include Numbers",
                                   onvalue=1, offvalue=0)
        self.numbers.grid(row=1, column=0, padx=(10, 0), pady=(0, 5), sticky="w")

        self.symbols = CTkCheckBox(master=self.checkboxes,
                                   text="Include Symbols",
                                   onvalue=1, offvalue=0)
        self.symbols.grid(row=2, column=0, padx=(10, 0), pady=(0, 5), sticky="w")

        self.results_frame = CTkFrame(master=self)
        self.results_frame.grid(row=1, column=1, padx=(10, 20), pady=10, sticky="nsew")
        self.results_frame.grid_columnconfigure(0, weight=1)

        self.password = CTkEntry(master=self.results_frame, placeholder_text="Generated Password")
        self.password.grid(row=0, column=0, padx=(5, 5), pady=(5, 2), sticky="ew")

        self.entropy = CTkLabel(master=self.results_frame, text="Entropy: 0 bits")
        self.entropy.grid(row=1, column=0, padx=(5, 0), pady=(0, 2), sticky="w")

        self.zxcvbn_score = CTkLabel(master=self.results_frame, text="Zxcvbn Score: ")
        self.zxcvbn_score.grid(row=2, column=0, padx=(5, 0), pady=(0, 2), sticky="w")

        CTkButton(master=self,
                  text="Generate",
                  command=self._generate_password
        ).grid(row=2, column=0, columnspan=2, pady=(5, 15))

        self.config(menu=self.menu_bar)

    # Password Length Entry Logic
    @staticmethod
    def _validate(new_value: str | int) -> bool:
        if new_value == "":
            return True
        return new_value.isdigit()

    def _increase(self) -> None:
        value = self._get_entry()
        value = min(value + self.step, self.max_value)
        self._set_entry(value)

    def _decrease(self) -> None:
        value = self._get_entry()
        value = max(value - self.step, self.min_value)
        self._set_entry(value)

    def _on_mousewheel(self, event) -> None:
        if event.delta > 0:
            self._increase()
        else:
            self._decrease()

    def _get_entry(self) -> int:
        value = self.length_entry.get()
        return int(value) if value else self.min_value

    def _set_entry(self, value) -> None:
        value = max(self.min_value, min(self.max_value, int(value)))
        self.length_entry.delete(0, "end")
        self.length_entry.insert(0, str(value))

    # Entropy Score
    @staticmethod
    def _entropy_score(password_length: int, characters: str) -> str:
        if not characters:
            raise ValueError("Characters cannot be empty")

        entropy = floor(password_length * log2(len(characters)))

        if entropy < 40:
            strength = "Weak"
        elif entropy < 60:
            strength = "Decent"
        elif entropy < 80:
            strength = "Strong"
        elif entropy < 100:
            strength = "Very Strong"
        else:
            strength = "Extremely Strong"

        return f"{entropy} bits - {strength}"

    # zxcvbn Score
    @staticmethod
    def _zxcvbn_score(score: int) -> str:
        match score:
            case 0: return f"{score} - Terrible"
            case 1: return f"{score} - Very Weak"
            case 2: return f"{score} - Weak"
            case 3: return f"{score} - Good"
            case 4: return f"{score} - Very Strong"
            case _: return f"Unknown"

    # Password Logic
    def _generate_password(self) -> None:
        password_length: int = self._get_entry()
        characters: str = string.ascii_lowercase

        include_caps:    bool = True if self.uppercase.get() == 1 else False
        include_digits:  bool = True if self.numbers.get() == 1 else False
        include_symbols: bool = True if self.symbols.get() == 1 else False

        if include_caps:
            characters += string.ascii_uppercase

        if include_digits:
            characters += string.digits

        if include_symbols:
            characters += string.punctuation

        password: str = ''.join(secrets.choice(characters) for _ in range(password_length))
        self.password.delete(0, "end")
        self.password.insert(0, password)

        self.entropy.configure(text=f"Entropy: {self._entropy_score(password_length, characters)}")

        zxcvbn_results = zxcvbn(password)
        self.zxcvbn_score.configure(text=f"Zxcvbn Score: {self._zxcvbn_score(zxcvbn_results['score'])}")

    # Vault Logic
    def _make_new_vault(self) -> None:
        dialog = CTkInputDialog(title="New Vault Name", text="Enter new vault name or 'n' for default vault")
        vault_name = dialog.get_input()

        dialog = PasswordDialog(title="New Vault Password", text="Enter new vault password")
        master_password = dialog.get_input()
        if vault_name == "n":
            self.vault.create_vault(master_password)
        else:
            vault_name = vault_name + ".dat" if not vault_name.endswith(".dat") else vault_name

            self.vault = PasswordVault(file_path=vault_name, remake_loc=True)
            self.vault.create_vault(master_password)


    def _save_current_password(self) -> None:
        current_password = self.password.get()

        if not current_password:
            return

        dialog = CTkInputDialog(title="Website", text="Enter the website for this password")
        website = dialog.get_input()

        dialog = PasswordDialog(title="Password", text="Enter Master Password")
        master_password = dialog.get_input()

        try:
            self.vault.add_password(master_password, website, current_password)
            self.password.delete(0, "end")
        except Exception as e:
            MessageBox(master=self, title="Error", message=f"{e}", icon="warning")

    def _load_saved_passwords(self) -> None:
        dialog = PasswordDialog(title="Password", text="Enter Master Password")
        master_password = dialog.get_input()

        passwords: dict = self.vault.load_vault(master_password)
        # TODO: Make something decent
        print(passwords.keys())