# 🔐 CipherNote Vault

**CipherNote Vault** is a local encrypted password manager and secure notes app built with Python and PyQt6. It is designed for people who want an offline vault for passwords and important daily notes without depending on a cloud service. Project author: **Wang Yifan**. GitHub: <https://github.com/wangyifan349/>.

## ✨ What it does

CipherNote Vault combines a focused password manager with a practical secure notebook. Password entries use only the fields that matter: **title, username, password, and notes**. Secure notes are useful for private daily writing, recovery information, server notes, personal records, or any text that should not be stored in plaintext.

## 🌍 Language versions

This release includes five UI entry points:

```text
app_en.py  English
app_zh.py  Chinese
app_ja.py  Japanese
app_ko.py  Korean
app_es.py  Spanish
```

All language versions use the same `.cnvault` database format and the same cryptographic design.

## 🔎 Workflow

Create a new `.cnvault` database or open an existing one from any location. The main search box searches password titles, usernames, password notes, note titles, and note content. Lists use stable title-first sorting. Right-click blank space to add a password or note; right-click an existing item to edit or delete it. Notes preview on single click and open for editing on double click.

## 🗒️ Notes editor

The note editor is made for real daily use: a large resizable window, an uncluttered body area, a font-size slider, and `Ctrl+S` saving without closing the editor.

## 🔑 Password tools

The password generator supports password length, letters and numbers, mixed case, and symbols. Copied passwords are automatically cleared from the clipboard after 30 seconds.

## 🛡️ Security design

CipherNote Vault uses **Argon2id** to derive a 256-bit key from the master password and **ChaCha20-Poly1305** to authenticated-encrypt the entire database payload. The database file does not store the master password, plaintext passwords, or plaintext notes. It stores only metadata such as format version, cipher name, KDF parameters, salt, nonce, and ciphertext.

Default Argon2id parameters:

```text
iterations = 4
lanes      = 4
memory     = 262144 KiB
key length = 32 bytes
```

This uses about 256 MiB of memory during key derivation to increase the cost of offline brute-force attacks. Every save uses a fresh random 96-bit nonce for ChaCha20-Poly1305 and writes via a temporary file followed by atomic replacement.

## 🖥️ Windows screen-capture protection

On Windows, CipherNote Vault attempts to call `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE`. This can reduce ordinary PrintScreen, Win+Shift+S, screenshot tools, and common screen recording of the app window. If unsupported, it attempts to fall back to `WDA_MONITOR_ONLY`.

This is not a perfect anti-capture guarantee. It cannot stop phone photography, administrator-level tools, malware, GPU hooks, keyloggers, clipboard monitoring, or memory dumps.

## 🎨 No-blue-channel UI palette

The app-defined QSS colors are designed with a zero blue channel, using red/yellow/black-style `#RRGG00` colors. Emoji icons were removed from the app UI to avoid colored system emoji glyphs introducing blue pixels. Native OS title bars, file dialogs, and message-box frames may still be drawn by the OS theme.

## 🚀 Installation

Install dependencies with one command:

```bash
pip install PyQt6 "cryptography>=44.0.0"
```

## ▶️ Run

```bash
python app_en.py
python app_zh.py
python app_ja.py
python app_ko.py
python app_es.py
```

## 📦 Deployment

For a standalone executable, package the language file you want with PyInstaller:

```bash
pyinstaller --onefile --windowed app_en.py
```

Replace `app_en.py` with `app_zh.py`, `app_ja.py`, `app_ko.py`, or `app_es.py` as needed. Test the generated executable on the target OS.

## 🗃️ Database files

Default path:

```text
~/.ciphernote_vault/vault.cnvault
```

You can choose any path from the startup window. If the master password is forgotten, the database cannot be recovered because CipherNote Vault does not store the master password and has no recovery backdoor.

## ⚠️ Security boundary

CipherNote Vault protects data at rest and reduces some ordinary screen-capture risks on Windows. It cannot defend against a compromised OS, malware already running on the machine, phone photography, privileged capture tools, keyloggers, clipboard monitors, or memory-dump attacks. Use a strong unique master password and consider full-disk encryption such as BitLocker, FileVault, or LUKS.

## ❤️ Sponsorship

If CipherNote Vault is useful to you, donations are welcome.

Bitcoin:

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

Ethereum:

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

BNB Smart Chain:

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

## 📄 License

CipherNote Vault is released under the **GNU General Public License v3.0 only**. Source files include:

```text
SPDX-License-Identifier: GPL-3.0-only
```

For GitHub, choose GNU GPLv3 or add the official GPLv3 text as `LICENSE`.
