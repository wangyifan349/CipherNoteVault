# 🔐 CipherNote Vault

**CipherNote Vault** is a local encrypted password manager and secure notes app built with Python and PyQt6. It is designed for people who want an offline vault for passwords and important daily notes without depending on a cloud service.

## ✨ What it does

CipherNote Vault combines a focused password manager with a practical secure notebook. Password entries use only the fields that matter: **title, username, password, and notes**. Secure notes are useful for private daily writing, recovery information, server notes, personal records, or any text that should not be stored in plaintext.

## 🌍 Language versions

This release includes five UI entry points:

```text
CipherNoteVault_en.py  English
CipherNoteVault_zh.py  Chinese
CipherNoteVault_ja.py  Japanese
CipherNoteVault_ko.py  Korean
CipherNoteVault_es.py  Spanish
```

All language versions use the same `.cnvault` database format and the same cryptographic design.

## 🔎 Workflow

Create a new `.cnvault` database or open an existing one from any location. The main search box searches password titles, usernames, password notes, note titles, and note content. Lists use stable title-first sorting.

Right-click blank space to add a password or note. Right-click an existing item to edit or delete it. Notes preview on single click and open for editing on double click.

## 🗒️ Notes editor

The note editor is made for real daily use:

* Large resizable window
* Clean and uncluttered body area
* Font-size slider
* `Ctrl+S` saves without closing the editor
* Single-click preview
* Double-click editing

## 🔑 Password tools

The password generator supports:

* Password length
* Letters and numbers
* Mixed case
* Symbols

Copied passwords are automatically cleared from the clipboard after 30 seconds.

## 🛡️ Security design

CipherNote Vault uses **Argon2id** to derive a 256-bit key from the master password and **ChaCha20-Poly1305** to authenticated-encrypt the entire database payload.

The database file does **not** store:

* Master password
* Plaintext passwords
* Plaintext notes
* Recovery backdoors

The database file stores only metadata such as format version, cipher name, KDF parameters, salt, nonce, and ciphertext.

Default Argon2id parameters:

```text
iterations = 4
lanes      = 4
memory     = 262144 KiB
key length = 32 bytes
```

This uses about **256 MiB of memory** during key derivation to increase the cost of offline brute-force attacks. Every save uses a fresh random 96-bit nonce for ChaCha20-Poly1305 and writes via a temporary file followed by atomic replacement.

## 🖥️ Windows screen-capture protection

On Windows, CipherNote Vault attempts to call `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE`. This can reduce ordinary PrintScreen, Win+Shift+S, screenshot tools, and common screen recording of the app window.

If unsupported, it attempts to fall back to `WDA_MONITOR_ONLY`.

This is **not** a perfect anti-capture guarantee. It cannot stop phone photography, administrator-level tools, malware, GPU hooks, keyloggers, clipboard monitoring, or memory dumps.

## 🎨 Eye-friendly UI

CipherNote Vault uses a warm, eye-friendly desktop interface with a red and gold visual style. The UI is designed to keep the workspace clean, reduce unnecessary visual noise, and leave more room for passwords and notes.

Native OS title bars, file dialogs, and message-box frames may still be drawn by the operating system theme.

## ⚡ Quick start

### Linux / macOS

```bash
git clone https://github.com/wangyifan349/CipherNoteVault.git
cd CipherNoteVault
python3 -m pip install --upgrade pip
python3 -m pip install PyQt6 "cryptography>=44.0.0"
python3 CipherNoteVault_en.py
```

### Windows

Using Python Launcher:

```powershell
git clone https://github.com/wangyifan349/CipherNoteVault.git
cd CipherNoteVault
py -3 -m pip install --upgrade pip
py -3 -m pip install PyQt6 "cryptography>=44.0.0"
py -3 CipherNoteVault_en.py
```

## ▶️ Run another language version

Replace `CipherNoteVault_en.py` with one of the following files:

```text
CipherNoteVault_en.py  English
CipherNoteVault_zh.py  Chinese
CipherNoteVault_ja.py  Japanese
CipherNoteVault_ko.py  Korean
CipherNoteVault_es.py  Spanish
```

## 📦 Build executable

For a standalone executable, package the language file you want with PyInstaller.

### Linux / macOS

```bash
python3 -m pip install pyinstaller
pyinstaller -f -w CipherNoteVault_en.py
```

### Windows

```powershell
py -3 -m pip install pyinstaller
py -3 -m PyInstaller -f -w CipherNoteVault_en.py
```

To build another language version, replace `CipherNoteVault_en.py` with one of the other language files.

Always test the generated executable on the target operating system before distribution.

## 🗃️ Database files

Default path:

```text
~/.ciphernote_vault/vault.cnvault
```

You can choose any path from the startup window.

If the master password is forgotten, the database cannot be recovered because CipherNote Vault does not store the master password and has no recovery backdoor.

## ⚠️ Security boundary

CipherNote Vault protects data at rest and reduces some ordinary screen-capture risks on Windows. It cannot defend against:

* A compromised operating system
* Malware already running on the machine
* Phone photography
* Privileged capture tools
* Keyloggers
* Clipboard monitors
* Memory-dump attacks

Use a strong unique master password and understand the security boundary of your device and operating system.

## 💾 Backup recommendations

CipherNote Vault stores all passwords and notes inside an encrypted `.cnvault` database file. To help prevent data loss, it is strongly recommended to maintain regular backups of your database.

* 📂 Back up your `.cnvault` database file regularly, especially after adding or modifying important information.
* 🧩 Keep multiple backup copies instead of relying on a single file.
* 🌍 Store backups in different locations whenever possible to reduce the risk of a single point of failure.
* 🕒 Consider using dated filenames, such as `vault-2026-06-04.cnvault`, so older versions can be identified and restored if needed.
* 🔐 Keep your master password in a safe place. Without the correct master password, the encrypted database cannot be recovered.
* ✅ Periodically verify that your backup files can still be opened successfully with the correct master password.
* 🚫 Do not rely solely on the default database location. Device failure, accidental deletion, theft, hardware damage, or operating system reinstallation may result in permanent data loss.

### 🌍 Multi-location backup strategy

Good backup habits are not only important for CipherNote Vault, but also for any valuable digital data.

Consider maintaining multiple copies of important files in different locations. A simple multi-location backup strategy can significantly reduce the risk of data loss caused by hardware failure, accidental deletion, theft, fire, flooding, or other unexpected events.

❤️ A backup only becomes valuable when it is available after something goes wrong. Please make sure both your `.cnvault` database file and your master password are stored safely and can be recovered when needed.

## ❤️ Sponsorship

If CipherNote Vault is useful to you, sponsorship is welcome and greatly appreciated.

Your support helps encourage continued development, maintenance, and improvement of the project.

### ₿ Bitcoin

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

### Ξ Ethereum

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

### ◈ BNB Smart Chain (BEP20)

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

❤️ Thank you for supporting open-source software.

## 📄 License

🔓 **CipherNote Vault** and all files contained in this repository are licensed under the **GNU Affero General Public License v3.0 only (AGPL-3.0-only)**, unless explicitly stated otherwise.

You are free to:

* Use
* Study
* Modify
* Redistribute

this software under the terms of the GNU AGPLv3 license.

Any distributed derivative work must also comply with the GNU AGPLv3 license.

If you modify this software and make it available for use over a network, you must also make the corresponding source code available to users interacting with it remotely, as required by the GNU AGPLv3 license.

SPDX identifier:

```text
SPDX-License-Identifier: AGPL-3.0-only
```


## 🙏 Feedback and contributions

Thank you for using CipherNote Vault.

If you find a bug, notice inaccurate documentation, have a security concern, or want to suggest an improvement, please open an issue on GitHub.

Pull requests are also welcome. Your feedback helps make this project better.
