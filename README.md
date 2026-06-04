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
python CipherNoteVault_en.py
python CipherNoteVault_zh.py
python CipherNoteVault_ja.py
python CipherNoteVault_ko.py
python CipherNoteVault_es.py
```

## 📦 Deployment

For a standalone executable, package the language file you want with PyInstaller:

```bash
pyinstaller --onefile --windowed CipherNoteVault_en.py
pyinstaller --onefile --windowed CipherNoteVault_es.py
```



## 🗃️ Database files

Default path:

```text
~/.ciphernote_vault/vault.cnvault
```

You can choose any path from the startup window. If the master password is forgotten, the database cannot be recovered because CipherNote Vault does not store the master password and has no recovery backdoor.

## ⚠️ Security boundary

CipherNote Vault protects data at rest and reduces some ordinary screen-capture risks on Windows. It cannot defend against a compromised OS, malware already running on the machine, phone photography, privileged capture tools, keyloggers, clipboard monitors, or memory-dump attacks. Use a strong unique master password and consider full-disk encryption such as BitLocker, FileVault, or LUKS.

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


## 💾 Backup Recommendations

CipherNote Vault stores all passwords and notes inside an encrypted `.cnvault` database file. To help prevent data loss, it is strongly recommended to maintain regular backups of your database.

* 📂 Back up your `.cnvault` database file regularly, especially after adding or modifying important information.
* 🧩 Keep multiple backup copies instead of relying on a single file.
* 🌍 Store backups in different locations whenever possible to reduce the risk of a single point of failure.
* 🕒 Consider using dated filenames, such as `vault-2026-06-04.cnvault`, so older versions can be identified and restored if needed.
* 🔐 Keep your master password in a safe place. Without the correct master password, the encrypted database cannot be recovered.
* ✅ Periodically verify that your backup files can still be opened successfully with the correct master password.
* 🚫 Do not rely solely on the default database location. Device failure, accidental deletion, theft, hardware damage, or operating system reinstallation may result in permanent data loss.

### 🌍 Multi-location Backup Strategy

Good backup habits are not only important for CipherNote Vault, but also for any valuable digital data.

Consider maintaining multiple copies of important files in different locations.
A simple multi-location backup strategy can significantly reduce the risk of data loss caused by hardware failure, accidental deletion, theft, fire, flooding, or other unexpected events.

❤️ A backup only becomes valuable when it is available after something goes wrong. Please make sure both your `.cnvault` database file and your master password are stored safely and can be recovered when needed.

## 📄 License

🔓 **CipherNote Vault** and all files contained in this repository are licensed under the **GNU General Public License v3.0 only (GPL-3.0-only)**, unless explicitly stated otherwise.

You are free to:

* Use
* Study
* Modify
* Redistribute

this software under the terms of the GNU GPLv3 license.

Any distributed derivative work must also comply with the GNU GPLv3 license.

SPDX identifier:

```text
SPDX-License-Identifier: GPL-3.0-only
```

⚠️ This software is provided **"as is"**, without any warranty. Use it at your own risk.

❤️ If you find this project useful, feedback, bug reports, and contributions are always welcome.
