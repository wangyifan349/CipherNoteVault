# SPDX-License-Identifier: GPL-3.0-only
# CipherNote Vault
# Copyright (C) 2026 Wang Yifan
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 3 of the License.

import base64
import ctypes
import json
import os
import platform
import secrets
import string
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from PyQt6.QtCore import Qt, QTimer, QPoint
    from PyQt6.QtGui import QAction, Qフォント, QKeySequence, QShortcut
    from PyQt6.QtWidgets import (
        QApplication,
        QAbstractItemView,
        QButtonGroup,
        QCheckBox,
        QDialog,
        QFileDialog,
        QFormLayout,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLine編集,
        QMainWindow,
        QMenu,
        QMessageBox,
        QRadioButton,
        QPushButton,
        QPlainText編集,
        QSplitter,
        QSlider,
        QSpinBox,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:
    print("缺少依赖。请运行：pip install PyQt6 \"cryptography>=44.0.0\"")
    print(exc)
    raise


APP_NAME = "CipherNote Vault"
APP_VERSION = "1.4.0"
VAULT_FORMAT = "CipherNote Vault Database"
VAULT_VERSION = 1
DEFAULT_VAULT_DIR = Path.home() / ".ciphernote_vault"
DEFAULT_VAULT = DEFAULT_VAULT_DIR / "vault.cnvault"

ARGON2ID_PARAMS = {
    "name": "Argon2id",
    "length": 32,
    "iterations": 4,
    "lanes": 4,
    "memory_cost": 256 * 1024,
}

DONATION_BTC = "bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p"
DONATION_ETH = "0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b"
DONATION_BNB = "0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b"

WINDOWS_DISPLAY_AFFINITY_NONE = 0x00000000
WINDOWS_DISPLAY_AFFINITY_EXCLUDE_FROM_CAPTURE = 0x00000011
WINDOWS_DISPLAY_AFFINITY_MONITOR_ONLY = 0x00000001


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def readable_time(value: str) -> str:
    if not value:
        return ""
    return value.replace("T", " ").replace("+00:00", " UTC")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def make_aad(kdf: Dict[str, Any], salt_b64: str) -> bytes:
    metadata = {
        "format": VAULT_FORMAT,
        "version": VAULT_VERSION,
        "cipher": "ChaCha20-Poly1305",
        "kdf": kdf,
        "salt": salt_b64,
    }
    return json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8")


def derive_key(master_password: str, salt: bytes, kdf: Dict[str, Any]) -> bytes:
    if not master_password:
        raise ValueError("マスターパスワードは空にできません。")
    if kdf.get("name") != "Argon2id":
        raise ValueError("Unsupported key derivation algorithm.")

    return Argon2id(
        salt=salt,
        length=int(kdf.get("length", 32)),
        iterations=int(kdf.get("iterations", 3)),
        lanes=int(kdf.get("lanes", 4)),
        memory_cost=int(kdf.get("memory_cost", 64 * 1024)),
        ad=None,
        secret=None,
    ).derive(master_password.encode("utf-8"))


def empty_payload() -> Dict[str, Any]:
    return {
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "items": [],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }


def password_strength_label(password: str) -> str:
    score = 0
    if len(password) >= 12:
        score += 1
    if len(password) >= 18:
        score += 1
    if len(password) >= 24:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score <= 3:
        return "弱"
    if score <= 5:
        return "中"
    return "強"


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: Path):
        self.path = path
        self.key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        self.kdf: Dict[str, Any] = dict(ARGON2ID_PARAMS)
        self.payload: Dict[str, Any] = empty_payload()

    def create(self, master_password: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.salt = os.urandom(16)
        self.kdf = dict(ARGON2ID_PARAMS)
        self.key = derive_key(master_password, self.salt, self.kdf)
        self.payload = empty_payload()
        self.save()

    def unlock(self, master_password: str) -> None:
        if not self.path.exists():
            raise VaultError("データベースファイルが存在しません。")

        try:
            outer = json.loads(self.path.read_text(encoding="utf-8"))
            if outer.get("format") != VAULT_FORMAT:
                raise VaultError("CipherNote Vault データベースではありません。")
            if outer.get("version") != VAULT_VERSION:
                raise VaultError("未対応のデータベースバージョンです。")
            if outer.get("cipher") != "ChaCha20-Poly1305":
                raise VaultError("未対応の暗号化アルゴリズムです。")
            kdf = outer.get("kdf")
            if not isinstance(kdf, dict) or kdf.get("name") != "Argon2id":
                raise VaultError("KDF パラメータが無効です。")
            salt_b64 = outer["salt"]
            salt = b64d(salt_b64)
            nonce = b64d(outer["nonce"])
            ciphertext = b64d(outer["ciphertext"])
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError("データベースファイルが破損しているか、形式が無効です。") from exc

        key = derive_key(master_password, salt, kdf)

        try:
            aad = make_aad(kdf, salt_b64)
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise VaultError("マスターパスワードが違うか、データベースが改ざんされています。") from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise VaultError("The decrypted database content is corrupted.") from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise VaultError("Invalid database content format.")

        self.key = key
        self.salt = salt
        self.kdf = kdf
        self.payload = payload

    def save(self) -> None:
        if self.key is None or self.salt is None:
            raise VaultError("データベースはロックされています。")

        self.payload["updated_at"] = now_iso()
        plaintext = json.dumps(self.payload, ensure_ascii=False, sort_keys=True).encode("utf-8")

        nonce = os.urandom(12)
        salt_b64 = b64e(self.salt)
        aad = make_aad(self.kdf, salt_b64)
        ciphertext = ChaCha20Poly1305(self.key).encrypt(nonce, plaintext, aad)

        outer = {
            "format": VAULT_FORMAT,
            "version": VAULT_VERSION,
            "cipher": "ChaCha20-Poly1305",
            "kdf": self.kdf,
            "salt": salt_b64,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }

        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(outer, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def change_master_password(self, new_master_password: str) -> None:
        if self.key is None:
            raise VaultError("データベースはロックされています。")
        self.salt = os.urandom(16)
        self.kdf = dict(ARGON2ID_PARAMS)
        self.key = derive_key(new_master_password, self.salt, self.kdf)
        self.save()

    def lock(self) -> None:
        self.key = None
        self.salt = None
        self.payload = empty_payload()

    def all_items(self, item_type: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.payload.get("items", [])
        if item_type is None:
            return list(items)
        return [item for item in items if item.get("type") == item_type]

    def upsert_item(self, item: Dict[str, Any]) -> None:
        items = self.payload.setdefault("items", [])
        item["updated_at"] = now_iso()
        for index, existing in enumerate(items):
            if existing.get("id") == item.get("id"):
                items[index] = item
                self.save()
                return
        item.setdefault("id", str(uuid.uuid4()))
        item.setdefault("created_at", now_iso())
        items.append(item)
        self.save()

    def delete_item(self, item_id: str) -> None:
        items = self.payload.setdefault("items", [])
        self.payload["items"] = [item for item in items if item.get("id") != item_id]
        self.save()


class StartupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mode = "open"
        self.setWindowTitle(APP_NAME)
        self.setMinimumWidth(780)

        title_label = QLabel("CipherNote Vault")
        title_label.setObjectName("DialogTitle")
        subtitle_label = QLabel("ローカル暗号化パスワード管理・セキュアノートアプリです。すべての内容は Argon2id + ChaCha20-Poly1305 で保護されます。")
        subtitle_label.setObjectName("SubtleLabel")
        subtitle_label.setWordWrap(True)

        self.open_database_radio = QRadioButton("既存のデータベースを開く")
        self.create_database_radio = QRadioButton("新しいデータベースを作成")
        self.open_database_radio.setObjectName("ModeRadio")
        self.create_database_radio.setObjectName("ModeRadio")
        self.open_database_radio.setChecked(True)

        self.mode_button_group = QButtonGroup(self)
        self.mode_button_group.addButton(self.open_database_radio)
        self.mode_button_group.addButton(self.create_database_radio)
        self.mode_button_group.setExclusive(True)

        self.open_database_radio.toggled.connect(self.update_startup_mode)
        self.create_database_radio.toggled.connect(self.update_startup_mode)

        mode_frame = QFrame()
        mode_frame.setObjectName("ModeFrame")
        mode_layout = QHBoxLayout(mode_frame)
        mode_layout.setContentsMargins(12, 10, 12, 10)
        mode_layout.setSpacing(18)
        mode_layout.addWidget(self.open_database_radio)
        mode_layout.addWidget(self.create_database_radio)
        mode_layout.addStretch(1)

        self.path_edit = QLine編集(str(DEFAULT_VAULT))
        self.path_edit.setPlaceholderText(".cnvault データベースファイルを選択")
        browse_button = QPushButton("参照")
        browse_button.clicked.connect(self.browse)

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_edit, 1)
        path_layout.addWidget(browse_button)

        self.password_edit = QLine編集()
        self.password_edit.setEchoMode(QLine編集.EchoMode.Password)
        self.confirm_edit = QLine編集()
        self.confirm_edit.setEchoMode(QLine編集.EchoMode.Password)

        self.status_label = QLabel("")
        self.status_label.setObjectName("SubtleLabel")
        self.status_label.setWordWrap(True)

        form_layout = QFormLayout()
        form_layout.addRow("操作:", mode_frame)
        form_layout.addRow("データベースファイル:", path_layout)
        form_layout.addRow("マスターパスワード:", self.password_edit)
        form_layout.addRow("マスターパスワード確認:", self.confirm_edit)
        form_layout.addRow("", self.status_label)

        self.ok_button = QPushButton("データベースを開く")
        self.cancel_button = QPushButton("キャンセル")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        dialog_layout = QVBoxLayout(self)
        dialog_layout.addWidget(title_label)
        dialog_layout.addWidget(subtitle_label)
        dialog_layout.addSpacing(10)
        dialog_layout.addLayout(form_layout)
        dialog_layout.addLayout(button_layout)

        self.update_startup_mode()

    def update_startup_mode(self):
        if self.create_database_radio.isChecked():
            self.mode = "create"
            self.setWindowTitle("新しいデータベースを作成 - CipherNote Vault")
            self.ok_button.setText("データベースを作成")
            self.confirm_edit.setEnabled(True)
            self.status_label.setText("現在の操作: 新しいデータベースを強力な暗号化設定で作成します。")
        else:
            self.mode = "open"
            self.setWindowTitle("データベースを開く - CipherNote Vault")
            self.ok_button.setText("データベースを開く")
            self.confirm_edit.setEnabled(False)
            self.status_label.setText("現在の操作: 既存のデータベースを開きます。.cnvault ファイルを選択し、マスターパスワードを入力してください。")

    def browse(self):
        if self.mode == "create":
            selected_filename, _ = QFileDialog.get保存FileName(
                self,
                "Create CipherNote Vault database",
                self.path_edit.text() or str(DEFAULT_VAULT),
                "CipherNote Vault (*.cnvault);;JSON Files (*.json);;All Files (*)",
            )
        else:
            selected_filename, _ = QFileDialog.getOpenFileName(
                self,
                "Open CipherNote Vault database",
                self.path_edit.text() or str(DEFAULT_VAULT_DIR),
                "CipherNote Vault (*.cnvault);;JSON Files (*.json);;All Files (*)",
            )
        if selected_filename:
            self.path_edit.setText(selected_filename)

    def get_result(self) -> Optional[Dict[str, Any]]:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None

        database_path = Path(self.path_edit.text()).expanduser()
        master_password = self.password_edit.text()

        if not str(database_path).strip():
            QMessageBox.warning(self, "パスがありません", "データベースファイルのパスを選択してください。")
            return None
        if not master_password:
            QMessageBox.warning(self, "マスターパスワードがありません", "マスターパスワードを入力してください。")
            return None

        if self.mode == "create":
            if len(master_password) < 12:
                QMessageBox.warning(self, "マスターパスワードが短すぎます", "マスターパスワードは12文字以上、できれば長いパスフレーズを推奨します。")
                return None
            if master_password != self.confirm_edit.text():
                QMessageBox.warning(self, "パスワードが一致しません", "2つのマスターパスワードが一致しません。")
                return None
            if database_path.exists():
                answer = QMessageBox.question(self, "ファイルは既に存在します", "このファイルは既に存在します。続行すると上書きされます。よろしいですか？")
                if answer != QMessageBox.StandardButton.Yes:
                    return None
            return {"mode": "create", "path": database_path, "password": master_password}

        if not database_path.exists():
            QMessageBox.warning(self, "ファイルが存在しません", "既存のデータベースファイルを選択してください。")
            return None
        return {"mode": "open", "path": database_path, "password": master_password}


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("強力なパスワードを生成")
        self.setMinimumWidth(420)

        self.password_length_spinbox = QSpinBox()
        self.password_length_spinbox.setRange(8, 128)
        self.password_length_spinbox.setValue(28)

        self.include_alnum_checkbox = QCheckBox("英数字")
        self.use_mixed_case_checkbox = QCheckBox("大文字・小文字")
        self.include_symbols_checkbox = QCheckBox("記号")

        self.include_alnum_checkbox.setChecked(True)
        self.use_mixed_case_checkbox.setChecked(True)
        self.include_symbols_checkbox.setChecked(True)

        form_layout = QFormLayout()
        form_layout.addRow("パスワード長:", self.password_length_spinbox)
        form_layout.addRow("", self.include_alnum_checkbox)
        form_layout.addRow("", self.use_mixed_case_checkbox)
        form_layout.addRow("", self.include_symbols_checkbox)

        generate_button = QPushButton("生成")
        cancel_button = QPushButton("キャンセル")
        generate_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)

        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(generate_button)
        button_layout.addWidget(cancel_button)

        dialog_layout = QVBoxLayout(self)
        dialog_layout.addLayout(form_layout)
        dialog_layout.addLayout(button_layout)

    def generate(self) -> Optional[str]:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None

        character_groups = []

        if self.include_alnum_checkbox.isChecked():
            if self.use_mixed_case_checkbox.isChecked():
                character_groups.extend([string.ascii_lowercase, string.ascii_uppercase, string.digits])
            else:
                character_groups.extend([string.ascii_lowercase, string.digits])
        elif self.use_mixed_case_checkbox.isChecked():
            character_groups.extend([string.ascii_lowercase, string.ascii_uppercase])

        if self.include_symbols_checkbox.isChecked():
            character_groups.append("!@#$%^&*()-_=+[]{}:,.?")

        if not character_groups:
            QMessageBox.warning(self, "条件がありません", "少なくとも1つの条件を選択してください。")
            return None

        password_length = self.password_length_spinbox.value()
        if password_length < len(character_groups):
            QMessageBox.warning(self, "Length is too short", "Password length cannot be smaller than the number of selected character groups.")
            return None

        character_pool = "".join(character_groups)
        password_characters = [secrets.choice(group) for group in character_groups]
        password_characters.extend(
            secrets.choice(character_pool)
            for _ in range(password_length - len(password_characters))
        )
        secrets.SystemRandom().shuffle(password_characters)
        return "".join(password_characters)


class PasswordDialog(QDialog):
    def __init__(self, item: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.item = item or {}
        self.setWindowTitle("パスワード項目")
        self.resize(860, 620)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.setWindowFlag(Qt.WindowType.WindowMinimizeButtonHint, True)

        self.title_edit = QLine編集(self.item.get("title", ""))
        self.username_edit = QLine編集(self.item.get("username", ""))
        self.password_edit = QLine編集(self.item.get("password", ""))
        self.password_edit.setEchoMode(QLine編集.EchoMode.Password)
        self.notes_edit = QPlainText編集(self.item.get("notes", ""))

        self.strength_label = QLabel("")
        self.strength_label.setObjectName("SubtleLabel")
        self.password_edit.text変更済み.connect(self.update_strength)
        self.update_strength()

        show_password_button = QPushButton("表示/非表示")
        generate_password_button = QPushButton("強力なパスワードを生成")
        show_password_button.clicked.connect(self.toggle_password_visibility)
        generate_password_button.clicked.connect(self.generate_password)

        password_row = QHBoxLayout()
        password_row.addWidget(self.password_edit, 1)
        password_row.addWidget(show_password_button)
        password_row.addWidget(generate_password_button)

        form_layout = QFormLayout()
        form_layout.addRow("タイトル:", self.title_edit)
        form_layout.addRow("ユーザー名:", self.username_edit)
        form_layout.addRow("パスワード:", password_row)
        form_layout.addRow("", self.strength_label)
        form_layout.addRow("メモ:", self.notes_edit)

        save_button = QPushButton("保存")
        cancel_button = QPushButton("キャンセル")
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)

        button_layout = QHBoxLayout()
        button_layout.addStretch(1)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)

        dialog_layout = QVBoxLayout(self)
        dialog_layout.addLayout(form_layout)
        dialog_layout.addLayout(button_layout)

    def update_strength(self):
        password_value = self.password_edit.text()
        self.strength_label.setText(
            "パスワード強度: 未入力"
            if not password_value
            else f"パスワード強度: {password_strength_label(password_value)}"
        )

    def toggle_password_visibility(self):
        if self.password_edit.echoMode() == QLine編集.EchoMode.パスワード:
            self.password_edit.setEchoMode(QLine編集.EchoMode.Normal)
        else:
            self.password_edit.setEchoMode(QLine編集.EchoMode.Password)

    def generate_password(self):
        generated_password = PasswordGeneratorDialog(parent=self).generate()
        if generated_password:
            self.password_edit.setText(generated_password)
            self.password_edit.setEchoMode(QLine編集.EchoMode.Normal)

    def get_item(self) -> Optional[Dict[str, Any]]:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None

        title_value = self.title_edit.text().strip()
        if not title_value:
            QMessageBox.warning(self, "タイトルがありません", "タイトルは空にできません。")
            return None

        return {
            "id": self.item.get("id", str(uuid.uuid4())),
            "type": "password",
            "title": title_value,
            "username": self.username_edit.text().strip(),
            "password": self.password_edit.text(),
            "notes": self.notes_edit.toPlainText(),
            "created_at": self.item.get("created_at", now_iso()),
            "updated_at": now_iso(),
        }


class NoteDialog(QDialog):
    def __init__(
        self,
        item: Optional[Dict[str, Any]] = None,
        parent=None,
        on_save: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        super().__init__(parent)
        self.item = dict(item or {})
        self.on_save = on_save
        self.setWindowTitle("セキュアノート")
        self.resize(1120, 820)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.setWindowFlag(Qt.WindowType.WindowMinimizeButtonHint, True)

        self.title_edit = QLine編集(self.item.get("title", ""))
        self.title_edit.setPlaceholderText("ノートタイトル")
        self.content_edit = QPlainText編集(self.item.get("content", ""))
        self.content_edit.setObjectName("NoteContent編集or")
        self.content_edit.setPlaceholderText("大切なノートをここに書いてください...")

        self.note_font_slider = QSlider(Qt.Orientation.Horizontal)
        self.note_font_slider.setRange(12, 36)
        self.note_font_slider.setValue(int(self.item.get("font_size", 18) or 18))
        self.note_font_slider.setFixedWidth(180)
        self.note_font_slider.value変更済み.connect(self.apply_note_font_size)

        self.note_font_size_label = QLabel(f"フォント {self.note_font_slider.value()}")
        self.note_font_size_label.setObjectName("SubtleLabel")
        self.save_status_label = QLabel("Ctrl+Sで保存、閉じません")
        self.save_status_label.setObjectName("SubtleLabel")

        title_layout = QHBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(8)
        title_label = QLabel("Title")
        title_label.setObjectName("検索Label")
        title_label.setFixedWidth(44)
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.title_edit, 1)

        save_button = QPushButton("保存")
        close_button = QPushButton("閉じる")
        save_button.clicked.connect(self.save_without_closing)
        close_button.clicked.connect(self.close)

        save_shortcut = QShortcut(QKeySequence.StandardKey.保存, self)
        save_shortcut.activated.connect(self.save_without_closing)

        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(0, 6, 0, 0)
        bottom_layout.setSpacing(8)
        bottom_layout.addWidget(QLabel("フォント"))
        bottom_layout.addWidget(self.note_font_slider)
        bottom_layout.addWidget(self.note_font_size_label)
        bottom_layout.addSpacing(14)
        bottom_layout.addWidget(self.save_status_label)
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(save_button)
        bottom_layout.addWidget(close_button)

        dialog_layout = QVBoxLayout(self)
        dialog_layout.setContentsMargins(10, 10, 10, 10)
        dialog_layout.setSpacing(6)
        dialog_layout.addLayout(title_layout)
        dialog_layout.addWidget(self.content_edit, 1)
        dialog_layout.addLayout(bottom_layout)

        self.apply_note_font_size()

    def apply_note_font_size(self):
        note_font = Qフォント("Microsoft YaHei")
        note_font.setPointSize(self.note_font_slider.value())
        self.content_edit.setフォント(note_font)
        self.note_font_size_label.setText(f"フォント {self.note_font_slider.value()}")

    def build_note_item(self) -> Optional[Dict[str, Any]]:
        note_title = self.title_edit.text().strip()
        if not note_title:
            QMessageBox.warning(self, "タイトルがありません", "タイトルは空にできません。")
            return None

        return {
            "id": self.item.get("id", str(uuid.uuid4())),
            "type": "note",
            "title": note_title,
            "content": self.content_edit.toPlainText(),
            "font_size": self.note_font_slider.value(),
            "created_at": self.item.get("created_at", now_iso()),
            "updated_at": now_iso(),
        }

    def save_without_closing(self):
        note_item = self.build_note_item()
        if note_item is None:
            return

        self.item = note_item
        if self.on_save is not None:
            self.on_save(note_item)

        self.save_status_label.setText(f"保存済み: {readable_time(note_item.get('updated_at', ''))}")

    def get_item(self) -> Optional[Dict[str, Any]]:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None
        return self.build_note_item()


class MasterPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("マスターパスワードを変更")
        self.setMinimumWidth(520)

        self.password_edit = QLine編集()
        self.password_edit.setEchoMode(QLine編集.EchoMode.Password)
        self.confirm_edit = QLine編集()
        self.confirm_edit.setEchoMode(QLine編集.EchoMode.Password)

        hint = QLabel("Changing the master password regenerates the salt and re-encrypts the database using a new Argon2id-derived key.")
        hint.setObjectName("SubtleLabel")
        hint.setWordWrap(True)

        form = QFormLayout()
        form.addRow("新しいマスターパスワード:", self.password_edit)
        form.addRow("マスターパスワード確認:", self.confirm_edit)

        save_btn = QPushButton("変更")
        cancel_btn = QPushButton("キャンセル")
        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(hint)
        layout.addLayout(form)
        layout.addLayout(buttons)

    def get_password(self) -> Optional[str]:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None

        password = self.password_edit.text()
        if len(password) < 12:
            QMessageBox.warning(self, "マスターパスワードが短すぎます", "The master password should be at least 12 characters.")
            return None
        if password != self.confirm_edit.text():
            QMessageBox.warning(self, "パスワードが一致しません", "2つのマスターパスワードが一致しません。")
            return None
        return password


class DetailCard(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("Card")
        self.title = QLabel("項目を選択")
        self.title.setObjectName("CardTitle")
        self.title.setWordWrap(True)
        self.meta = QLabel("")
        self.meta.setObjectName("SubtleLabel")
        self.meta.setWordWrap(True)
        self.body = QLabel("")
        self.body.setObjectName("BodyLabel")
        self.body.setWordWrap(True)
        self.body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        layout = QVBoxLayout(self)
        layout.addWidget(self.title)
        layout.addWidget(self.meta)
        layout.addSpacing(10)
        layout.addWidget(self.body, 1)

    def show_password_item(self, item: Optional[Dict[str, Any]]):
        if not item:
            self.title.setText("请选择一条密码记录")
            self.meta.setText("")
            self.body.setText("左侧列表支持搜索；双击记录可以編集。")
            return

        masked = "•" * min(max(len(item.get("password", "")), 8), 24)
        self.title.setText(item.get("title", ""))
        self.meta.setText(f"更新: {readable_time(item.get('updated_at', ''))}")
        self.body.setText(
            f"ユーザー名:{item.get('username', '')}\n"
            f"パスワード:{masked}\n\n"
            f"メモ:\n{item.get('notes', '')}"
        )

    def show_note_item(self, item: Optional[Dict[str, Any]]):
        if not item:
            self.title.setText("请选择一条セキュリティ笔记")
            self.meta.setText("")
            self.body.setText("左侧列表支持搜索；双击记录可以打开編集。")
            return

        self.title.setText(item.get("title", ""))
        self.meta.setText(f"更新: {readable_time(item.get('updated_at', ''))}")
        self.body.setText(item.get("content", ""))


class MainWindow(QMainWindow):
    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self.setWindowTitle(f"{APP_NAME} - {vault.path}")
        self.resize(1240, 790)

        self.password_items_all: List[Dict[str, Any]] = []
        self.password_items_view: List[Dict[str, Any]] = []
        self.note_items_all: List[Dict[str, Any]] = []
        self.note_items_view: List[Dict[str, Any]] = []

        self.search_edit = QLine編集()
        self.search_edit.setPlaceholderText("タイトル、ユーザー名、メモ、ノート内容を検索")
        self.search_edit.text変更済み.connect(self.apply_filter)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.password_table = self.make_table(["Title", "ユーザー名", "メモ", "更新"])
        self.note_table = self.make_table(["Title", "更新"])
        self.password_detail = DetailCard()
        self.note_detail = DetailCard()
        self.password_detail.hide()
        self.note_detail.hide()
        self.password_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.note_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.tabs.addTab(self.make_password_tab(), "パスワード管理")
        self.tabs.addTab(self.make_note_tab(), "セキュアノート")

        self.make_toolbar()
        self.setup_context_menus()

        main = QWidget()
        layout = QVBoxLayout(main)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        top_card = QFrame()
        top_card.setObjectName("TopCard")
        top_layout = QHBoxLayout(top_card)
        top_layout.setContentsMargins(10, 8, 10, 8)
        top_layout.setSpacing(8)
        search_label = QLabel("検索")
        search_label.setObjectName("検索Label")
        search_label.setMinimumWidth(86)
        search_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_layout.addWidget(search_label)
        top_layout.addWidget(self.search_edit, 1)
        self.status_label = QLabel("")
        self.status_label.setObjectName("SubtleLabel")
        top_layout.addWidget(self.status_label)

        layout.addWidget(top_card)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(main)

        self.password_table.itemClicked.connect(self.show_clicked_password_detail)
        self.note_table.itemClicked.connect(self.show_clicked_note_detail)
        self.password_table.doubleClicked.connect(self.edit_password)
        self.note_table.doubleClicked.connect(self.edit_note)

        self.refresh_all()

    def enable_windows_screen_capture_protection(self):
        if platform.system() != "Windows":
            return

        try:
            window_handle = int(self.winId())
            result = ctypes.windll.user32.SetWindowDisplayAffinity(
                window_handle,
                WINDOWS_DISPLAY_AFFINITY_EXCLUDE_FROM_CAPTURE,
            )

            if result == 0:
                ctypes.windll.user32.SetWindowDisplayAffinity(
                    window_handle,
                    WINDOWS_DISPLAY_AFFINITY_MONITOR_ONLY,
                )
        except Exception:
            pass

    def make_toolbar(self):
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        save_action = QAction("保存", self)
        save_action.triggered.connect(self.force_save)
        toolbar.addAction(save_action)

        change_master_action = QAction("マスターパスワードを変更", self)
        change_master_action.triggered.connect(self.change_master_password)
        toolbar.addAction(change_master_action)

        lock_action = QAction("ロック", self)
        lock_action.triggered.connect(self.lock_and_exit)
        toolbar.addAction(lock_action)

        toolbar.addSeparator()

        info_action = QAction("情報", self)
        info_action.triggered.connect(self.show_database_info)
        toolbar.addAction(info_action)

        donate_action = QAction("スポンサー", self)
        donate_action.triggered.connect(self.show_donation)
        toolbar.addAction(donate_action)

        security_action = QAction("セキュリティ", self)
        security_action.triggered.connect(self.show_security_notes)
        toolbar.addAction(security_action)

    def make_table(self, headers: List[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.set編集Triggers(QAbstractItemView.編集Trigger.No編集Triggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setAlternatingRowColors(True)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        return table

    def make_password_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        self.password_splitter.addWidget(self.password_table)
        self.password_splitter.addWidget(self.password_detail)
        self.password_splitter.setSizes([1240, 0])
        layout.addWidget(self.password_splitter, 1)
        return page

    def make_note_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        self.note_splitter.addWidget(self.note_table)
        self.note_splitter.addWidget(self.note_detail)
        self.note_splitter.setSizes([1240, 0])
        layout.addWidget(self.note_splitter, 1)
        return page

    def setup_context_menus(self):
        self.password_table.customContextMenuRequested.connect(self.show_password_context_menu)
        self.note_table.customContextMenuRequested.connect(self.show_note_context_menu)

    def show_password_context_menu(self, pos: QPoint):
        item = self.password_table.itemAt(pos)
        menu = QMenu(self)
        if item is None:
            add_action = menu.addAction("パスワードを追加")
            action = menu.exec(self.password_table.viewport().mapToGlobal(pos))
            if action == add_action:
                self.add_password()
            return

        self.password_table.selectRow(item.row())
        add_action = menu.addAction("パスワードを追加")
        edit_action = menu.addAction("編集")
        delete_action = menu.addAction("削除")
        menu.addSeparator()
        copy_user_action = menu.addAction("ユーザー名をコピー")
        copy_pass_action = menu.addAction("パスワードをコピー")

        action = menu.exec(self.password_table.viewport().mapToGlobal(pos))
        if action == add_action:
            self.add_password()
        elif action == edit_action:
            self.edit_password()
        elif action == delete_action:
            self.delete_password()
        elif action == copy_user_action:
            self.copy_username()
        elif action == copy_pass_action:
            self.copy_password()

    def show_note_context_menu(self, pos: QPoint):
        item = self.note_table.itemAt(pos)
        menu = QMenu(self)
        if item is None:
            add_action = menu.addAction("ノートを追加")
            action = menu.exec(self.note_table.viewport().mapToGlobal(pos))
            if action == add_action:
                self.add_note()
            return

        self.note_table.selectRow(item.row())
        add_action = menu.addAction("ノートを追加")
        edit_action = menu.addAction("開く/編集")
        delete_action = menu.addAction("削除")

        action = menu.exec(self.note_table.viewport().mapToGlobal(pos))
        if action == add_action:
            self.add_note()
        elif action == edit_action:
            self.edit_note()
        elif action == delete_action:
            self.delete_note()

    def refresh_all(self):
        self.password_items_all = sorted(
            self.vault.all_items("password"),
            key=self.password_sort_key,
        )
        self.note_items_all = sorted(
            self.vault.all_items("note"),
            key=self.note_sort_key,
        )
        self.status_label.setText(f"Passwords {len(self.password_items_all)} · メモ {len(self.note_items_all)} · 強力な暗号化")
        self.apply_filter()

    def password_sort_key(self, item: Dict[str, Any]):
        title_value = str(item.get("title", "")).casefold()
        username_value = str(item.get("username", "")).casefold()
        updated_value = str(item.get("updated_at", ""))
        return (title_value, username_value, updated_value)

    def note_sort_key(self, item: Dict[str, Any]):
        title_value = str(item.get("title", "")).casefold()
        updated_value = str(item.get("updated_at", ""))
        return (title_value, updated_value)

    def apply_filter(self):
        keyword = self.search_edit.text().strip().lower()

        def match(item: Dict[str, Any], fields: List[str]) -> bool:
            if not keyword:
                return True
            return keyword in "\n".join(str(item.get(field, "")) for field in fields).lower()

        self.password_items_view = [item for item in self.password_items_all if match(item, ["title", "username", "notes"])]
        self.note_items_view = [item for item in self.note_items_all if match(item, ["title", "content"])]
        self.refresh_password_table()
        self.refresh_note_table()
        self.hide_details()

    def hide_details(self):
        self.password_detail.hide()
        self.note_detail.hide()
        self.password_splitter.setSizes([1240, 0])
        self.note_splitter.setSizes([1240, 0])

    def refresh_password_table(self):
        self.password_table.setRowCount(0)
        for item in self.password_items_view:
            row = self.password_table.rowCount()
            self.password_table.insertRow(row)
            values = [item.get("title", ""), item.get("username", ""), item.get("notes", ""), readable_time(item.get("updated_at", ""))]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.get("id"))
                self.password_table.setItem(row, column, cell)

    def refresh_note_table(self):
        self.note_table.setRowCount(0)
        for item in self.note_items_view:
            row = self.note_table.rowCount()
            self.note_table.insertRow(row)
            values = [item.get("title", ""), readable_time(item.get("updated_at", ""))]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.get("id"))
                self.note_table.setItem(row, column, cell)

    def selected_password(self) -> Optional[Dict[str, Any]]:
        row = self.password_table.currentRow()
        if row < 0 or row >= len(self.password_items_view):
            return None
        return self.password_items_view[row]

    def selected_note(self) -> Optional[Dict[str, Any]]:
        row = self.note_table.currentRow()
        if row < 0 or row >= len(self.note_items_view):
            return None
        return self.note_items_view[row]

    def show_clicked_password_detail(self, *_args):
        item = self.selected_password()
        if item:
            self.password_detail.show_password_item(item)
            self.password_detail.show()
            self.password_splitter.setSizes([820, 390])

    def show_clicked_note_detail(self, *_args):
        item = self.selected_note()
        if item:
            self.note_detail.show_note_item(item)
            self.note_detail.show()
            self.note_splitter.setSizes([820, 390])

    def require_password_selection(self) -> Optional[Dict[str, Any]]:
        item = self.selected_password()
        if item is None:
            QMessageBox.information(self, "項目を選択", "先にパスワード項目を選択してください。")
        return item

    def require_note_selection(self) -> Optional[Dict[str, Any]]:
        item = self.selected_note()
        if item is None:
            QMessageBox.information(self, "項目を選択", "先にノートを選択してください。")
        return item

    def add_password(self):
        item = PasswordDialog(parent=self).get_item()
        if item:
            self.vault.upsert_item(item)
            self.refresh_all()

    def edit_password(self, *_args):
        item = self.require_password_selection()
        if not item:
            return
        updated = PasswordDialog(item=item, parent=self).get_item()
        if updated:
            self.vault.upsert_item(updated)
            self.refresh_all()

    def delete_password(self):
        item = self.require_password_selection()
        if not item:
            return
        answer = QMessageBox.question(self, "削除の確認", f"削除 “{item.get('title', '')}”?")
        if answer == QMessageBox.StandardButton.Yes:
            self.vault.delete_item(item["id"])
            self.refresh_all()

    def copy_username(self):
        item = self.require_password_selection()
        if item:
            self.copy_to_clipboard(item.get("username", ""), "ユーザー名をコピーしました。")

    def copy_password(self):
        item = self.require_password_selection()
        if item:
            self.copy_to_clipboard(item.get("password", ""), "パスワードをコピーしました。30秒後にクリップボードを消去します。", auto_clear=True)

    def copy_to_clipboard(self, text: str, message: str, auto_clear: bool = False):
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "コピー済み", message)
        if auto_clear:
            def clear_clipboard():
                if QApplication.clipboard().text() == text:
                    QApplication.clipboard().clear()
            QTimer.singleShot(30_000, clear_clipboard)

    def add_note(self):
        item = NoteDialog(parent=self).get_item()
        if item:
            self.vault.upsert_item(item)
            self.refresh_all()

    def edit_note(self, *_args):
        item = self.require_note_selection()
        if not item:
            return
        updated = NoteDialog(item=item, parent=self).get_item()
        if updated:
            self.vault.upsert_item(updated)
            self.refresh_all()

    def delete_note(self):
        item = self.require_note_selection()
        if not item:
            return
        answer = QMessageBox.question(self, "削除の確認", f"削除 “{item.get('title', '')}”?")
        if answer == QMessageBox.StandardButton.Yes:
            self.vault.delete_item(item["id"])
            self.refresh_all()

    def force_save(self):
        try:
            self.vault.save()
            QMessageBox.information(self, "保存d", "データベースを保存しました。")
        except Exception as exc:
            QMessageBox.critical(self, "保存 failed", str(exc))

    def change_master_password(self):
        new_password = MasterPasswordDialog(parent=self).get_password()
        if new_password:
            try:
                self.vault.change_master_password(new_password)
                QMessageBox.information(self, "変更済み", "The master password has been changed and the database has been re-encrypted with the new key.")
            except Exception as exc:
                QMessageBox.critical(self, "変更 failed", str(exc))

    def lock_and_exit(self):
        self.vault.lock()
        self.hide()

        reopened_vault = bootstrap_vault(parent=None)
        if reopened_vault is None:
            self.close()
            return

        self.vault = reopened_vault
        self.setWindowTitle(f"{APP_NAME} - {self.vault.path}")
        self.refresh_all()
        self.show()
        self.enable_windows_screen_capture_protection()

    def show_database_info(self):
        message = (
            f"Application: {APP_NAME} {APP_VERSION}\n"
            f"File: {self.vault.path}\n"
            f"Algorithm: Argon2id + ChaCha20-Poly1305\n"
            f"Argon2id：iterations={self.vault.kdf.get('iterations')}，lanes={self.vault.kdf.get('lanes')}，memory={self.vault.kdf.get('memory_cost')} KiB\n"
            f"Password entries: {len(self.password_items_all)}\n"
            f"セキュアノート: {len(self.note_items_all)}"
        )
        QMessageBox.information(self, "データベース情報", message)

    def show_donation(self):
        message = (
            f"このプロジェクトが役に立った場合は、作者を支援できます。\n\n"
            f"Bitcoin：{DONATION_BTC}\n"
            f"Ethereum：{DONATION_ETH}\n"
            f"BNB Smart Chain：{DONATION_BNB}"
        )
        QMessageBox.information(self, "作者を支援", message)

    def show_security_notes(self):
        message = (
            "CipherNote Vault uses Argon2id to derive a 256-bit key from the master password and uses ChaCha20-Poly1305 to authenticated-encrypt the entire database.\n\n"
            "Password entries and secure notes are stored in the same encrypted payload. The database file only stores the salt, nonce, KDF parameters, and ciphertext.\n\n"
            "Saving uses a temporary file and atomic replacement to reduce the risk of corruption caused by interrupted writes.\n\n"
            "On Windows, the program attempts to enable SetWindowDisplayAffinity to reduce ordinary screenshot and screen-recording capture.\n\n"
            "セキュリティ boundary: this program cannot defend against malware that already controls the machine, phone photography, administrator-level screen capture, keyloggers, clipboard monitoring, or memory dumps. Full-disk encryption is recommended."
        )
        QMessageBox.information(self, "セキュリティメモ", message)


def set_app_style(app: QApplication):
    app.setStyleSheet("""
        QWidget {
            font-family: "Microsoft YaHei", "Segoe UI", "PingFang SC", sans-serif;
            font-size: 14px;
            color: #FFF700;
            background-color: #8A1F00;
        }
        QMainWindow, QDialog {
            background-color: #8A1F00;
        }
        QLine編集, QPlainText編集, QTableWidget {
            background-color: #6F1A00;
            color: #FFF700;
            border: 1px solid #C86F00;
            border-radius: 10px;
            padding: 9px;
            selection-background-color: #B45300;
            selection-color: #FFF700;
        }
        QPlainText編集 { line-height: 1.5em; }
        QTableWidget {
            gridline-color: #9A3400;
            alternate-background-color: #7C1D00;
            border-radius: 12px;
        }
        QTableWidget::item { padding: 8px; }
        QTableWidget::item:selected {
            background-color: #B45300;
            color: #FFF700;
        }
        QHeaderView::section {
            background-color: #5F1700;
            color: #FDE600;
            padding: 8px;
            border: none;
            border-bottom: 1px solid #C86F00;
            font-weight: 700;
        }
        QPushButton {
            background-color: #E9C400;
            color: #4A1200;
            border: 1px solid #F6D900;
            border-radius: 10px;
            padding: 9px 14px;
            font-weight: 800;
        }
        QPushButton:hover { background-color: #F3D500; }
        QPushButton:pressed { background-color: #D9A400; }
        QPushButton:disabled {
            background-color: #9CA300;
            color: #5F1700;
        }
        QPushButton#PrimaryButton {
            background-color: #F1C900;
            padding: 18px;
            font-size: 16px;
        }
        QPushButton#SecondaryButton {
            background-color: #D89C00;
            padding: 18px;
            font-size: 16px;
        }
        QPushButton#SecondaryButton:hover { background-color: #E8B900; }
        QTabWidget::pane {
            border: 1px solid #C86F00;
            border-radius: 12px;
            top: -1px;
            background-color: #8A1F00;
        }
        QTabBar::tab {
            background-color: #6F1A00;
            color: #FDE600;
            padding: 7px 14px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 1px;
            font-weight: 700;
        }
        QTabBar::tab:selected {
            background-color: #E9C400;
            color: #4A1200;
        }
        QToolBar {
            background-color: #5A1500;
            border: none;
            spacing: 6px;
            padding: 6px;
        }
        QToolButton {
            color: #FDE600;
            background-color: #6F1A00;
            border-radius: 8px;
            padding: 7px 9px;
        }
        QToolButton:hover { background-color: #9A3400; }
        QMenu {
            background-color: #6F1A00;
            color: #FFF700;
            border: 1px solid #E9C400;
            padding: 6px;
        }
        QMenu::item {
            padding: 8px 28px;
            border-radius: 6px;
        }
        QMenu::item:selected {
            background-color: #E9C400;
            color: #4A1200;
        }

        QSlider::groove:horizontal {
            height: 6px;
            background-color: #5F1700;
            border: 1px solid #C86F00;
            border-radius: 3px;
        }
        QSlider::handle:horizontal {
            width: 16px;
            margin: -6px 0;
            border-radius: 8px;
            background-color: #E9C400;
            border: 1px solid #F6D900;
        }
        QSlider::sub-page:horizontal {
            background-color: #E9C400;
            border-radius: 3px;
        }
        QSpinBox, QCheckBox {
            color: #FFF700;
            background-color: #6F1A00;
        }
        QLabel#DialogTitle {
            font-size: 30px;
            font-weight: 900;
            color: #FFF700;
        }
        QLabel#CardTitle {
            font-size: 22px;
            font-weight: 900;
            color: #FFF700;
        }
        QLabel#SubtleLabel { color: #FDE600; }
        QLabel#BodyLabel {
            color: #FFF700;
            background-color: #6F1A00;
            border-radius: 10px;
            padding: 12px;
        }
        QLabel#検索Label {
            font-weight: 800;
            color: #FDE600;
        }
        QFrame#Card {
            background-color: #6F1A00;
            border: 1px solid #C86F00;
            border-radius: 16px;
            padding: 12px;
        }
        QFrame#TopCard {
            background-color: #5F1700;
            border: 1px solid #C86F00;
            border-radius: 14px;
            padding: 8px;
        }
        QMessageBox QLabel { color: #FFF700; }
    """)


def bootstrap_vault(parent=None) -> Optional[Vault]:
    for _ in range(3):
        dialog = StartupDialog(parent=parent)
        result = dialog.get_result()
        if result is None:
            return None

        vault = Vault(result["path"])
        try:
            if result["mode"] == "create":
                vault.create(result["password"])
            else:
                vault.unlock(result["password"])
            return vault
        except Exception as exc:
            QMessageBox.critical(parent, "数据库打开失败", str(exc))

    return None


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    set_app_style(app)

    vault = bootstrap_vault()
    if vault is None:
        return 1

    window = MainWindow(vault)
    window.show()
    window.enable_windows_screen_capture_protection()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
