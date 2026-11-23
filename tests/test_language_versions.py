"""Regression checks shared by the independently runnable language versions."""

import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import string
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.dont_write_bytecode = True

from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import QApplication, QDialog, QLineEdit, QStyle, QStyleOptionViewItem


ROOT = Path(__file__).resolve().parents[1]
FILENAMES = ("app_zh.py", "CipherNoteVault_en.py", "app_ja.py", "app_ko.py", "app_es.py")


def load_version(filename):
    spec = importlib.util.spec_from_file_location(Path(filename).stem, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NormalizeText(ast.NodeTransformer):
    """Ignore translated strings while preserving APIs, structure, and numbers."""

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            node.value = "<text>"
        return node


class LanguageVersionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.versions = {filename: load_version(filename) for filename in FILENAMES}

    def setUp(self):
        preferred_temp = Path(os.environ.get("LOCALAPPDATA", "")) / "Temp" / "opencode"
        self.temp = tempfile.TemporaryDirectory(
            prefix="ciphernote-tests-", dir=preferred_temp if preferred_temp.is_dir() else None
        )
        self.addCleanup(self.temp.cleanup)

    def new_unlocked_vault(self, module):
        # Tests of saving and widgets need an unlocked vault but no repeated KDF.
        # Cross-language tests below separately exercise the production KDF.
        vault = module.Vault(Path(self.temp.name) / "test.cnvault")
        vault.key = os.urandom(32)
        vault.salt = os.urandom(16)
        return vault

    def test_implementation_parity(self):
        def normalized(filename):
            tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
            return ast.dump(NormalizeText().visit(tree))

        expected = normalized("app_zh.py")
        for filename in FILENAMES[1:]:
            with self.subTest(language=filename):
                self.assertEqual(normalized(filename), expected)
                # UI text may differ, but protocol identifiers and parameters must not.
                module = self.versions[filename]
                baseline = self.versions["app_zh.py"]
                self.assertEqual(module.ARGON2ID_PARAMS, baseline.ARGON2ID_PARAMS)
                self.assertEqual(module.empty_payload(), baseline.empty_payload())
                self.assertEqual(module.VAULT_FORMAT, baseline.VAULT_FORMAT)
                self.assertEqual(module.VAULT_VERSION, baseline.VAULT_VERSION)

    def test_cross_language_encrypted_round_trip(self):
        path = Path(self.temp.name) / "shared.cnvault"
        password = "Cross-language master password!"
        baseline = self.versions["app_zh.py"]
        vault = baseline.Vault(path)
        vault.create(password)
        expected = []
        for filename, module in self.versions.items():
            with self.subTest(language=filename):
                vault = module.Vault(path)
                vault.unlock(password)
                self.assertEqual(vault.all_items(), expected)
                item = {"id": filename, "type": "note", "title": "中文 日本語 한국어 Español",
                        "content": "Private content: " + filename, "font_size": 24,
                        "created_at": "legacy", "updated_at": "legacy"}
                vault.upsert_item(item)
                self.assertNotIn("created_at", item)
                self.assertNotIn("updated_at", item)
                expected.append(item)
                self.assertEqual(vault.payload["items"], expected)
                self.assertNotIn("Private content", path.read_text(encoding="utf-8"))
                outer = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(outer["kdf"], baseline.ARGON2ID_PARAMS)

        reopened = baseline.Vault(path)
        reopened.unlock(password)
        self.assertEqual(reopened.all_items(), expected)
        with self.assertRaises(baseline.VaultError):
            baseline.Vault(path).unlock("wrong password")

        reopened.change_master_password("New master password!")
        translated = self.versions["CipherNoteVault_en.py"].Vault(path)
        translated.unlock("New master password!")
        self.assertEqual(translated.all_items(), expected)
        # Modifying authenticated metadata must invalidate the ciphertext.
        outer = json.loads(path.read_text(encoding="utf-8"))
        outer["kdf"]["iterations"] = 3
        path.write_text(json.dumps(outer), encoding="utf-8")
        with self.assertRaises(baseline.VaultError):
            baseline.Vault(path).unlock("New master password!")

    def test_legacy_timestamps_removed_and_failed_write_rolled_back(self):
        for filename, module in self.versions.items():
            with self.subTest(language=filename):
                vault = self.new_unlocked_vault(module)
                vault.payload.update(created_at="legacy", updated_at="legacy")
                vault.payload["items"] = [
                    {"id": "existing", "type": "note", "title": "Original", "content": "Original",
                     "created_at": "legacy", "updated_at": "legacy"}
                ]
                vault.save()
                self.assertNotIn("created_at", vault.payload)
                self.assertNotIn("updated_at", vault.payload)
                self.assertNotIn("created_at", vault.all_items()[0])
                self.assertNotIn("updated_at", vault.all_items()[0])
                original = copy.deepcopy(vault.payload)
                original_file = vault.path.read_bytes()
                for item_id in ("existing", "new"):
                    candidate = {"id": item_id, "type": "note", "title": "Changed",
                                 "content": "Unsaved", "updated_at": "legacy"}
                    original_candidate = dict(candidate)
                    with patch.object(module.os, "replace", side_effect=OSError("disk unavailable")):
                        with self.assertRaises(OSError):
                            vault.upsert_item(candidate)
                    self.assertEqual(vault.payload, original)
                    self.assertEqual(candidate, original_candidate)
                    self.assertEqual(vault.path.read_bytes(), original_file)
                vault.upsert_item({"id": "existing", "type": "note", "title": "Retry"})
                self.assertEqual(vault.all_items()[0]["title"], "Retry")

    def test_widgets_and_note_save_retry(self):
        for filename, module in self.versions.items():
            with self.subTest(language=filename):
                vault = self.new_unlocked_vault(module)
                window = module.MainWindow(vault)
                self.addCleanup(window.close)
                window.show()
                self.app.processEvents()
                self.assertEqual(window.password_table.columnCount(), 3)
                self.assertEqual(window.note_table.columnCount(), 1)
                self.assertTrue(window.note_table.horizontalHeader().isHidden())
                self.assertFalse(hasattr(window, "note_detail"))
                self.assertIsInstance(window.password_table.itemDelegate(), module.NoFocusItemDelegate)

                startup = module.StartupDialog()
                self.assertEqual(startup.mode, "open")
                self.assertFalse(startup.confirm_edit.isEnabled())
                startup.create_database_radio.setChecked(True)
                self.assertEqual(startup.mode, "create")
                self.assertTrue(startup.confirm_edit.isEnabled())
                startup.close()
                master = module.MasterPasswordDialog()
                master.close()
                password_dialog = module.PasswordDialog()
                password_dialog.toggle_password_visibility()
                self.assertEqual(password_dialog.password_edit.echoMode(), QLineEdit.EchoMode.Normal)
                password_dialog.close()

                window.search_edit.setText("does not match")
                editor = module.NoteDialog(on_save=window.save_note, parent=window)
                editor.show()
                editor.title_edit.setText("Saved note")
                editor.content_edit.setPlainText("Recoverable text 日本語 한국어")
                editor.note_font_slider.setValue(24)
                editor.save_without_closing()
                self.assertTrue(editor.isVisible())
                self.assertEqual(window.search_edit.text(), "")
                self.assertEqual(window.selected_note()["id"], editor.item["id"])
                self.assertEqual(vault.all_items("note")[0]["font_size"], 24)
                self.assertEqual(editor.content_edit.font().pointSize(), 24)
                shortcuts = editor.findChildren(QShortcut)
                self.assertTrue(any(s.key() == QKeySequence(QKeySequence.StandardKey.Save) for s in shortcuts))

                original = copy.deepcopy(vault.payload)
                editor.content_edit.setPlainText("Text to retry")
                with patch.object(vault, "save", side_effect=OSError("disk unavailable")):
                    with patch.object(module.QMessageBox, "critical") as message:
                        editor.save_without_closing()
                        message.assert_called_once()
                self.assertEqual(vault.payload, original)
                self.assertEqual(editor.content_edit.toPlainText(), "Text to retry")
                self.assertNotEqual(editor.save_status_label.text(), self.saved_label(module))
                editor.save_without_closing()
                self.assertEqual(vault.all_items("note")[0]["content"], "Text to retry")
                self.assertEqual(editor.save_status_label.text(), self.saved_label(module))

                # Editing the same note must replace it, not add another record.
                existing = module.NoteDialog(item=editor.item, on_save=window.save_note, parent=window)
                existing.content_edit.setPlainText("Edited again")
                existing.save_without_closing()
                self.assertEqual(len(vault.all_items("note")), 1)
                self.assertEqual(vault.all_items("note")[0]["content"], "Edited again")
                existing.close()
                editor.close()

                disconnected = module.NoteDialog()
                disconnected.title_edit.setText("No save callback")
                with patch.object(module.QMessageBox, "critical") as message:
                    disconnected.save_without_closing()
                    message.assert_called_once()
                self.assertEqual(disconnected.item, {})
                disconnected.close()

                # New/edit actions must wire the persistence callback, even when
                # the dialog stays open after pressing Save.
                def save_from_dialog(dialog):
                    self.assertEqual(dialog.on_save, window.save_note)
                    dialog.title_edit.setText("Action note")
                    dialog.content_edit.setPlainText("Saved by action")
                    dialog.save_without_closing()
                    dialog.close()
                    return QDialog.DialogCode.Rejected

                with patch.object(module.NoteDialog, "exec", save_from_dialog):
                    window.add_note()
                    window.edit_note()
                self.assertEqual(len(vault.all_items("note")), 2)
                self.assertEqual(window.selected_note()["content"], "Saved by action")

                with patch.object(module.QMessageBox, "information") as message:
                    window.show_database_info()
                    window.show_security_notes()
                    window.show_donation()
                    self.assertEqual(message.call_count, 3)

                vault.upsert_item({"id": "password", "type": "password", "title": "Account",
                                   "username": "user", "password": "secret", "notes": "Memo"})
                window.refresh_all()
                window.password_table.selectRow(0)
                window.show_clicked_password_detail()
                self.assertFalse(window.password_detail.isHidden())
                self.assertNotIn("secret", window.password_detail.body.text())
                option = QStyleOptionViewItem()
                option.state |= QStyle.StateFlag.State_HasFocus
                window.password_table.itemDelegate().initStyleOption(
                    option, window.password_table.model().index(0, 0)
                )
                self.assertFalse(option.state & QStyle.StateFlag.State_HasFocus)
                window.close()

    @staticmethod
    def saved_label(module):
        return {"app_zh": "已保存", "CipherNoteVault_en": "Saved", "app_ja": "保存済み",
                "app_ko": "저장됨", "app_es": "Guardado"}[module.__name__]

    def test_password_generator_constraints(self):
        for filename, module in self.versions.items():
            with self.subTest(language=filename):
                generator = module.PasswordGeneratorDialog()
                with patch.object(module.PasswordGeneratorDialog, "exec", return_value=QDialog.DialogCode.Accepted):
                    generated = generator.generate()
                    self.assertEqual(len(generated), 28)
                    for chars in (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation):
                        self.assertTrue(any(character in chars for character in generated))
                    generator.include_alnum_checkbox.setChecked(False)
                    generator.use_mixed_case_checkbox.setChecked(False)
                    generator.include_symbols_checkbox.setChecked(False)
                    with patch.object(module.QMessageBox, "warning") as message:
                        self.assertIsNone(generator.generate())
                        message.assert_called_once()
                generator.close()


if __name__ == "__main__":
    unittest.main()
