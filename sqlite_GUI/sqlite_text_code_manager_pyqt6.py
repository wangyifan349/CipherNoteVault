"""
This is a local text/code manager built with SQLite and PyQt6. It stores three kinds of user data: title, body, and remark. It supports adding records, double-click viewing, editing, deleting, smart search, importing a single file, importing files from a directory in bulk, and exporting selected records in bulk. When importing a file, the title is saved as the file name, the body is saved as the file content, and the remark is left empty. Search, import, and export operations run in worker threads so the interface remains responsive with large datasets.
In the body window, Ctrl + mouse wheel adjusts only the body text font size. In the table, Ctrl+A selects all rows and Ctrl+D inverts the selection.
Install and run: python -m pip install PyQt6 && python sqlite_text_code_manager_pyqt6_clean_en.py
"""
import hashlib
import re
import sqlite3
import sys
import threading
from pathlib import Path
from PyQt6.QtCore import QEvent, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QKeySequence, QPalette, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QSlider,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


DB_NAME = "snippets.db"

DEFAULT_EXTENSIONS = {
    ".py",
    ".txt",
    ".json",
    ".sql",
    ".md",
    ".yaml",
    ".yml",
}

UI_FONT_SIZE = 14
DEFAULT_BODY_FONT_SIZE = 14

COLORS = {
    "app_bg": "#FFF000",
    "panel_bg": "#FFE000",
    "panel_alt": "#FFD000",
    "field_bg": "#FFFF00",
    "button_bg": "#D85000",
    "button_hover": "#F06000",
    "button_pressed": "#B03000",
    "danger_bg": "#A00000",
    "danger_hover": "#C02000",
    "border": "#8A3000",
    "border_soft": "#C86000",
    "text": "#220000",
    "text_muted": "#5A3000",
    "selection": "#C84000",
    "selection_text": "#FFFF00",
    "table_header": "#B84000",
    "progress_bg": "#FFD000",
    "progress_chunk": "#B84000",
    "disabled_bg": "#806000",
}


def build_style(body_font_size):
    return f"""
    QWidget {{
        background-color: {COLORS["app_bg"]};
        color: {COLORS["text"]};
        font-size: {UI_FONT_SIZE}px;
    }}

    QMainWindow {{
        background-color: {COLORS["app_bg"]};
    }}

    QLabel {{
        background-color: transparent;
        color: {COLORS["text"]};
    }}

    QLabel#mutedLabel {{
        color: {COLORS["text_muted"]};
    }}

    QLineEdit,
    QPlainTextEdit,
    QComboBox {{
        background-color: {COLORS["field_bg"]};
        color: {COLORS["text"]};
        border: 2px solid {COLORS["border"]};
        border-radius: 8px;
        padding: 7px;
        selection-background-color: {COLORS["selection"]};
        selection-color: {COLORS["selection_text"]};
    }}

    QLineEdit:focus,
    QPlainTextEdit:focus,
    QComboBox:focus {{
        border: 2px solid {COLORS["button_bg"]};
    }}

    QPlainTextEdit#bodyTextEdit {{
        font-size: {body_font_size}px;
    }}

    QPlainTextEdit#remarkTextEdit {{
        font-size: 12px;
        min-height: 56px;
        max-height: 76px;
    }}

    QPushButton#remarkToggleButton {{
        padding: 3px 8px;
        min-width: 58px;
        max-width: 70px;
        min-height: 24px;
        max-height: 28px;
    }}

    QComboBox::drop-down {{
        background-color: {COLORS["panel_alt"]};
        border-left: 1px solid {COLORS["border"]};
        width: 28px;
    }}

    QComboBox::down-arrow {{
        width: 0px;
        height: 0px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {COLORS["field_bg"]};
        color: {COLORS["text"]};
        border: 2px solid {COLORS["border"]};
        selection-background-color: {COLORS["selection"]};
        selection-color: {COLORS["selection_text"]};
    }}

    QPushButton {{
        background-color: {COLORS["button_bg"]};
        color: {COLORS["text"]};
        border: 2px solid {COLORS["border"]};
        border-radius: 8px;
        padding: 8px 12px;
        font-weight: bold;
    }}

    QPushButton:hover {{
        background-color: {COLORS["button_hover"]};
    }}

    QPushButton:pressed {{
        background-color: {COLORS["button_pressed"]};
    }}

    QPushButton:disabled {{
        background-color: {COLORS["disabled_bg"]};
        color: {COLORS["text_muted"]};
    }}

    QPushButton#dangerButton {{
        background-color: {COLORS["danger_bg"]};
        color: {COLORS["selection_text"]};
    }}

    QPushButton#dangerButton:hover {{
        background-color: {COLORS["danger_hover"]};
    }}

    QTableWidget {{
        background-color: {COLORS["field_bg"]};
        color: {COLORS["text"]};
        border: 2px solid {COLORS["border"]};
        border-radius: 8px;
        gridline-color: {COLORS["border_soft"]};
        selection-background-color: {COLORS["selection"]};
        selection-color: {COLORS["selection_text"]};
    }}

    QHeaderView::section {{
        background-color: {COLORS["table_header"]};
        color: {COLORS["selection_text"]};
        border: 1px solid {COLORS["border"]};
        padding: 7px;
        font-weight: bold;
    }}

    QTableCornerButton::section {{
        background-color: {COLORS["table_header"]};
        border: 1px solid {COLORS["border"]};
    }}

    QCheckBox {{
        background-color: transparent;
        color: {COLORS["text"]};
        spacing: 8px;
    }}

    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border: 2px solid {COLORS["border"]};
        background-color: {COLORS["field_bg"]};
    }}

    QCheckBox::indicator:checked {{
        background-color: {COLORS["button_bg"]};
    }}

    QSlider::groove:horizontal {{
        border: 1px solid {COLORS["border"]};
        height: 6px;
        background-color: {COLORS["panel_alt"]};
        border-radius: 3px;
    }}

    QSlider::handle:horizontal {{
        background-color: {COLORS["button_bg"]};
        border: 2px solid {COLORS["border"]};
        width: 18px;
        margin: -7px 0;
        border-radius: 9px;
    }}

    QSlider::sub-page:horizontal {{
        background-color: {COLORS["button_pressed"]};
        border-radius: 3px;
    }}

    QProgressBar {{
        background-color: {COLORS["progress_bg"]};
        color: {COLORS["text"]};
        border: 2px solid {COLORS["border"]};
        border-radius: 8px;
        text-align: center;
        min-height: 22px;
    }}

    QProgressBar::chunk {{
        background-color: {COLORS["progress_chunk"]};
        border-radius: 6px;
    }}

    QScrollBar:vertical,
    QScrollBar:horizontal {{
        background-color: {COLORS["panel_alt"]};
        border: 1px solid {COLORS["border"]};
    }}

    QScrollBar::handle:vertical,
    QScrollBar::handle:horizontal {{
        background-color: {COLORS["button_bg"]};
        border-radius: 4px;
    }}

    QDialog,
    QMessageBox {{
        background-color: {COLORS["app_bg"]};
    }}
    """


def apply_no_blue_palette(app):
    palette = QPalette()

    app_bg = QColor(COLORS["app_bg"])
    panel_bg = QColor(COLORS["panel_bg"])
    field_bg = QColor(COLORS["field_bg"])
    text = QColor(COLORS["text"])
    muted = QColor(COLORS["text_muted"])
    selection = QColor(COLORS["selection"])
    selection_text = QColor(COLORS["selection_text"])
    button_bg = QColor(COLORS["button_bg"])

    palette.setColor(QPalette.ColorRole.Window, app_bg)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, field_bg)
    palette.setColor(QPalette.ColorRole.AlternateBase, panel_bg)
    palette.setColor(QPalette.ColorRole.ToolTipBase, field_bg)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, button_bg)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, selection_text)
    palette.setColor(QPalette.ColorRole.Highlight, selection)
    palette.setColor(QPalette.ColorRole.HighlightedText, selection_text)
    palette.setColor(QPalette.ColorRole.PlaceholderText, muted)

    app.setPalette(palette)


def create_items_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,                  -- Primary key, auto-incremented unique record ID
        title TEXT NOT NULL,                                  -- Title; cannot be empty; stores the file name when importing
        body TEXT NOT NULL,                                   -- Body content; cannot be empty; stores the file content when importing
        remark TEXT                                           -- Remark; stores the content SHA256 hash when importing
    )
    """)


def ensure_minimal_schema(conn):
    row = conn.execute("""
    SELECT name                                                -- Table name
    FROM sqlite_master                                         -- SQLite internal schema table
    WHERE type = 'table'                                       -- Only look for ordinary tables
      AND name = 'items'                                       -- Only check the items table
    """).fetchone()

    if not row:
        create_items_table(conn)
        return

    columns = [
        item[1]
        for item in conn.execute("""
        PRAGMA table_info(items)                               -- Get the current column structure of items
        """).fetchall()
    ]

    expected = ["id", "title", "body", "remark"]

    if columns == expected:
        return

    conn.execute("""
    DROP TRIGGER IF EXISTS items_ai                            -- Drop the old insert trigger
    """)
    conn.execute("""
    DROP TRIGGER IF EXISTS items_ad                            -- Drop the old delete trigger
    """)
    conn.execute("""
    DROP TRIGGER IF EXISTS items_au                            -- Drop the old update trigger
    """)
    conn.execute("""
    DROP TABLE IF EXISTS items_fts                             -- Drop the old full-text search virtual table
    """)

    conn.execute("""
    ALTER TABLE items RENAME TO items_old_migration            -- Temporarily rename the old table for data migration
    """)

    create_items_table(conn)

    old_columns = set(columns)

    id_expr = "id" if "id" in old_columns else "NULL"
    title_expr = "title" if "title" in old_columns else "''"
    body_expr = "body" if "body" in old_columns else "''"
    remark_expr = "remark" if "remark" in old_columns else "''"

    conn.execute(f"""
    INSERT INTO items (
        id,                                                     -- Keep the original ID
        title,                                                  -- Keep the title
        body,                                                   -- Keep the body
        remark                                                  -- Keep the remark
    )
    SELECT
        {id_expr},                                              -- Old table ID
        {title_expr},                                           -- Old table title
        {body_expr},                                            -- Old table body
        {remark_expr}                                           -- Old table remark
    FROM items_old_migration                                    -- Migrate from the old table
    """)

    conn.execute("""
    DROP TABLE items_old_migration                              -- Drop the migrated old table
    """)


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")

        ensure_minimal_schema(conn)

        conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS items_fts
        USING fts5(
            title,                                            -- Title participates in full-text search
            body,                                             -- Body participates in full-text search
            remark,                                           -- Remark participates in full-text search; hashes can be searched
            content='items',                                  -- Link to the real data table items
            content_rowid='id',                               -- items.id corresponds to the rowid of the FTS table
            tokenize='unicode61 tokenchars _'                 -- Support Unicode and treat underscores as part of tokens for code variable search
        )
        """)

        conn.execute("""
        CREATE TRIGGER IF NOT EXISTS items_ai
        AFTER INSERT ON items                                  -- Triggered after inserting into items
        BEGIN
            INSERT INTO items_fts(rowid, title, body, remark)  -- Synchronize into the full-text search index
            VALUES (new.id, new.title, new.body, new.remark);
        END;
        """)

        conn.execute("""
        CREATE TRIGGER IF NOT EXISTS items_ad
        AFTER DELETE ON items                                  -- Triggered after deleting from items
        BEGIN
            INSERT INTO items_fts(items_fts, rowid, title, body, remark)  -- Delete old data from the full-text search index
            VALUES ('delete', old.id, old.title, old.body, old.remark);
        END;
        """)

        conn.execute("""
        CREATE TRIGGER IF NOT EXISTS items_au
        AFTER UPDATE ON items                                  -- Triggered after updating items
        BEGIN
            INSERT INTO items_fts(items_fts, rowid, title, body, remark)  -- First delete the old full-text search index entry
            VALUES ('delete', old.id, old.title, old.body, old.remark);

            INSERT INTO items_fts(rowid, title, body, remark)  -- Then write the new full-text search index entry
            VALUES (new.id, new.title, new.body, new.remark);
        END;
        """)

        conn.execute("""
        INSERT INTO items_fts(items_fts)                       -- Rebuild the full-text search index so existing data is searchable
        VALUES ('rebuild')
        """)


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def calc_sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_text_file(path):
    data = path.read_bytes()
    file_hash = calc_sha256(data)

    for encoding in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return data.decode(encoding), file_hash, encoding
        except UnicodeDecodeError:
            continue

    raise UnicodeDecodeError(
        "unknown",
        b"",
        0,
        1,
        "Unable to decode this file with utf-8, utf-8-sig, or gbk",
    )


def parse_extensions(ext_text):
    if not ext_text.strip():
        return DEFAULT_EXTENSIONS

    extensions = set()

    for item in ext_text.split(","):
        ext = item.strip().lower()

        if not ext:
            continue

        if not ext.startswith("."):
            ext = "." + ext

        extensions.add(ext)

    return extensions or DEFAULT_EXTENSIONS


def build_search_query(keyword, operator):
    words = re.findall(r"[A-Za-z0-9_\u4e00-\u9fff]+", keyword)

    if not words:
        return ""

    joiner = " AND " if operator == "AND" else " OR "

    return joiner.join(f"{word}*" for word in words)


def find_same_hash(conn, file_hash):
    return conn.execute("""
    SELECT
        id,                                                     -- Record ID
        title                                                   -- Title; usually the file name when imported
    FROM items                                                  -- Query from the main data table
    WHERE remark = ?                                            -- When importing files, the remark stores the SHA256 hash, so it can be used to find duplicate content
    ORDER BY id DESC                                            -- Newest IDs first
    LIMIT 10                                                    -- Show at most 10 rows to avoid an overly long prompt
    """, (file_hash,)).fetchall()


def insert_item_with_conn(conn, title, body, remark):
    cursor = conn.execute("""
    INSERT INTO items (
        title,                                                  -- Title
        body,                                                   -- Body content
        remark                                                  -- Remark; stores the SHA256 hash here when importing
    )
    VALUES (?, ?, ?)                                            -- Use parameter binding to prevent quotes, line breaks, or code symbols from breaking SQL
    """, (title, body, remark))

    return cursor.lastrowid


def safe_filename(name, item_id):
    cleaned = str(name).strip()

    for char in '<>:"/\\|?*\n\r\t':
        cleaned = cleaned.replace(char, "_")

    cleaned = cleaned.strip(" .")

    if not cleaned:
        cleaned = f"item_{item_id}"

    if cleaned in {".", ".."}:
        cleaned = f"item_{item_id}"

    return cleaned


def make_unique_output_path(directory, filename, item_id):
    base_path = directory / filename

    if not base_path.exists():
        return base_path

    candidate = directory / f"{filename}_{item_id}"

    if not candidate.exists():
        return candidate

    index = 1

    while True:
        candidate = directory / f"{filename}_{item_id}_{index}"

        if not candidate.exists():
            return candidate

        index += 1


class QueryWorker(QThread):
    finished_ok = pyqtSignal(list, str)
    failed = pyqtSignal(str)

    def __init__(self, mode, keyword="", operator="OR", parent=None):
        super().__init__(parent)
        self.mode = mode
        self.keyword = keyword
        self.operator = operator

    def run(self):
        try:
            if self.mode == "all":
                rows = self.load_all()
                self.finished_ok.emit(rows, f"Loaded: {len(rows)} records")
            else:
                rows, fts_query = self.search()
                self.finished_ok.emit(rows, f"Search completed: {len(rows)} records; FTS: {fts_query or self.keyword}")
        except Exception as e:
            self.failed.emit(str(e))

    def load_all(self):
        with get_connection() as conn:
            return conn.execute("""
            SELECT
                id,                                             -- Record ID
                title,                                          -- Title
                substr(replace(IFNULL(remark, ''), char(10), ' '), 1, 120) AS remark_preview -- Remark preview
            FROM items                                          -- Query from the main data table
            ORDER BY id DESC                                    -- Newest IDs first
            """).fetchall()

    def search(self):
        fts_query = build_search_query(self.keyword, self.operator)
        results = []
        seen_ids = set()

        with get_connection() as conn:
            if fts_query:
                try:
                    rows = conn.execute("""
                    SELECT
                        i.id,                                   -- Record ID
                        i.title,                                -- Title
                        substr(replace(IFNULL(i.remark, ''), char(10), ' '), 1, 120) AS remark_preview -- Remark preview
                    FROM items_fts                              -- Search from the full-text search index table
                    JOIN items i ON i.id = items_fts.rowid       -- Join the main data table to get complete record information
                    WHERE items_fts MATCH ?                     -- Use the FTS5 MATCH search statement
                    ORDER BY bm25(items_fts)                    -- Sort by relevance; lower scores are more relevant
                    LIMIT 1000                                  -- Show at most 1000 rows to avoid loading too many rows into the interface at once
                    """, (fts_query,)).fetchall()

                    for row in rows:
                        results.append(row)
                        seen_ids.add(row[0])

                except sqlite3.OperationalError:
                    pass

            words = re.findall(r"[A-Za-z0-9_\u4e00-\u9fff]+", self.keyword)

            if not words:
                words = [self.keyword]

            conditions = []
            params = []

            for word in words:
                like_word = f"%{word}%"

                conditions.append("""
                (
                    title LIKE ?                                -- Title contains the keyword
                    OR body LIKE ?                              -- Body contains the keyword
                    OR remark LIKE ?                            -- Remark contains the keyword
                )
                """)

                params.extend([like_word, like_word, like_word])

            sql = f"""
            SELECT
                id,                                             -- Record ID
                title,                                          -- Title
                substr(replace(IFNULL(remark, ''), char(10), ' '), 1, 120) AS remark_preview -- Remark preview
            FROM items                                          -- Fallback search from the main data table
            WHERE {" OR ".join(conditions)}                     -- Dynamically concatenate multiple LIKE conditions
            ORDER BY id DESC                                    -- Sort fallback results by newest ID
            LIMIT 1000                                          -- Show at most 1000 rows
            """

            like_rows = conn.execute(sql, params).fetchall()

            for row in like_rows:
                if row[0] not in seen_ids:
                    results.append(row)
                    seen_ids.add(row[0])

        return results, fts_query


class FileImportWorker(QThread):
    progress = pyqtSignal(int, int, str)
    duplicate_found = pyqtSignal(str, str, list)
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, files, duplicate_action="skip", parent=None):
        super().__init__(parent)
        self.files = [Path(file) for file in files]
        self.duplicate_action = duplicate_action
        self._duplicate_event = threading.Event()
        self._duplicate_decision = False

    def set_duplicate_decision(self, should_import):
        self._duplicate_decision = should_import
        self._duplicate_event.set()

    def run(self):
        success_count = 0
        skip_count = 0
        fail_count = 0
        imported_ids = []

        try:
            total = len(self.files)

            with get_connection() as conn:
                for index, path in enumerate(self.files, start=1):
                    self.progress.emit(index, total, str(path))

                    result, new_id = self.import_one(conn, path)

                    if result == "success":
                        success_count += 1
                        imported_ids.append(new_id)
                    elif result == "skip":
                        skip_count += 1
                    else:
                        fail_count += 1

            self.finished_ok.emit({
                "success": success_count,
                "skip": skip_count,
                "fail": fail_count,
                "imported_ids": imported_ids,
            })
        except Exception as e:
            self.failed.emit(str(e))

    def import_one(self, conn, path):
        path = Path(path).expanduser()

        if not path.exists():
            print(f"Import failed: file does not exist: {path}")
            return "fail", None

        if not path.is_file():
            print(f"Import failed: not a file: {path}")
            return "fail", None

        try:
            body, file_hash, encoding = read_text_file(path)
        except Exception as e:
            print(f"Import failed: {path}: {e}")
            return "fail", None

        if not body.strip():
            print(f"Import skipped: empty text content: {path}")
            return "skip", None

        same_hash_rows = find_same_hash(conn, file_hash)

        if same_hash_rows:
            if self.duplicate_action == "skip":
                return "skip", None

            if self.duplicate_action == "ask":
                self._duplicate_event.clear()
                self._duplicate_decision = False
                self.duplicate_found.emit(str(path), file_hash, same_hash_rows)
                self._duplicate_event.wait()

                if not self._duplicate_decision:
                    return "skip", None

        title = path.name                                      # When importing a file, the title is the file name
        remark = ""                                           # When importing a file, the remark is left empty
        new_id = insert_item_with_conn(conn, title, body, remark)

        return "success", new_id


class ExportWorker(QThread):
    progress = pyqtSignal(int, int, str)
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, item_ids, output_directory, parent=None):
        super().__init__(parent)
        self.item_ids = list(item_ids)
        self.output_directory = Path(output_directory)

    def run(self):
        success_count = 0
        fail_count = 0

        try:
            self.output_directory.mkdir(parents=True, exist_ok=True)

            total = len(self.item_ids)

            with get_connection() as conn:
                for index, item_id in enumerate(self.item_ids, start=1):
                    self.progress.emit(index, total, f"ID={item_id}")

                    row = conn.execute("""
                    SELECT
                        id,                                     -- Record ID
                        title,                                  -- Title; used as the file name when exporting
                        body,                                   -- Body; used as the file content when exporting
                        remark                                  -- Remark; appended to the end of the file when exporting
                    FROM items                                  -- Read from the main data table
                    WHERE id = ?                                -- Read precisely by ID
                    """, (item_id,)).fetchone()

                    if not row:
                        fail_count += 1
                        continue

                    record_id, title, body, remark = row
                    filename = safe_filename(title, record_id)
                    output_path = make_unique_output_path(self.output_directory, filename, record_id)

                    content = body or ""

                    if remark:
                        content += "\n\n" if not content.endswith("\n") else "\n"
                        content += "Remark:\n"
                        content += remark

                    output_path.write_text(content, encoding="utf-8")
                    success_count += 1

            self.finished_ok.emit({
                "success": success_count,
                "fail": fail_count,
                "directory": str(self.output_directory),
            })
        except Exception as e:
            self.failed.emit(str(e))


class ItemDialog(QDialog):
    def __init__(self, title, item=None, read_only=False, parent=None):
        super().__init__(parent)

        self.setWindowTitle(title)
        self.resize(980, 760)
        self.read_only = read_only
        self.remark_visible = False

        self.title_input = QLineEdit()
        self.title_input.setFixedHeight(36)
        self.title_input.setPlaceholderText("Title")
        self.title_input.setToolTip("The full title is stored in the database. If it is long, move left or right inside the input box to view it.")

        self.body_input = QPlainTextEdit()
        self.body_input.setObjectName("bodyTextEdit")
        self.body_input.setPlaceholderText("Body content")

        self.remark_toggle_button = QPushButton("Remark")
        self.remark_toggle_button.setObjectName("remarkToggleButton")
        self.remark_toggle_button.clicked.connect(self.toggle_remark)

        self.remark_input = QPlainTextEdit()
        self.remark_input.setObjectName("remarkTextEdit")
        self.remark_input.setMaximumHeight(76)
        self.remark_input.setPlaceholderText("Remark")
        self.remark_input.setVisible(False)

        if item:
            self.title_input.setText(item.get("title", ""))
            self.body_input.setPlainText(item.get("body", ""))
            self.remark_input.setPlainText(item.get("remark", "") or "")

        self.title_input.setReadOnly(read_only)
        self.body_input.setReadOnly(read_only)
        self.remark_input.setReadOnly(read_only)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(8)

        main_layout.addWidget(QLabel("Title:"))
        main_layout.addWidget(self.title_input)
        main_layout.addWidget(QLabel("Body:"))
        main_layout.addWidget(self.body_input, 1)
        main_layout.addWidget(self.remark_input)

        remark_button_row = QHBoxLayout()
        remark_button_row.addStretch(1)
        remark_button_row.addWidget(self.remark_toggle_button)
        main_layout.addLayout(remark_button_row)

        button_layout = QHBoxLayout()
        button_layout.addStretch(1)

        if not read_only:
            ok_button = QPushButton("Save")
            ok_button.clicked.connect(self.accept)
            button_layout.addWidget(ok_button)

        close_button = QPushButton("Close" if read_only else "Cancel")
        close_button.setObjectName("dangerButton")
        close_button.clicked.connect(self.reject)
        button_layout.addWidget(close_button)

        main_layout.addLayout(button_layout)

    def toggle_remark(self):
        self.remark_visible = not self.remark_visible
        self.remark_input.setVisible(self.remark_visible)
        self.remark_toggle_button.setText("Hide" if self.remark_visible else "Remark")

    def values(self):
        return {
            "title": self.title_input.text().strip(),
            "body": self.body_input.toPlainText(),
            "remark": self.remark_input.toPlainText(),
        }


class ImportDirectoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Import directory")
        self.resize(760, 250)

        self.path_input = QLineEdit()
        self.ext_input = QLineEdit(".py,.txt,.json,.sql,.md,.yaml,.yml")
        self.recursive_checkbox = QCheckBox("Recursively import subdirectories")

        self.duplicate_combo = QComboBox()
        self.duplicate_combo.addItem("Skip files with the same hash", "skip")
        self.duplicate_combo.addItem("Still import as a new record", "import")

        browse_button = QPushButton("Choose directory")
        browse_button.clicked.connect(self.choose_directory)

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_input, 1)
        path_layout.addWidget(browse_button)

        form = QFormLayout()
        form.addRow("Directory path:", path_layout)
        form.addRow("Extensions:", self.ext_input)
        form.addRow("Subdirectories:", self.recursive_checkbox)
        form.addRow("Duplicate content:", self.duplicate_combo)

        ok_button = QPushButton("Start import")
        ok_button.clicked.connect(self.accept)

        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("dangerButton")
        cancel_button.clicked.connect(self.reject)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(ok_button)
        buttons.addWidget(cancel_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addLayout(form)
        layout.addLayout(buttons)

    def choose_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Choose directory")

        if directory:
            self.path_input.setText(directory)

    def values(self):
        return {
            "directory": self.path_input.text().strip(),
            "extensions": parse_extensions(self.ext_input.text()),
            "recursive": self.recursive_checkbox.isChecked(),
            "duplicate_action": self.duplicate_combo.currentData(),
        }


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.current_id = None
        self.query_worker = None
        self.import_worker = None
        self.export_worker = None
        self.body_font_size = DEFAULT_BODY_FONT_SIZE

        self.setWindowTitle("SQLite Text / Code Manager")
        self.resize(1380, 840)
        self.setMinimumSize(1120, 700)

        root = QWidget()
        self.setCentralWidget(root)

        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(12, 12, 12, 10)
        main_layout.setSpacing(10)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search title, body, remark, or hash")
        self.search_input.returnPressed.connect(self.search_items_async)

        self.search_mode = QComboBox()
        self.search_mode.addItem("Loose search", "OR")
        self.search_mode.addItem("Exact search", "AND")
        self.search_mode.setFixedWidth(120)

        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_items_async)

        self.show_all_button = QPushButton("Show all")
        self.show_all_button.clicked.connect(self.load_all_items_async)

        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self.open_add_dialog)

        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self.open_edit_dialog)

        self.delete_button = QPushButton("Delete")
        self.delete_button.setObjectName("dangerButton")
        self.delete_button.clicked.connect(self.delete_item)

        self.export_button = QPushButton("Export selected")
        self.export_button.clicked.connect(self.export_selected_items)

        self.import_file_button = QPushButton("Import file")
        self.import_file_button.clicked.connect(self.import_single_file)

        self.import_directory_button = QPushButton("Import directory")
        self.import_directory_button.clicked.connect(self.import_directory)

        self.font_slider = QSlider(Qt.Orientation.Horizontal)
        self.font_slider.setMinimum(10)
        self.font_slider.setMaximum(28)
        self.font_slider.setValue(self.body_font_size)
        self.font_slider.setFixedWidth(120)
        self.font_slider.valueChanged.connect(self.change_font_size)

        toolbar.addWidget(self.search_input, 1)
        toolbar.addWidget(self.search_mode)
        toolbar.addWidget(self.search_button)
        toolbar.addWidget(self.show_all_button)
        toolbar.addSpacing(8)
        toolbar.addWidget(self.add_button)
        toolbar.addWidget(self.edit_button)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.export_button)
        toolbar.addSpacing(8)
        toolbar.addWidget(self.import_file_button)
        toolbar.addWidget(self.import_directory_button)
        toolbar.addSpacing(8)
        toolbar.addWidget(self.font_slider)

        main_layout.addLayout(toolbar)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["ID", "Title", "Remark"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(lambda _: self.open_view_dialog())

        self.select_all_shortcut = QShortcut(QKeySequence("Ctrl+A"), self.table)
        self.select_all_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.select_all_shortcut.activated.connect(self.table.selectAll)

        self.invert_selection_shortcut = QShortcut(QKeySequence("Ctrl+D"), self.table)
        self.invert_selection_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.invert_selection_shortcut.activated.connect(self.invert_table_selection)

        QApplication.instance().installEventFilter(self)

        main_layout.addWidget(self.table, 1)

        bottom = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("mutedLabel")

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedWidth(360)

        bottom.addWidget(self.status_label, 1)
        bottom.addWidget(self.progress_bar)

        main_layout.addLayout(bottom)

        self.load_all_items_async()

    def eventFilter(self, source, event):
        if event.type() == QEvent.Type.Wheel and event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()

            if delta > 0:
                self.change_font_size(min(28, self.body_font_size + 1))
            elif delta < 0:
                self.change_font_size(max(10, self.body_font_size - 1))

            return True

        return super().eventFilter(source, event)

    def change_font_size(self, value):
        value = max(10, min(28, int(value)))

        if value == self.body_font_size:
            return

        self.body_font_size = value
        self.font_slider.blockSignals(True)
        self.font_slider.setValue(value)
        self.font_slider.blockSignals(False)
        QApplication.instance().setStyleSheet(build_style(value))

    def invert_table_selection(self):
        row_count = self.table.rowCount()

        if row_count == 0:
            return

        selected_rows = {
            index.row()
            for index in self.table.selectionModel().selectedRows()
        }

        self.table.blockSignals(True)
        self.table.clearSelection()

        for row in range(row_count):
            if row not in selected_rows:
                self.table.selectRow(row)

        self.table.blockSignals(False)
        self.on_selection_changed()
        self.set_status("Inverted the current table selection")

    def set_status(self, message):
        self.status_label.setText(message)

    def show_info(self, message):
        QMessageBox.information(self, "Information", message)
        self.set_status(message)

    def show_warning(self, message):
        QMessageBox.warning(self, "Warning", message)
        self.set_status(message)

    def set_query_busy(self, busy):
        for widget in (
            self.search_input,
            self.search_mode,
            self.search_button,
            self.show_all_button,
        ):
            widget.setDisabled(busy)

        if busy:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(False)

    def set_import_busy(self, busy):
        self.import_file_button.setDisabled(busy)
        self.import_directory_button.setDisabled(busy)

        if busy:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(False)

    def set_export_busy(self, busy):
        self.export_button.setDisabled(busy)

        if busy:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(False)

    def on_selection_changed(self):
        selected_ids = self.selected_ids(show_warning=False)
        self.current_id = selected_ids[0] if len(selected_ids) == 1 else None

    def selected_ids(self, show_warning=True):
        selected_rows = self.table.selectionModel().selectedRows(0)
        ids = []

        for index in selected_rows:
            item = self.table.item(index.row(), 0)

            if item is None:
                continue

            try:
                ids.append(int(item.text()))
            except ValueError:
                continue

        ids = sorted(set(ids))

        if show_warning and not ids:
            self.show_warning("Please select at least one record first")

        return ids

    def selected_single_id(self):
        ids = self.selected_ids()

        if not ids:
            return None

        if len(ids) > 1:
            self.show_warning("Please select exactly one record")
            return None

        return ids[0]

    def fetch_item(self, item_id):
        with get_connection() as conn:
            row = conn.execute("""
            SELECT
                id,                                             -- Record ID
                title,                                          -- Title
                body,                                           -- Full body
                remark                                          -- Full remark
            FROM items                                          -- Query from the main data table
            WHERE id = ?                                        -- Query precisely by ID
            """, (item_id,)).fetchone()

        if not row:
            return None

        return {
            "id": row[0],
            "title": row[1],
            "body": row[2],
            "remark": row[3] or "",
        }

    def open_add_dialog(self):
        dialog = ItemDialog("Add record", parent=self)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        values = dialog.values()

        if not values["title"]:
            self.show_warning("Title cannot be empty")
            return

        if not values["body"].strip():
            self.show_warning("Body cannot be empty")
            return

        with get_connection() as conn:
            new_id = insert_item_with_conn(conn, values["title"], values["body"], values["remark"])

        self.load_all_items_async()
        self.show_info(f"Added successfully, ID = {new_id}")

    def open_view_dialog(self):
        item_id = self.selected_single_id()

        if item_id is None:
            return

        item = self.fetch_item(item_id)

        if not item:
            self.show_warning("Record not found")
            return

        dialog = ItemDialog(f"View record: ID {item_id}", item=item, read_only=True, parent=self)
        dialog.exec()

    def open_edit_dialog(self):
        item_id = self.selected_single_id()

        if item_id is None:
            return

        item = self.fetch_item(item_id)

        if not item:
            self.show_warning("Record not found")
            return

        dialog = ItemDialog(f"Edit record: ID {item_id}", item=item, read_only=False, parent=self)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        values = dialog.values()

        if not values["title"]:
            self.show_warning("Title cannot be empty")
            return

        if not values["body"].strip():
            self.show_warning("Body cannot be empty")
            return

        with get_connection() as conn:
            conn.execute("""
            UPDATE items                                        -- Update the main data table
            SET
                title = ?,                                      -- Update title
                body = ?,                                       -- Update body
                remark = ?                                      -- Update remark
            WHERE id = ?                                        -- Update only the record with the specified ID
            """, (values["title"], values["body"], values["remark"], item_id))

        self.load_all_items_async()
        self.show_info(f"Updated successfully, ID = {item_id}")

    def delete_item(self):
        item_id = self.selected_single_id()

        if item_id is None:
            return

        item = self.fetch_item(item_id)

        if not item:
            self.show_warning("Record not found")
            return

        answer = QMessageBox.question(
            self,
            "Confirm delete",
            f"Delete \"{item['title']}\"?\n\nID = {item_id}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            self.set_status("Delete canceled")
            return

        with get_connection() as conn:
            conn.execute("""
            DELETE FROM items                                   -- Delete the record from the main data table
            WHERE id = ?                                        -- Delete only the record with the specified ID
            """, (item_id,))

        self.current_id = None
        self.load_all_items_async()
        self.show_info("Deleted successfully")

    def load_all_items_async(self):
        if self.query_worker and self.query_worker.isRunning():
            self.show_warning("The current query has not finished yet")
            return

        self.set_query_busy(True)
        self.set_status("Loading...")

        self.query_worker = QueryWorker(mode="all")
        self.query_worker.finished_ok.connect(self.on_query_finished)
        self.query_worker.failed.connect(self.on_query_failed)
        self.query_worker.start()

    def search_items_async(self):
        if self.query_worker and self.query_worker.isRunning():
            self.show_warning("The current query has not finished yet")
            return

        keyword = self.search_input.text().strip()

        if not keyword:
            self.load_all_items_async()
            return

        self.set_query_busy(True)
        self.set_status("Searching...")

        self.query_worker = QueryWorker(
            mode="search",
            keyword=keyword,
            operator=self.search_mode.currentData(),
        )
        self.query_worker.finished_ok.connect(self.on_query_finished)
        self.query_worker.failed.connect(self.on_query_failed)
        self.query_worker.start()

    def on_query_finished(self, rows, message):
        self.fill_table(rows)
        self.set_query_busy(False)
        self.set_status(message)

    def on_query_failed(self, message):
        self.set_query_busy(False)
        self.show_warning(f"Query failed: {message}")

    def fill_table(self, rows):
        self.table.blockSignals(True)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        for row_data in rows:
            row_index = self.table.rowCount()
            self.table.insertRow(row_index)

            for column_index, value in enumerate(row_data):
                item = QTableWidgetItem("" if value is None else str(value))
                self.table.setItem(row_index, column_index, item)

        self.table.setSortingEnabled(True)
        self.table.blockSignals(False)
        self.current_id = None

    def import_single_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose a file to import",
            "",
            "Text files (*.py *.txt *.json *.sql *.md *.yaml *.yml);;All files (*)",
        )

        if not file_path:
            return

        self.start_import_worker([Path(file_path)], duplicate_action="ask")

    def import_directory(self):
        dialog = ImportDirectoryDialog(self)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        options = dialog.values()
        directory = Path(options["directory"]).expanduser()

        if not directory.exists():
            self.show_warning("Directory does not exist")
            return

        if not directory.is_dir():
            self.show_warning("This is not a directory")
            return

        extensions = options["extensions"]

        if options["recursive"]:
            files = [
                file
                for file in directory.rglob("*")
                if file.is_file() and file.suffix.lower() in extensions
            ]
        else:
            files = [
                file
                for file in directory.iterdir()
                if file.is_file() and file.suffix.lower() in extensions
            ]

        files.sort(key=lambda p: str(p).lower())

        if not files:
            self.show_warning("No matching files found")
            return

        answer = QMessageBox.question(
            self,
            "Confirm import",
            f"About to import {len(files)} files. Start?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )

        if answer != QMessageBox.StandardButton.Yes:
            self.set_status("Import canceled")
            return

        self.start_import_worker(files, duplicate_action=options["duplicate_action"])

    def start_import_worker(self, files, duplicate_action):
        if self.import_worker and self.import_worker.isRunning():
            self.show_warning("The current import task has not finished yet")
            return

        self.set_import_busy(True)
        self.set_status("Importing...")

        self.import_worker = FileImportWorker(files, duplicate_action=duplicate_action)
        self.import_worker.progress.connect(self.on_import_progress)
        self.import_worker.duplicate_found.connect(self.on_duplicate_found)
        self.import_worker.finished_ok.connect(self.on_import_finished)
        self.import_worker.failed.connect(self.on_import_failed)
        self.import_worker.start()

    def on_import_progress(self, current, total, path):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.set_status(f"Importing {current}/{total}: {path}")

    def on_duplicate_found(self, file_path, file_hash, same_hash_rows):
        details = "\n".join(
            f"ID={row[0]}, title={row[1]}"
            for row in same_hash_rows
        )

        answer = QMessageBox.question(
            self,
            "Same hash found",
            f"The current file may be a duplicate or renamed file:\n{file_path}\n\nHash:\n{file_hash}\n\nExisting records:\n{details}\n\nImport it as a new record anyway?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        self.import_worker.set_duplicate_decision(answer == QMessageBox.StandardButton.Yes)

    def on_import_finished(self, summary):
        self.set_import_busy(False)

        if not (self.query_worker and self.query_worker.isRunning()):
            self.load_all_items_async()

        self.show_info(
            f"Import completed: succeeded {summary['success']}, skipped {summary['skip']}, failed {summary['fail']}"
        )

    def on_import_failed(self, message):
        self.set_import_busy(False)
        self.show_warning(f"Import failed: {message}")

    def export_selected_items(self):
        ids = self.selected_ids()

        if not ids:
            return

        directory = QFileDialog.getExistingDirectory(self, "Choose export directory")

        if not directory:
            return

        self.start_export_worker(ids, directory)

    def start_export_worker(self, ids, directory):
        if self.export_worker and self.export_worker.isRunning():
            self.show_warning("The current export task has not finished yet")
            return

        self.set_export_busy(True)
        self.set_status("Exporting...")

        self.export_worker = ExportWorker(ids, directory)
        self.export_worker.progress.connect(self.on_export_progress)
        self.export_worker.finished_ok.connect(self.on_export_finished)
        self.export_worker.failed.connect(self.on_export_failed)
        self.export_worker.start()

    def on_export_progress(self, current, total, info):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.set_status(f"Exporting {current}/{total}: {info}")

    def on_export_finished(self, summary):
        self.set_export_busy(False)
        self.show_info(
            f"Export completed: succeeded {summary['success']}, failed {summary['fail']}\nDirectory: {summary['directory']}"
        )

    def on_export_failed(self, message):
        self.set_export_busy(False)
        self.show_warning(f"Export failed: {message}")

    def closeEvent(self, event):
        if self.query_worker and self.query_worker.isRunning():
            self.show_warning("A query task is still running. Please close the window later.")
            event.ignore()
            return

        if self.import_worker and self.import_worker.isRunning():
            answer = QMessageBox.question(
                self,
                "Import is still running",
                "An import task is still running. Force close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        if self.export_worker and self.export_worker.isRunning():
            answer = QMessageBox.question(
                self,
                "Export is still running",
                "An export task is still running. Force close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        event.accept()

def main():
    init_db()
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    apply_no_blue_palette(app)
    app.setStyleSheet(build_style(DEFAULT_BODY_FONT_SIZE))
    window = MainWindow()
    window.show()
    return app.exec()
if __name__ == "__main__":
    raise SystemExit(main())
