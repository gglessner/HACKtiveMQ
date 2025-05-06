# Documentation - part of the HACKtiveMQ Suite
# Copyright (C) 2025 Garland Glessner - gglesner@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from pathlib import Path

from PySide6.QtWidgets import QWidget, QTextEdit, QVBoxLayout
from PySide6.QtGui import QTextCursor, QFont

# Define the tab label for the tab widget
TAB_LABEL = "Documentation"

class TabContent(QWidget):
    """
    Displays the contents of ../README.md in a read-only text box
    using a larger monospaced font, rendered as markdown.
    Works on Windows, macOS, and Linux.
    """

    def __init__(self) -> None:
        super().__init__()

        # ---------- read the file ----------
        module_dir = Path(__file__).resolve().parent  # .../modules
        readme = module_dir.parent / "README.md"      # one level up
        try:
            text = readme.read_text(encoding="utf-8")
        except Exception as exc:
            text = f"⚠️ Could not read {readme}:\n{exc}"

        # ---------- UI ----------
        viewer = QTextEdit()
        viewer.setReadOnly(True)
        viewer.setMarkdown(text)  # Render content as markdown
        viewer.moveCursor(QTextCursor.Start)

        # Bigger monospaced font
        font = QFont("Courier New")  # Falls back to a system monospace
        font.setPointSize(14)
        viewer.setFont(font)

        layout = QVBoxLayout(self)
        layout.addWidget(viewer)
