from typing import Dict, Optional, List, Tuple
from PyQt6.QtCore import QObject, pyqtSignal, QRect, QSize, QPoint
from PyQt6.QtWidgets import QWidget, QApplication

class DecoyWindowManager(QObject):
    """
    Centralized Window Manager for the Windows 11 Decoy Desktop.
    Coordinates z-order, focus, minimize/restore, maximize, snap positioning,
    and taskbar active indicators across all decoy windows.
    """
    _instance = None

    window_state_changed = pyqtSignal(str, str)  # (app_id, action: opened|closed|minimized|restored|maximized)
    active_window_changed = pyqtSignal(str)       # (app_id)

    @classmethod
    def get_instance(cls) -> "DecoyWindowManager":
        if cls._instance is None:
            cls._instance = DecoyWindowManager()
        return cls._instance

    def __init__(self, parent=None):
        super().__init__(parent)
        self.windows: Dict[str, dict] = {}
        self.active_app_id: Optional[str] = None

    def register_window(self, app_id: str, widget: QWidget, title: str = "", icon: str = ""):
        """Registers a decoy application window with the manager."""
        self.windows[app_id] = {
            "widget": widget,
            "title": title or app_id,
            "icon": icon,
            "is_minimized": False,
            "is_maximized": False,
            "normal_geom": None
        }

    def unregister_window(self, app_id: str):
        if app_id in self.windows:
            del self.windows[app_id]
            if self.active_app_id == app_id:
                self.active_app_id = None
                self.active_window_changed.emit("")

    def get_window(self, app_id: str) -> Optional[QWidget]:
        entry = self.windows.get(app_id)
        return entry["widget"] if entry else None

    def is_open(self, app_id: str) -> bool:
        entry = self.windows.get(app_id)
        if not entry:
            return False
        return entry["widget"].isVisible()

    def is_minimized(self, app_id: str) -> bool:
        entry = self.windows.get(app_id)
        return entry.get("is_minimized", False) if entry else False

    def is_maximized(self, app_id: str) -> bool:
        entry = self.windows.get(app_id)
        return entry.get("is_maximized", False) if entry else False

    def get_open_app_ids(self) -> List[str]:
        """Returns list of app_ids that are currently open (visible or minimized)."""
        return [app_id for app_id, entry in self.windows.items() if entry["widget"].isVisible() or entry.get("is_minimized", False)]

    def bring_to_front(self, app_id: str):
        """Brings the window to the front, restores from minimize if needed, and focuses."""
        entry = self.windows.get(app_id)
        if not entry:
            return

        widget = entry["widget"]
        if not widget.isVisible():
            widget.show()
        entry["is_minimized"] = False
        widget.raise_()
        widget.activateWindow()

        self.active_app_id = app_id
        self.active_window_changed.emit(app_id)
        self.window_state_changed.emit(app_id, "opened")

    def minimize(self, app_id: str):
        """Minimizes the window to the taskbar."""
        entry = self.windows.get(app_id)
        if not entry:
            return

        widget = entry["widget"]
        widget.hide()
        entry["is_minimized"] = True

        if self.active_app_id == app_id:
            self.active_app_id = None
            self.active_window_changed.emit("")

        self.window_state_changed.emit(app_id, "minimized")

    def maximize_or_restore(self, app_id: str, parent_widget: Optional[QWidget] = None):
        """Toggles between maximized and normal window state."""
        entry = self.windows.get(app_id)
        if not entry:
            return

        widget = entry["widget"]
        if not entry["is_maximized"]:
            # Maximize
            entry["normal_geom"] = widget.geometry()
            parent = parent_widget or widget.parent()
            if parent:
                parent_rect = parent.rect()
                # Leave 48px for taskbar at bottom
                widget.setGeometry(0, 0, parent_rect.width(), parent_rect.height() - 48)
            else:
                screen = QApplication.primaryScreen()
                geom = screen.geometry() if screen else QRect(0, 0, 1920, 1080)
                widget.setGeometry(0, 0, geom.width(), geom.height() - 48)

            entry["is_maximized"] = True
            self.window_state_changed.emit(app_id, "maximized")
        else:
            # Restore
            if entry["normal_geom"]:
                widget.setGeometry(entry["normal_geom"])
            else:
                widget.resize(widget.sizeHint())
            entry["is_maximized"] = False
            self.window_state_changed.emit(app_id, "restored")

        self.bring_to_front(app_id)

    def close_window(self, app_id: str):
        """Closes the window."""
        entry = self.windows.get(app_id)
        if not entry:
            return

        widget = entry["widget"]
        widget.hide()
        entry["is_minimized"] = False

        if self.active_app_id == app_id:
            self.active_app_id = None
            self.active_window_changed.emit("")

        self.window_state_changed.emit(app_id, "closed")

    def toggle_window(self, app_id: str):
        """
        Handles taskbar click:
        - If active and visible -> minimize
        - If hidden or minimized -> bring to front
        - If visible but not active -> bring to front
        """
        entry = self.windows.get(app_id)
        if not entry:
            return

        widget = entry["widget"]
        if widget.isVisible() and self.active_app_id == app_id and not entry.get("is_minimized", False):
            self.minimize(app_id)
        else:
            self.bring_to_front(app_id)


def get_window_manager() -> DecoyWindowManager:
    return DecoyWindowManager.get_instance()
