"""Double-click launcher — opens the desktop interface, with no console.

A .pyw runs under pythonw.exe, which has no console window. That is exactly
right for the GUI, and exactly wrong for the terminal dashboard, so this file
is now the graphical one. Use `python run.py` for the terminal version.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def main() -> int:
    try:
        from sysup.config import Settings
        from sysup.gui import main as gui_main
    except Exception as error:                      # a missing dependency
        import tkinter.messagebox as messagebox
        messagebox.showerror(
            "System Supe-Up",
            f"Could not start:\n\n{error}\n\n"
            f"Install what it needs with:\n"
            f"    pip install -r requirements.txt")
        return 1
    return gui_main(Settings.load())


if __name__ == "__main__":
    raise SystemExit(main())
