"""Small launcher for the Tkinter GUI (gui/tk_gui.py).

Usage: python run_gui.py

This file intentionally keeps startup minimal and robust. It imports the
Tkinter application and starts the mainloop. Previously this file attempted
to call `app.run()` which does not exist on a Tk() instance and raised
AttributeError; this version uses the correct entrypoint.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

def main():
    try:
        # gui.tk_gui exposes either a `run()` helper or a CryptsaZApp class.
        # Prefer the helper if present; otherwise instantiate and call mainloop().
        from gui import tk_gui as _tk_gui
    except Exception as e:
        print("Failed to import the Tkinter GUI (ensure tkinter and other deps are installed).")
        print(e)
        sys.exit(1)

    if hasattr(_tk_gui, 'run'):
        _tk_gui.run()
        return

    # Fall back to creating the app and starting mainloop
    try:
        CryptsaZApp = getattr(_tk_gui, 'CryptsaZApp')
        app = CryptsaZApp()
        app.mainloop()
    except Exception as e:
        print('Failed to start the GUI application:')
        raise


if __name__ == '__main__':
    main()
