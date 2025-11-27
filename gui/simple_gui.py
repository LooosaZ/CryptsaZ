"""
Deprecated PySimpleGUI prototype for CryptsaZ.

This file is kept for reference only. During development we used
PySimpleGUI as a quick prototype, but the project has migrated to a
Tkinter-based GUI (`gui/tk_gui.py`) due to licensing and distribution
concerns with PySimpleGUI.

If you are reading this file to learn the GUI flow, prefer the
`gui/tk_gui.py` implementation. Do not rely on this file for production
work — it may be removed in future releases.

Simple PySimpleGUI front-end for CryptsaZ core functions.

This file provides a small GUI for symmetric encryption/decryption,
asymmetric encryption, and RSA key generation using the wrappers in
`gui.core_api`.
"""

import os
import threading
import sys
import traceback

try:
    import PySimpleGUI as sg
except Exception:
    print("PySimpleGUI not installed. Install with: pip install PySimpleGUI")
    sys.exit(1)

from gui import core_api

sg.theme('DarkBlue14')

ALGORITHMS = ['AES-128', 'AES-256', 'TripleDES', 'ChaCha20']


def make_layout():
    tab_sym = sg.Tab('Symmetric', [
        [sg.Text('Input file'), sg.Input(key='-INFILE-'), sg.FileBrowse()],
        [sg.Text('Algorithm'), sg.Combo(ALGORITHMS, default_value='AES-256', key='-ALGO-')],
        [sg.Radio('Generate key', 'keytype', default=True, key='-KEY_GEN-'),
         sg.Radio('Custom key (hex)', 'keytype', key='-KEY_CUSTOM-')],
    [sg.Input(key='-CUSTOM_KEY-', size=(60, 1)), sg.Button('Generate Symmetric Key', key='-SYM_GEN_KEY-'), sg.Button('Copy Key', key='-SYM_COPY_KEY-')],
        [sg.Text('Output folder (optional)'), sg.Input(key='-OUTDIR-'), sg.FolderBrowse()],
        [sg.Button('Encrypt', key='-SYM_ENCRYPT-'), sg.Button('Decrypt', key='-SYM_DECRYPT-')],
        [sg.ProgressBar(1, orientation='h', size=(40, 20), key='-PROG-')],
        [sg.Multiline(key='-LOG-', size=(80, 10), autoscroll=True, disabled=True)]
    ])

    tab_asy = sg.Tab('Asymmetric', [
        [sg.Text('Input file'), sg.Input(key='-ASY_INFILE-'), sg.FileBrowse()],
        [sg.Text('Public key (.pem)'), sg.Input(key='-ASY_PUB-'), sg.FileBrowse(file_types=(('PEM', '*.pem'),))],
        [sg.Text('Private key (.pem)'), sg.Input(key='-ASY_PRIV-'), sg.FileBrowse(file_types=(('PEM', '*.pem'),))],
        [sg.Text('Output folder (optional)'), sg.Input(key='-ASY_OUT-'), sg.FolderBrowse()],
        [sg.Button('Encrypt (RSA)', key='-ASY_ENCRYPT-'), sg.Button('Decrypt (RSA)', key='-ASY_DECRYPT-')],
        [sg.Multiline(key='-ASY_LOG-', size=(80, 10), autoscroll=True, disabled=True)]
    ])

    tab_keys = sg.Tab('Keys', [
        [sg.Text('RSA Key Generation')],
        [sg.Text('Output folder (optional)'), sg.Input(key='-KEY_OUT-'), sg.FolderBrowse()],
        [sg.Button('Generate RSA Keys', key='-GEN_KEYS-')],
        [sg.Multiline(key='-KEYS_LOG-', size=(80, 10), autoscroll=True, disabled=True)]
    ])

    layout = [
        [sg.Text('CryptsaZ - Simple GUI Prototype', font=('Any', 16), justification='center', expand_x=True)],
        [sg.TabGroup([[tab_sym, tab_asy, tab_keys]])]
    ]
    return layout


def log(window, win_key, text):
    try:
        win = window[win_key]
        prev = win.get() or ''
        win.update(value=prev + text + '\n')
    except Exception:
        # window may be closed
        pass


def run_worker(window, tag, fn, *args, **kwargs):
    def _target():
        try:
            res = fn(*args, **kwargs)
        except Exception:
            res = {'success': False, 'error': 'exception', 'trace': traceback.format_exc()}
        window.write_event_value('-TASK_DONE-', (tag, res))

    threading.Thread(target=_target, daemon=True).start()


def run_encrypt_symmetric(window, values):
    infile = values.get('-INFILE-')
    algo = values.get('-ALGO-')
    outdir = values.get('-OUTDIR-') or None
    if not infile or not os.path.exists(infile):
        log(window, '-LOG-', 'Input file not selected or not found.')
        return
    if values.get('-KEY_CUSTOM-'):
        key_hex = values.get('-CUSTOM_KEY-', '').strip()
        try:
            key = bytes.fromhex(key_hex)
        except Exception:
            log(window, '-LOG-', 'Custom key is not valid hex.')
            return
    else:
        key = None

    log(window, '-LOG-', f'Starting symmetric encryption: {infile} -> {algo}')
    window['-PROG-'].update_bar(1)
    run_worker(window, 'sym_enc', core_api.symmetric_encrypt, infile, algo, key, outdir)


def run_decrypt_symmetric(window, values):
    infile = values.get('-INFILE-')
    outdir = values.get('-OUTDIR-') or None
    if not infile or not os.path.exists(infile):
        log(window, '-LOG-', 'Input file not selected or not found.')
        return
    key_hex = None
    if values.get('-KEY_CUSTOM-'):
        key_hex = values.get('-CUSTOM_KEY-', '').strip()
    log(window, '-LOG-', f'Starting symmetric decryption: {infile}')
    run_worker(window, 'sym_dec', core_api.symmetric_decrypt, infile, key_hex, outdir)


def run_encrypt_asymmetric(window, values):
    infile = values.get('-ASY_INFILE-')
    pub = values.get('-ASY_PUB-')
    priv = values.get('-ASY_PRIV-') or None
    outdir = values.get('-ASY_OUT-') or None
    if not infile or not os.path.exists(infile):
        log(window, '-ASY_LOG-', 'Input file not selected or not found.')
        return
    if not pub or not os.path.exists(pub):
        log(window, '-ASY_LOG-', 'Public key not selected or not found.')
        return
    log(window, '-ASY_LOG-', f'Starting asymmetric encryption: {infile}')
    run_worker(window, 'asy_enc', core_api.asymmetric_encrypt, infile, pub, priv, outdir)


def run_decrypt_asymmetric(window, values):
    infile = values.get('-ASY_INFILE-')
    priv = values.get('-ASY_PRIV-')
    pub = values.get('-ASY_PUB-') or None
    outdir = values.get('-ASY_OUT-') or None
    if not infile or not os.path.exists(infile):
        log(window, '-ASY_LOG-', 'Input file not selected or not found.')
        return
    if not priv or not os.path.exists(priv):
        log(window, '-ASY_LOG-', 'Private key not selected or not found.')
        return
    log(window, '-ASY_LOG-', f'Starting asymmetric decryption: {infile}')
    run_worker(window, 'asy_dec', core_api.asymmetric_decrypt, infile, priv, pub, outdir)


def run_generate_keys(window, values):
    outdir = values.get('-KEY_OUT-') or None
    log(window, '-KEYS_LOG-', 'Generating RSA keys...')
    run_worker(window, 'key_gen', core_api.generate_rsa_keys, outdir)


def main():
    layout = make_layout()
    window = sg.Window('CryptsaZ Prototype', layout, resizable=True, finalize=True)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, None):
            break
        if event == '-SYM_ENCRYPT-':
            confirm = sg.popup_ok_cancel('Start symmetric encryption now?', title='Confirm')
            if confirm == 'OK':
                run_encrypt_symmetric(window, values)
            else:
                log(window, '-LOG-', 'Symmetric encryption cancelled.')
        elif event == '-SYM_DECRYPT-':
            confirm = sg.popup_ok_cancel('Start symmetric decryption now?', title='Confirm')
            if confirm == 'OK':
                run_decrypt_symmetric(window, values)
            else:
                log(window, '-LOG-', 'Symmetric decryption cancelled.')
        elif event == '-SYM_GEN_KEY-':
            # Generate a symmetric key and populate the custom key field
            algo = values.get('-ALGO-') or 'AES-256'
            outdir = values.get('-OUTDIR-') or None
            log(window, '-LOG-', f'Generating symmetric key for {algo}...')
            # call synchronously since it's quick
            res = core_api.generate_symmetric_key(algo, output_dir=None)
            if res.get('success'):
                key_hex = res.get('key_hex')
                # set into custom key field and select custom radio
                window['-CUSTOM_KEY-'].update(key_hex)
                window['-KEY_CUSTOM-'].update(True)
                log(window, '-LOG-', f'Generated key (hex): {key_hex}')
                # Ask user whether to save the key to disk
                if outdir:
                    confirm = sg.popup_yes_no(f"Save generated key to {outdir}?", title='Save key')
                    if confirm == 'Yes':
                        save_res = core_api.generate_symmetric_key(algo, output_dir=outdir)
                        if save_res.get('success') and save_res.get('file_path'):
                            log(window, '-LOG-', f'Saved key to: {save_res.get("file_path")}')
                        else:
                            log(window, '-LOG-', f'Could not save key: {save_res.get("error") or "unknown"}')
            else:
                log(window, '-LOG-', f'Error generating key: {res.get("error")}')
        elif event == '-SYM_COPY_KEY-':
            # Copy the key in the input to clipboard
            key_text = values.get('-CUSTOM_KEY-', '').strip()
            if not key_text:
                log(window, '-LOG-', 'No key to copy.')
            else:
                try:
                    sg.clipboard_set(key_text)
                    log(window, '-LOG-', 'Key copied to clipboard.')
                except Exception:
                    log(window, '-LOG-', 'Failed to copy key to clipboard.')
        elif event == '-ASY_ENCRYPT-':
            confirm = sg.popup_ok_cancel('Start asymmetric encryption now?', title='Confirm')
            if confirm == 'OK':
                run_encrypt_asymmetric(window, values)
            else:
                log(window, '-ASY_LOG-', 'Asymmetric encryption cancelled.')
        elif event == '-ASY_DECRYPT-':
            confirm = sg.popup_ok_cancel('Start asymmetric decryption now?', title='Confirm')
            if confirm == 'OK':
                run_decrypt_asymmetric(window, values)
            else:
                log(window, '-ASY_LOG-', 'Asymmetric decryption cancelled.')
        elif event == '-GEN_KEYS-':
            # Confirm before saving generated RSA keys to an output dir
            outdir = values.get('-KEY_OUT-') or None
            if outdir:
                confirm = sg.popup_yes_no(f"Generate RSA keys and save to {outdir}?", title='Generate RSA Keys')
                if confirm == 'Yes':
                    run_generate_keys(window, values)
                else:
                    log(window, '-KEYS_LOG-', 'RSA key generation cancelled by user.')
            else:
                run_generate_keys(window, values)

        elif event == '-TASK_DONE-':
            tag, res = values[event]
            if res.get('success'):
                log(window, '-LOG-', f'[done:{tag}] success: {res.get("output_file") or res.get("output_dir") or res.get("message") or "ok"}')
            else:
                log(window, '-LOG-', f'[done:{tag}] error: {res.get("error")}')
                if res.get('trace'):
                    log(window, '-LOG-', res.get('trace'))
            window['-PROG-'].update_bar(0)

    window.close()


if __name__ == '__main__':
    main()