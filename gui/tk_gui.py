"""Tkinter-based GUI replacement for the previous PySimpleGUI prototype.

Provides basic tabs for Symmetric, Asymmetric and Keys and mirrors features:
- Generate symmetric key (populate custom key field)
- Copy key to clipboard
- Confirm before operations
- Run long tasks in background threads and log output
"""
import os
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from gui import core_api


class CryptsaZApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('CryptsaZ')
        self.geometry('900x600')
        
        # Load theme configuration
        self.theme = self._load_theme()
        self._apply_theme()

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)

        self.sym_frame = tk.Frame(self.notebook, bg=self.theme.get("bg", "#1e1e1e"))
        self.asy_frame = tk.Frame(self.notebook, bg=self.theme.get("bg", "#1e1e1e"))
        self.keys_frame = tk.Frame(self.notebook, bg=self.theme.get("bg", "#1e1e1e"))

        self.notebook.add(self.sym_frame, text='Symmetric')
        self.notebook.add(self.asy_frame, text='Asymmetric')
        self.notebook.add(self.keys_frame, text='Keys')

        self._build_symmetric()
        self._build_asymmetric()
        self._build_keys()

    def _load_theme(self):
        """Load theme configuration from JSON file."""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'theme.json')
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get('dark_mode', {})
        except FileNotFoundError:
            # Fallback to default dark theme
            return {
                "bg": "#2c2c2c",
                "fg": "#e0e0e0",
                "button_bg": "#f84600",
                "button_fg": "#ffffff",
                "entry_bg": "#2d2d2d",
                "entry_fg": "#e0e0e0",
                "text_bg": "#252525",
                "text_fg": "#e0e0e0",
                "accent": "#f84600"
            }

    def _apply_theme(self):
        """Apply dark mode theme to the app."""
        self.configure(bg=self.theme.get("bg", "#1e1e1e"))
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook
        style.configure('TNotebook', background=self.theme.get("bg", "#1e1e1e"), 
                       borderwidth=0)
        style.configure('TNotebook.Tab', padding=[5, 5])
        style.map('TNotebook.Tab', background=[('selected', self.theme.get("accent", "#f84600"))])
        
        # Configure labels
        style.configure('TLabel', background=self.theme.get("bg", "#1e1e1e"),
                       foreground=self.theme.get("fg", "#e0e0e0"), font=('Segoe UI', 10))
        
        # Configure entries
        style.configure('TEntry', fieldbackground=self.theme.get("entry_bg", "#2d2d2d"),
                       foreground=self.theme.get("entry_fg", "#e0e0e0"), font=('Segoe UI', 10))
        
        # Configure buttons
        style.configure('TButton', background=self.theme.get("button_bg", "#f84600"),
                       foreground=self.theme.get("button_fg", "#ffffff"), font=('Segoe UI', 10),
                       padding=[8, 6])
        style.map('TButton', background=[('active', '#ff6b35')])
        
        # Configure radio buttons and checkboxes
        style.configure('TRadiobutton', background=self.theme.get("bg", "#1e1e1e"),
                       foreground=self.theme.get("fg", "#e0e0e0"), font=('Segoe UI', 10))
        style.configure('TCombobox', fieldbackground=self.theme.get("entry_bg", "#2d2d2d"),
                       foreground=self.theme.get("entry_fg", "#e0e0e0"), font=('Segoe UI', 10))

    def _build_symmetric(self):
        f = self.sym_frame
        pad = 10
        
        ttk.Label(f, text='Input file').grid(row=0, column=0, sticky='w', padx=pad, pady=pad)
        self.sym_in = ttk.Entry(f, width=70)
        self.sym_in.grid(row=0, column=1, padx=pad, pady=pad)
        # move browse to right column so all orange action buttons align vertically
        ttk.Button(f, text='Browse', command=self._browse_sym_in).grid(row=0, column=3, sticky='e', padx=pad, pady=pad)

        ttk.Label(f, text='Algorithm').grid(row=1, column=0, sticky='w', padx=pad, pady=pad)
        self.algo_var = tk.StringVar(value='AES-256')
        self.algo_combo = ttk.Combobox(f, textvariable=self.algo_var, values=['AES-128', 'AES-256', 'TripleDES', 'ChaCha20'])
        self.algo_combo.grid(row=1, column=1, sticky='w', padx=pad, pady=pad)

        ttk.Label(f, text='Key').grid(row=2, column=0, sticky='w', padx=pad, pady=pad)
        self.custom_key = tk.StringVar()
        self.key_mode = tk.StringVar(value='custom')
        ttk.Entry(f, textvariable=self.custom_key, width=70).grid(row=2, column=1, padx=pad, pady=pad)
        # create a small frame in the right column that holds both buttons (keeps spacing consistent)
        btn_frame = tk.Frame(f, bg=self.theme.get("bg", "#1e1e1e"))
        btn_frame.grid(row=2, column=3, sticky='e', padx=pad, pady=pad)
        ttk.Button(btn_frame, text='Generate Symmetric Key', command=self._generate_sym_key).pack(side='left', padx=(0,6))
        ttk.Button(btn_frame, text='Copy Key', command=self._copy_key).pack(side='left')

        ttk.Label(f, text='Output folder (optional)').grid(row=3, column=0, sticky='w', padx=pad, pady=pad)
        self.outdir_entry = ttk.Entry(f, width=70)
        self.outdir_entry.grid(row=3, column=1, padx=pad, pady=pad)
        ttk.Button(f, text='Browse', command=self._browse_outdir).grid(row=3, column=3, sticky='e', padx=pad, pady=pad)

        ttk.Button(f, text='Encrypt', command=self._confirm_sym_encrypt).grid(row=4, column=0, sticky='w', padx=pad, pady=pad)
        ttk.Button(f, text='Decrypt', command=self._confirm_sym_decrypt).grid(row=4, column=1, sticky='w', padx=pad, pady=pad)

        self.sym_log = tk.Text(f, height=15, bg=self.theme.get("text_bg", "#252525"),
                               fg=self.theme.get("text_fg", "#e0e0e0"), font=('Consolas', 9))
        self.sym_log.grid(row=5, column=0, columnspan=4, sticky='nsew', padx=pad, pady=pad)

        # layout: column 1 expands, column 3 hosts right-aligned action buttons
        f.grid_rowconfigure(5, weight=1)
        f.grid_columnconfigure(0, minsize=120)
        f.grid_columnconfigure(1, weight=1)
        f.grid_columnconfigure(2, minsize=8)
        f.grid_columnconfigure(3, minsize=220)

    def _build_asymmetric(self):
        f = self.asy_frame
        pad = 10
        
        ttk.Label(f, text='Input').grid(row=0, column=0, sticky='w', padx=pad, pady=pad)
        self.asy_in = ttk.Entry(f, width=70)
        self.asy_in.grid(row=0, column=1, padx=pad, pady=pad)
        ttk.Button(f, text='Browse', command=self._browse_asy_in).grid(row=0, column=3, sticky='e', padx=pad, pady=pad)

        ttk.Label(f, text='Public key (.pem)').grid(row=1, column=0, sticky='w', padx=pad, pady=pad)
        self.pub_entry = ttk.Entry(f, width=70)
        self.pub_entry.grid(row=1, column=1, padx=pad, pady=pad)
        ttk.Button(f, text='Browse', command=self._browse_pub).grid(row=1, column=3, sticky='e', padx=pad, pady=pad)

        ttk.Label(f, text='Private key (.pem)').grid(row=2, column=0, sticky='w', padx=pad, pady=pad)
        self.priv_entry = ttk.Entry(f, width=70)
        self.priv_entry.grid(row=2, column=1, padx=pad, pady=pad)
        ttk.Button(f, text='Browse', command=self._browse_priv).grid(row=2, column=3, sticky='e', padx=pad, pady=pad)

        ttk.Button(f, text='Encrypt (RSA)', command=self._confirm_asy_encrypt).grid(row=3, column=0, sticky='w', padx=pad, pady=pad)
        ttk.Button(f, text='Decrypt (RSA)', command=self._confirm_asy_decrypt).grid(row=3, column=1, sticky='w', padx=pad, pady=pad)

        self.asy_log = tk.Text(f, height=15, bg=self.theme.get("text_bg", "#252525"),
                               fg=self.theme.get("text_fg", "#e0e0e0"), font=('Consolas', 9))
        self.asy_log.grid(row=4, column=0, columnspan=4, sticky='nsew', padx=pad, pady=pad)
        
        # align columns same as symmetric tab
        f.grid_rowconfigure(4, weight=1)
        f.grid_columnconfigure(0, minsize=120)
        f.grid_columnconfigure(1, weight=1)
        f.grid_columnconfigure(2, minsize=8)
        f.grid_columnconfigure(3, minsize=220)

    def _build_keys(self):
        f = self.keys_frame
        pad = 10
        
        ttk.Label(f, text='RSA Key Generation      ').grid(row=0, column=1, sticky='e', padx=pad, pady=pad)
        ttk.Label(f, text='Output folder (optional)').grid(row=1, column=0, sticky='w', padx=pad, pady=pad)
        self.key_out = ttk.Entry(f, width=70)
        self.key_out.grid(row=1, column=1, padx=pad, pady=pad)
        ttk.Button(f, text='Browse', command=self._browse_key_out).grid(row=1, column=2, padx=pad, pady=pad)
        ttk.Button(f, text='Generate RSA Keys', command=self._confirm_generate_keys).grid(row=2, column=0, sticky='w', padx=pad, pady=pad)

        self.keys_log = tk.Text(f, height=15, bg=self.theme.get("text_bg", "#252525"),
                                fg=self.theme.get("text_fg", "#e0e0e0"), font=('Consolas', 9))
        self.keys_log.grid(row=3, column=0, columnspan=4, sticky='nsew', padx=pad, pady=pad)
        
        f.grid_rowconfigure(3, weight=1)
        f.grid_columnconfigure(0, minsize=120)
        f.grid_columnconfigure(1, weight=1)
        f.grid_columnconfigure(2, minsize=8)
        f.grid_columnconfigure(3, minsize=220)

    # Browse helpers
    def _browse_sym_in(self):
        """Show a small modal dialog allowing user to pick a file or a folder."""
        parent = self

        # container for the selection result
        selection = {'path': None}

        def choose_file():
            p = filedialog.askopenfilename(parent=parent)
            if p:
                selection['path'] = p
                dlg.destroy()

        def choose_folder():
            p = filedialog.askdirectory(parent=parent)
            if p:
                selection['path'] = p
                dlg.destroy()

        def cancel():
            dlg.destroy()

        # create modal dialog
        dlg = tk.Toplevel(parent)
        dlg.title('Select input')
        dlg.transient(parent)
        dlg.resizable(False, False)
        dlg.grab_set()

        ttk.Label(dlg, text='Select a file or a folder to use as input:').grid(row=0, column=0, columnspan=3, padx=12, pady=(12,6))

        ttk.Button(dlg, text='Select File', command=choose_file).grid(row=1, column=0, padx=8, pady=12)
        ttk.Button(dlg, text='Select Folder', command=choose_folder).grid(row=1, column=1, padx=8, pady=12)
        ttk.Button(dlg, text='Cancel', command=cancel).grid(row=1, column=2, padx=8, pady=12)

        # center dialog over parent
        parent.update_idletasks()
        dlg.update_idletasks()
        pw = parent.winfo_width(); ph = parent.winfo_height()
        px = parent.winfo_rootx(); py = parent.winfo_rooty()
        dw = dlg.winfo_reqwidth(); dh = dlg.winfo_reqheight()
        dlg.geometry(f"+{px + (pw-dw)//2}+{py + (ph-dh)//2}")

        parent.wait_window(dlg)

        if selection['path']:
            self.sym_in.delete(0, 'end')
            self.sym_in.insert(0, selection['path'])

    def _browse_asy_in(self):
        """Show a small modal dialog allowing user to pick a file or a folder."""
        parent = self

        # container for the selection result
        selection = {'path': None}

        def choose_file():
            p = filedialog.askopenfilename(parent=parent)
            if p:
                selection['path'] = p
                dlg.destroy()

        def choose_folder():
            p = filedialog.askdirectory(parent=parent)
            if p:
                selection['path'] = p
                dlg.destroy()

        def cancel():
            dlg.destroy()

        # create modal dialog
        dlg = tk.Toplevel(parent)
        dlg.title('Select input')
        dlg.transient(parent)
        dlg.resizable(False, False)
        dlg.grab_set()

        ttk.Label(dlg, text='Select a file or a folder to use as input:').grid(row=0, column=0, columnspan=3, padx=12, pady=(12,6))

        ttk.Button(dlg, text='Select File', command=choose_file).grid(row=1, column=0, padx=8, pady=12)
        ttk.Button(dlg, text='Select Folder', command=choose_folder).grid(row=1, column=1, padx=8, pady=12)
        ttk.Button(dlg, text='Cancel', command=cancel).grid(row=1, column=2, padx=8, pady=12)

        # center dialog over parent
        parent.update_idletasks()
        dlg.update_idletasks()
        pw = parent.winfo_width(); ph = parent.winfo_height()
        px = parent.winfo_rootx(); py = parent.winfo_rooty()
        dw = dlg.winfo_reqwidth(); dh = dlg.winfo_reqheight()
        dlg.geometry(f"+{px + (pw-dw)//2}+{py + (ph-dh)//2}")

        parent.wait_window(dlg)

        if selection['path']:
            self.asy_in.delete(0, 'end')
            self.asy_in.insert(0, selection['path'])

    def _browse_pub(self):
        p = filedialog.askopenfilename(filetypes=[('PEM', '*.pem')])
        if p:
            self.pub_entry.delete(0, 'end')
            self.pub_entry.insert(0, p)

    def _browse_priv(self):
        p = filedialog.askopenfilename(filetypes=[('PEM', '*.pem')])
        if p:
            self.priv_entry.delete(0, 'end')
            self.priv_entry.insert(0, p)

    def _browse_outdir(self):
        p = filedialog.askdirectory()
        if p:
            self.outdir_entry.delete(0, 'end')
            self.outdir_entry.insert(0, p)

    def _browse_key_out(self):
        p = filedialog.askdirectory()
        if p:
            self.key_out.delete(0, 'end')
            self.key_out.insert(0, p)

    # Actions
    def _generate_sym_key(self):
        algo = self.algo_var.get()
        self._log(self.sym_log, f'Generating symmetric key for {algo}...')
        res = core_api.generate_symmetric_key(algo, output_dir=None)
        if res.get('success'):
            key_hex = res.get('key_hex')
            self.custom_key.set(key_hex)
            self.key_mode.set('custom')
            self._log(self.sym_log, f'Generated key (hex): {key_hex}')
            outdir = self.outdir_entry.get().strip()
            if outdir:
                if messagebox.askyesno('Save key', f'Save generated key to {outdir}?'):
                    save_res = core_api.generate_symmetric_key(algo, output_dir=outdir)
                    if save_res.get('success') and save_res.get('file_path'):
                        self._log(self.sym_log, f'Saved key to: {save_res.get("file_path")}')
                    else:
                        self._log(self.sym_log, f'Could not save key: {save_res.get("error") or "unknown"}')
        else:
            self._log(self.sym_log, f'Error generating key: {res.get("error")}')

    def _copy_key(self):
        key = self.custom_key.get().strip()
        if not key:
            self._log(self.sym_log, 'No key to copy.')
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(key)
            self._log(self.sym_log, 'Key copied to clipboard.')
        except Exception:
            self._log(self.sym_log, 'Failed to copy key to clipboard.')

    def _confirm_sym_encrypt(self):
        if messagebox.askokcancel('Confirm', 'Start symmetric encryption now?'):
            threading.Thread(target=self._sym_encrypt, daemon=True).start()
        else:
            self._log(self.sym_log, 'Symmetric encryption cancelled.')

    def _confirm_sym_decrypt(self):
        if messagebox.askokcancel('Confirm', 'Start symmetric decryption now?'):
            threading.Thread(target=self._sym_decrypt, daemon=True).start()
        else:
            self._log(self.sym_log, 'Symmetric decryption cancelled.')

    def _confirm_asy_encrypt(self):
        if messagebox.askokcancel('Confirm', 'Start asymmetric encryption now?'):
            threading.Thread(target=self._asy_encrypt, daemon=True).start()
        else:
            self._log(self.asy_log, 'Asymmetric encryption cancelled.')

    def _confirm_asy_decrypt(self):
        if messagebox.askokcancel('Confirm', 'Start asymmetric decryption now?'):
            threading.Thread(target=self._asy_decrypt, daemon=True).start()
        else:
            self._log(self.asy_log, 'Asymmetric decryption cancelled.')

    def _confirm_generate_keys(self):
        outdir = self.key_out.get().strip()
        if outdir:
            if not messagebox.askyesno('Generate RSA Keys', f'Generate RSA keys and save to {outdir}?'):
                self._log(self.keys_log, 'RSA key generation cancelled by user.')
                return
        threading.Thread(target=self._generate_keys, daemon=True).start()

    # Background workers
    def _sym_encrypt(self):
        infile = self.sym_in.get().strip()
        algo = self.algo_var.get()
        key_hex = self.custom_key.get().strip() if self.key_mode.get() == 'custom' else None
        outdir = self.outdir_entry.get().strip() or None
        self._log(self.sym_log, f'Starting symmetric encryption: {infile} -> {algo}')
        
        try:
            # Check if input is a directory
            if os.path.isdir(infile):
                self._log(self.sym_log, f'Processing folder: {infile}')
                files = sorted([f for f in os.listdir(infile) if os.path.isfile(os.path.join(infile, f))])
                
                success_count = 0
                error_count = 0
                
                for filename in files:
                    filepath = os.path.join(infile, filename)
                    self._log(self.sym_log, f'Encrypting file: {filename}')
                    res = core_api.symmetric_encrypt(filepath, algo, key=bytes.fromhex(key_hex) if key_hex else None, output_dir=outdir)
                    if res.get('success'):
                        success_count += 1
                        self._log(self.sym_log, f'  ✓ {filename} encrypted')
                        if res.get('key_hex') and success_count == 1:
                            self._log(self.sym_log, f'Key (hex): {res.get("key_hex")}')
                    else:
                        error_count += 1
                        self._log(self.sym_log, f'  ✗ {filename} failed: {res.get("error") or "unknown"}')
                        if res.get('trace'):
                            self._log(self.sym_log, res.get('trace'))
                
                self._log(self.sym_log, f'Folder encryption finished. Success: {success_count}, Errors: {error_count}')
            else:
                res = core_api.symmetric_encrypt(infile, algo, key=bytes.fromhex(key_hex) if key_hex else None, output_dir=outdir)
                if res.get('success'):
                    self._log(self.sym_log, f'Encryption finished. Output: {res.get("output_file")}')
                    if res.get('key_hex'):
                        self._log(self.sym_log, f'Key (hex): {res.get("key_hex")}')
                else:
                    self._log(self.sym_log, f'Error: {res.get("error")}')
                    if res.get('trace'):
                        self._log(self.sym_log, res.get('trace'))
        except PermissionError as e:
            self._log(self.sym_log, f'Permission Denied: {str(e)}')
            self._log(self.sym_log, 'Try running the application as Administrator.')
        except Exception as e:
            self._log(self.sym_log, f'Unexpected error: {str(e)}')

    def _sym_decrypt(self):
        infile = self.sym_in.get().strip()
        key_hex = self.custom_key.get().strip() if self.key_mode.get() == 'custom' else None
        outdir = self.outdir_entry.get().strip() or None
        self._log(self.sym_log, f'Starting symmetric decryption: {infile}')
        
        try:
            # Check if input is a directory
            if os.path.isdir(infile):
                self._log(self.sym_log, f'Processing folder: {infile}')
                files = sorted([f for f in os.listdir(infile) if os.path.isfile(os.path.join(infile, f))])
                
                success_count = 0
                error_count = 0
                
                for filename in files:
                    filepath = os.path.join(infile, filename)
                    self._log(self.sym_log, f'Decrypting file: {filename}')
                    res = core_api.symmetric_decrypt(filepath, key_hex=key_hex, output_dir=outdir)
                    if res.get('success'):
                        success_count += 1
                        self._log(self.sym_log, f'  ✓ {filename} decrypted')
                    else:
                        error_count += 1
                        self._log(self.sym_log, f'  ✗ {filename} failed: {res.get("error") or "unknown"}')
                        if res.get('trace'):
                            self._log(self.sym_log, res.get('trace'))
                
                self._log(self.sym_log, f'Folder decryption finished. Success: {success_count}, Errors: {error_count}')
            else:
                res = core_api.symmetric_decrypt(infile, key_hex=key_hex, output_dir=outdir)
                if res.get('success'):
                    self._log(self.sym_log, f'Decryption finished. Output: {res.get("output_file")}')
                else:
                    self._log(self.sym_log, f'Error: {res.get("error")}')
                    if res.get('trace'):
                        self._log(self.sym_log, res.get('trace'))
        except PermissionError as e:
            self._log(self.sym_log, f'Permission Denied: {str(e)}')
            self._log(self.sym_log, 'Try running the application as Administrator.')
        except Exception as e:
            self._log(self.sym_log, f'Unexpected error: {str(e)}')

    def _asy_encrypt(self):
        infile = self.asy_in.get().strip()
        pub = self.pub_entry.get().strip()
        priv = self.priv_entry.get().strip() or None
        outdir = None
        self._log(self.asy_log, f'Starting asymmetric encryption: {infile}')
        res = core_api.asymmetric_encrypt(infile, pub, priv, output_dir=outdir)
        if res.get('success'):
            self._log(self.asy_log, f'Asymmetric encryption finished. Output dir: {res.get("output_dir")}')
        else:
            self._log(self.asy_log, f'Error: {res.get("error")}')
            if res.get('trace'):
                self._log(self.asy_log, res.get('trace'))

    def _asy_decrypt(self):
        infile = self.asy_in.get().strip()
        priv = self.priv_entry.get().strip()
        pub = self.pub_entry.get().strip() or None
        outdir = None
        self._log(self.asy_log, f'Starting asymmetric decryption: {infile}')
        try:
            # Check if input is a directory
            if os.path.isdir(infile):
                self._log(self.asy_log, f'Processing folder: {infile}')
                files = sorted(os.listdir(infile))
                # classify files
                key_files = [os.path.join(infile, f) for f in files if f.lower().endswith('.bin')]
                sig_files = [os.path.join(infile, f) for f in files if f.lower().endswith('.sig')]
                data_files = [os.path.join(infile, f) for f in files if not f.lower().endswith(('.bin', '.sig'))]

                success_count = 0
                error_count = 0

                for data_path in data_files:
                    data_name = os.path.basename(data_path)
                    # try to find matching key
                    key_path = None
                    if len(key_files) == 1:
                        key_path = key_files[0]
                    else:
                        # look for a key that contains the data filename (or same base name)
                        base = os.path.splitext(data_name)[0].lower()
                        for k in key_files:
                            kn = os.path.basename(k).lower()
                            if base in kn or kn.startswith(base):
                                key_path = k
                                break

                    # try to find matching signature
                    sig_path = None
                    if len(sig_files) == 1:
                        sig_path = sig_files[0]
                    else:
                        base = os.path.splitext(data_name)[0].lower()
                        for s in sig_files:
                            sn = os.path.basename(s).lower()
                            if base in sn or sn.startswith(base):
                                sig_path = s
                                break

                    # if no key found, log and skip to avoid passing None
                    if not key_path and not sig_path:
                        self._log(self.asy_log, f'  ✗ Skipping {data_name}: no matching key (.bin) or signature (.sig) found.')
                        error_count += 1
                        continue

                    self._log(self.asy_log, f'Decrypting file: {data_name}')
                    res = core_api.asymmetric_decrypt(data_path, key_path, priv, [pub] if pub else [], signature_path=sig_path)
                    if res.get('success'):
                        success_count += 1
                        self._log(self.asy_log, f'  ✓ {data_name} decrypted')
                    else:
                        error_count += 1
                        self._log(self.asy_log, f'  ✗ {data_name} failed: {res.get("error") or "unknown"}')
                        if res.get('trace'):
                            self._log(self.asy_log, res.get('trace'))

                self._log(self.asy_log, f'Folder decryption finished. Success: {success_count}, Errors: {error_count}')
            else:
                res = core_api.asymmetric_decrypt(infile, None, priv, [pub] if pub else [], signature_path=None)
                if res.get('success'):
                    self._log(self.asy_log, f'Asymmetric decryption finished. Output dir: {res.get("output_dir")}')
                else:
                    self._log(self.asy_log, f'Error: {res.get("error")}')
                    if res.get('trace'):
                        self._log(self.asy_log, res.get('trace'))
        except PermissionError as e:
            self._log(self.asy_log, f'Permission Denied: {str(e)}')
            self._log(self.asy_log, 'Try running the application as Administrator.')
        except Exception as e:
            self._log(self.asy_log, f'Unexpected error: {str(e)}')

    def _generate_keys(self):
        outdir = self.key_out.get().strip() or None
        self._log(self.keys_log, 'Generating RSA keys...')
        res = core_api.generate_rsa_keys(output_dir=outdir)
        if res.get('success'):
            self._log(self.keys_log, f'Generated keys: {res.get("public_key")}, {res.get("private_key")}')
        else:
            self._log(self.keys_log, f'Error: {res.get("error")}')
            if res.get('trace'):
                self._log(self.keys_log, res.get('trace'))

    def _log(self, widget, text):
        widget.insert('end', text + '\n')
        widget.see('end')


def run():
    app = CryptsaZApp()
    app.mainloop()


if __name__ == '__main__':
    run()
