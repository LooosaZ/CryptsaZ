"""Thin wrappers around the existing CLI modules to provide a simple API for a GUI.
These wrappers call the existing modules (encryptSy, decryptSy, keyGenerator, etc.) and
return dictionaries with structured results for the GUI to present.

Note: this file intentionally minimizes changes to existing code and doesn't refactor heavy logic.
"""
import os
import traceback
from typing import Optional

import encryptSy
import decryptSy
import encryptAsy
import decryptAsy
import keyGenerator


def symmetric_encrypt(input_path: str, algorithm: str, key: Optional[bytes] = None, output_dir: Optional[str] = None):
    try:
        # If no key provided, generate one using existing function
        if key is None:
            key = encryptSy.generateKey(algorithm)
        # Build output filename in current working dir or provided output_dir
        base = os.path.basename(input_path)
        ext = os.path.splitext(base)[1]
        output_file = os.path.splitext(base)[0] + f" ({algorithm})" + ext
        # Call existing encryptFile
        encryptSy.encryptFile(input_path, output_file, key, algorithm)
        # Move to output_dir if provided
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            dest = os.path.join(output_dir, output_file)
            try:
                import shutil
                shutil.move(output_file, dest)
                output_file = dest
            except Exception:
                pass
        return {
            'success': True,
            'output_file': output_file,
            'key_hex': key.hex(),
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}


def symmetric_decrypt(input_path: str, key_hex: Optional[str] = None, output_dir: Optional[str] = None):
    try:
        if key_hex:
            key = bytes.fromhex(key_hex)
        else:
            # Try to find -Info.txt alongside file
            info_file = os.path.splitext(input_path)[0] + "-Info.txt"
            if os.path.exists(info_file):
                with open(info_file, 'r') as f:
                    lines = f.readlines()
                    key_line = next((ln for ln in lines if ln.startswith('Key: ')), None)
                    if key_line:
                        key = bytes.fromhex(key_line.split('Key: ')[1].strip())
                    else:
                        return {'success': False, 'error': 'Key not provided and not found in info file.'}
            else:
                return {'success': False, 'error': 'Key not provided and info file not found.'}

        base = os.path.basename(input_path)
        original_ext = os.path.splitext(base)[1]
        output_name = os.path.splitext(base)[0] + '_decrypted' + original_ext
        decryptSy.decryptFile(input_path, output_name, key)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            import shutil
            shutil.move(output_name, os.path.join(output_dir, output_name))
            output_name = os.path.join(output_dir, output_name)

        return {'success': True, 'output_file': output_name}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}


def generate_symmetric_key(algorithm: str, output_dir: Optional[str] = None):
    """Generate a symmetric key for the given algorithm and optionally save it to output_dir.

    Returns: {'success': True, 'key_hex': <hex>, 'file_path': <optional saved path>} or error dict.
    """
    try:
        key = encryptSy.generateKey(algorithm)
        key_hex = key.hex()
        file_path = None
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f'symmetric_key_{algorithm}.key')
            try:
                with open(file_path, 'w') as f:
                    f.write(key_hex)
            except Exception:
                # ignore save errors but report success with key_hex
                file_path = None

        return {'success': True, 'key_hex': key_hex, 'file_path': file_path}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}


def generate_rsa_keys(output_dir: Optional[str] = None):
    try:
        # keyGenerator.generateRsaKeys writes into assets by default; call it and then report paths
        keyGenerator.generateRsaKeys()
        private = os.path.join('assets', 'keys', 'myKeys', 'privateKey.pem')
        public = os.path.join('assets', 'keys', 'myKeys', 'publicKey.pem')
        # Optionally copy to output_dir
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            import shutil
            shutil.copy(private, os.path.join(output_dir, 'privateKey.pem'))
            shutil.copy(public, os.path.join(output_dir, 'publicKey.pem'))
        return {'success': True, 'private_key': private, 'public_key': public}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}


def asymmetric_encrypt(input_path: str, public_key_path: str, private_key_path: str, output_dir: Optional[str] = None):
    try:
        encryptAsy.main(filePath=input_path, publicKeyPath=public_key_path, privateKeyPath=private_key_path)
        # encryptAsy writes output to Desktop/<name> (RSA). Attempt to find that folder
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        folder = os.path.splitext(os.path.basename(input_path))[0] + ' (RSA)'
        folder_path = os.path.join(desktop, folder)
        return {'success': True, 'output_dir': folder_path}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}


def asymmetric_decrypt(encrypted_file_path: str, encrypted_key_path: Optional[str], private_key_path: str, public_key_paths: list, signature_path: Optional[str] = None):
    try:
        decryptAsy.main(encrypted_file_path, encrypted_key_path, private_key_path, public_key_paths, signature_path)
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        folder = os.path.splitext(os.path.basename(encrypted_file_path))[0]
        folder_path = os.path.join(desktop, folder)
        return {'success': True, 'output_dir': folder_path}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}
