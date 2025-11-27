import os
import tempfile
from gui import core_api


def test_generate_symmetric_key_aes256_creates_file_and_returns_hex():
    with tempfile.TemporaryDirectory() as td:
        result = core_api.generate_symmetric_key('AES-256', output_dir=td)
        assert result.get('success') is True
        key_hex = result.get('key_hex')
        assert key_hex and isinstance(key_hex, str)
        # AES-256 = 32 bytes -> 64 hex chars
        assert len(key_hex) == 64
        file_path = result.get('file_path')
        assert file_path and os.path.exists(file_path)
        # core_api writes the key as hex text to the file. Validate contents.
        with open(file_path, 'r') as f:
            data = f.read().strip()
        # hex length for 32 bytes is 64 characters
        assert len(data) == 64
        # ensure it decodes to 32 bytes
        decoded = bytes.fromhex(data)
        assert len(decoded) == 32
import os
import tempfile

from gui import core_api


def test_generate_symmetric_key_creates_hex_and_file(tmp_path):
    # Generate a key for AES-256 and save to a temp directory
    outdir = tmp_path / "keys"
    res = core_api.generate_symmetric_key('AES-256', output_dir=str(outdir))
    assert res.get('success') is True
    key_hex = res.get('key_hex')
    assert isinstance(key_hex, str)
    # AES-256 key should be 32 bytes -> 64 hex characters
    assert len(key_hex) == 64
    # file_path should point to a file inside outdir
    file_path = res.get('file_path')
    assert file_path is not None
    assert os.path.exists(file_path)
    with open(file_path, 'r') as f:
        content = f.read().strip()
    assert content == key_hex
