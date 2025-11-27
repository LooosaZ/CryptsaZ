# CryptsaZ - Application for Confidentiality and Integrity

## Description
CryptsaZ is a Python application developed to perform various cryptography and data security operations. This project was designed to explore digital security methods and offer a practical tool for symmetric and asymmetric encryption operations, digital signature verification, key generation, and data integrity through hashing.

## Main Features
The application architecture consists of several main modules, each playing a crucial role in data security and integrity. Among the modules, those responsible for encryption, integrity verification, and digital signature stand out. Below are the main implementations:
- **Symmetric encryption**: Uses a single symmetric key to encrypt and decrypt data, implementing algorithms such as AES-128, AES-256, ChaCha20, and TripleDES. The main steps include key generation with `generateKey()`, data encryption with `encryptFile()`, padding removal when necessary, and integrity verification through hashes.
- **Asymmetric encryption**: Uses two keys, one public and one private. AES-256 key generation is done with `get_random_bytes()`, and data is encrypted in EAX mode. The AES key is encrypted with RSA-2048 through `encryptRsa2048()`, enabling secure key exchange.
- **Integrity verification**: Implements hashing using the hashlib library to generate and verify data hashes. This not only ensures that data has not been altered, but also supports the creation of digital signatures to verify that it truly originates from the sender, which will be detailed later.

## Secondary Features
In addition to the main implementations, the system offers various features that improve usability and security, including:
- File extension identification
- Generation and storage of RSA key pairs
- Automatic file search
- Removal of residual files
- File upload interface via tkinter
- Automatic dependency installation
- Public key management menu

## Project Structure
- **/assets**: Contains auxiliary resources and files used by the application.
- **encryptAsy.py / decryptAsy.py**: Scripts for asymmetric encryption and decryption operations.
- **encryptSy.py / decryptSy.py**: Scripts for symmetric encryption and decryption operations.
- **keyGenerator.py**: Tool for generating encryption keys.
- **hashVerifier.py**: Utility for verifying data integrity using hashes.
- **verifyKeys.py**: Tool for verifying the validity of encryption keys.
- **verifySignature.py**: Utility for verifying digital signatures.
- **logo.py**: Configures the logo or graphical interface of the project.
- **main.py**: Main interface for accessing the project's features.
- **requirements.txt**: File that lists the external dependencies needed to run the project.

## Prerequisites
- **Python 3.8 or higher**: Ensure Python is installed.
    - You can check the installed version with the command: `python --version`.

## Installing Dependencies
### Automatic Mode
To simplify this process, the program uses a file called `requirements.txt`, which lists all necessary packages. Thus, whenever the program starts, it automatically checks and installs the dependencies:
### Manual Mode
If you prefer, you can install each library manually with one of these scripts:
```bash
pip install -r requirements.txt
pip install cryptography qrcode Pillow pycryptodome tk windows-curses tqdm
```

### External Libraries
- **cryptography**: For advanced encryption and decryption operations.
- **qrcode**: For generating QR codes, enabling secure sharing of keys or messages.
- **Pillow**: Used for image manipulation, especially in QR code support.
- **pycryptodome**: Provides high-performance implementations of cryptography algorithms.
- **tk**: Tkinter graphical interface, used to implement the interactive interface of the project.

## How to Use
### Initial Setup
Install dependencies using the command `pip install -r requirements.txt` to ensure all necessary packages are available.
### Starting the Console Interface
The entry point of the project is the `main.py` file, which provides an interactive console interface. It can be executed with the command:
```bash
python main.py
```
### Navigating the Console Interface
Once `main.py` is started, the console interface will guide the user through encryption, decryption, verification, and key generation options. Select the desired option and follow the instructions to complete the operation.

### Usage Examples
To perform specific operations, follow the steps as guided by the console interface in `main.py`. Here are some typical examples:
- **Symmetric cryptography**: This option allows the user to encrypt files using symmetric cryptography, likely using an algorithm like AES. Symmetric encryption is useful for quickly protecting data with a single encryption key.
- **Asymmetric cryptography (RSA)**: Here, the user can encrypt files using asymmetric cryptography with the RSA algorithm. This type of encryption uses a pair of keys (public and private), allowing data encrypted with a public key to only be decrypted by the corresponding private key, ideal for secure information sharing.
- **Decrypt symmetric encryption**: This functionality is used to decrypt files that were encrypted with symmetric cryptography. The user needs to provide the same symmetric key that was used to encrypt the file originally, so that the data can be restored to its original state.
- **Decrypt asymmetric encryption**: This option allows the user to decrypt files encrypted with asymmetric cryptography (RSA). The file encrypted with a public key can be decrypted here using the corresponding private key, ensuring that only the holder of the private key can access the original content.
- **Generate encryption keys**: Here, the user can generate a new pair of keys for asymmetric cryptography (RSA). This functionality creates a public key and a private key, essential for the encryption and digital signature process.
- **Public keys management**: This functionality allows the user to manage public keys. The user can add, remove, or view public keys from other users, which facilitates secure sharing of encrypted information with multiple contacts.
- **Fix Dependencies**: This option is intended to resolve possible software dependencies needed for the application to work correctly. It may involve installing or updating libraries and tools that the application uses.
- **Exit**: This option closes the application.

## Graphical UI (Quick start)

This project includes a tkinter-based GUI. To run it on Windows from the project root inside the project's virtual environment:

```powershell
# Set TCL_LIBRARY so tkinter can find the Tcl/Tk runtime (adjust path if your Python is installed elsewhere)
$env:TCL_LIBRARY='C:/Users/<youruser>/AppData/Local/Programs/Python/Python313/tcl/tcl8.6'
C:/path/to/venv/Scripts/python.exe -m gui.simple_gui
```

Notes:
- The GUI title is "CryptsaZ Prototype".
- The Symmetric tab has a "Generate Symmetric Key" button which will populate the custom key field and prompt to save the key if an output folder is set.
- There's a "Copy Key" button that copies the key hex to the clipboard.
- Actions that modify or produce files prompt for confirmation before saving.

If you prefer to run without the virtualenv, ensure tkinter is available on your system Python and adapt the TCL_LIBRARY path accordingly.

## Contributing
This project is open source and contributions are welcome. To contribute:
1. Fork the project.
2. Create a new branch with your changes.
3. Open a pull request with a detailed description of the contribution.

## License
This project is distributed under the MIT license. Consult the LICENSE file for more details.
