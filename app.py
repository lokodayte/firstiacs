import os
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad as unpad_crypto # Renamed to avoid conflict with custom unpad

app = Flask(__name__)
# !!! IMPORTANT: CHANGE THIS TO A STRONG, UNIQUE, RANDOM KEY !!!
# You can generate one using: os.urandom(24).hex()
app.secret_key = 'your_secret_key_here_a_very_secret_one'

# Configuration for file storage
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'
app.config['DECRYPTED_FOLDER'] = 'decrypted'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Constants for AES encryption/decryption
PBKDF2_ITERATIONS = 100000
KEY_LENGTH = 32  # 256 bits for AES-256
BLOCK_SIZE = AES.block_size  # 16 bytes (for AES, always 16 bytes)

def ensure_folder(folder_path):
    """
    Ensures a directory exists. If it doesn't, it creates it
    and attempts to set permissions to rwxr-xr-x (755).
    """
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path, exist_ok=True)
            # Set permissions for the newly created folder
            os.chmod(folder_path, 0o755)
            print(f"Created directory: {folder_path} with permissions 755.")
        except OSError as e:
            print(f"Error creating or setting permissions for {folder_path}: {e}")
    else:
        # If folder already exists, ensure permissions are set (optional, but good practice)
        try:
            os.chmod(folder_path, 0o755)
        except OSError as e:
            print(f"Warning: Could not set permissions for existing folder {folder_path}: {e}")

# Ensure necessary directories exist at application startup
for folder in [app.config['UPLOAD_FOLDER'], app.config['ENCRYPTED_FOLDER'], app.config['DECRYPTED_FOLDER']]:
    ensure_folder(folder)

def derive_key(password, salt):
    """
    Derives a strong cryptographic key from a given password and salt
    using PBKDF2 (Password-Based Key Derivation Function 2).
    This makes it harder to brute-force passwords.
    """
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

def encrypt_data(data, password):
    """
    Encrypts the given 'data' (bytes) using AES-256 in CBC mode.
    It generates a random salt and IV (Initialization Vector) for each encryption.
    The output format is: salt + IV + ciphertext.
    """
    salt = get_random_bytes(16) # Random salt for key derivation
    key = derive_key(password.encode(), salt) # Derive key from password and salt
    iv = get_random_bytes(BLOCK_SIZE) # Random IV for CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the data to be a multiple of BLOCK_SIZE using PKCS7 padding
    encrypted = cipher.encrypt(pad(data, BLOCK_SIZE))
    return salt + iv + encrypted

def decrypt_data(encrypted_data, password):
    """
    Decrypts the given 'encrypted_data' (bytes) using AES-256 in CBC mode.
    It expects the data to be in the format: salt + IV + ciphertext.
    Returns the decrypted data (bytes) or None if decryption fails (e.g., wrong password, corrupted data).
    """
    try:
        # Extract salt, IV, and ciphertext from the encrypted data
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        key = derive_key(password.encode(), salt) # Derive key using the extracted salt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt the ciphertext and unpad it using PKCS7 unpadding
        decrypted = unpad_crypto(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return decrypted
    except (ValueError, KeyError, IndexError) as e:
        # Catch specific errors that indicate decryption failure
        # ValueError: often due to incorrect padding (wrong key)
        # KeyError: if key size is wrong (unlikely with fixed KEY_LENGTH)
        # IndexError: if encrypted_data is too short to extract salt/IV
        print(f"Decryption failed: {e}")
        return None # Return None to indicate failure

# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the home page."""
    return render_template('index.html')

@app.route('/text', methods=['GET', 'POST'])
def text():
    """Handles text encryption and decryption."""
    result = ''
    message = ''
    # Initialize password_value to ensure it's always passed to the template
    password_value = '' 

    if request.method == 'POST':
        text_input = request.form.get('text', '')
        password = request.form.get('password', '')
        action = request.form.get('action')
        
        # Preserve the password value from the form submission
        password_value = password 

        if not text_input or not password:
            message = 'Text and password are required.'
            result = text_input # Preserve user input
            password_value = password # Keep password if input is missing
        else:
            if action == 'encrypt':
                encrypted = encrypt_data(text_input.encode('utf-8'), password) # Encode text to bytes
                result = encrypted.hex() # Convert bytes to hex string for display
                message = 'Text encrypted successfully.'
            elif action == 'decrypt':
                try:
                    encrypted_bytes = bytes.fromhex(text_input) # Convert hex string back to bytes
                    decrypted_bytes = decrypt_data(encrypted_bytes, password)
                    if decrypted_bytes is not None:
                        try:
                            result = decrypted_bytes.decode('utf-8') # Decode bytes to string
                            message = 'Text decrypted successfully.'
                        except UnicodeDecodeError:
                            # If decryption was technically successful but data isn't valid UTF-8
                            message = 'Decryption failed. Wrong password or data is corrupted (invalid UTF-8).'
                            result = text_input # Keep original encrypted hex for user to re-try
                            password_value = '' # Clear password on decryption failure
                    else:
                        # Decryption failed (e.g., wrong password, corrupted header)
                        message = 'Decryption failed. Wrong password or data is corrupted (incorrect password).'
                        result = text_input # Keep original encrypted hex for user to re-try
                        password_value = '' # Clear password on decryption failure
                except ValueError:
                    # If the input text is not a valid hexadecimal string
                    message = 'Invalid encrypted text format (must be a valid hexadecimal string).'
                    result = text_input # Keep original user input
                    password_value = '' # Clear password on decryption failure

    # Pass all necessary variables to the template
    return render_template('text.html', result=result, message=message, password_value=password_value)

@app.route('/image', methods=['GET', 'POST'])
def image():
    """
    Handles image file encryption and decryption.
    On failure, the uploaded file is preserved for retry.
    On success, inputs are cleared.
    """
    message = ''
    uploaded_filename = ''
    password_value = ''
    status = ''
    action = request.form.get('action', 'encrypt')

    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password', '')
        action = request.form.get('action')

        if not file or file.filename == '':
            message = 'Please select a file.'
            status = 'error'
        elif not password:
            message = 'Please enter a password.'
            status = 'error'
        else:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(file_path)
                uploaded_filename = filename
            except PermissionError:
                message = f"Permission denied: cannot save file to {file_path}. Check folder permissions."
                status = 'error'
                return render_template('image.html', message=message, action=action, status=status, uploaded_filename=uploaded_filename, password_value=password_value)

            with open(file_path, 'rb') as f:
                data = f.read()

            if action == 'encrypt':
                try:
                    encrypted = encrypt_data(data, password)
                    encrypted_filename = filename + '.enc'
                    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted)
                    os.remove(file_path)
                    return send_file(encrypted_path, as_attachment=True, download_name=encrypted_filename)
                except Exception as e:
                    message = f'Encryption failed: {str(e)}'
                    status = 'error'
                    if os.path.exists(file_path):
                        os.remove(file_path)

            elif action == 'decrypt':
                try:
                    decrypted = decrypt_data(data, password)
                    if decrypted is not None:
                        if filename.lower().endswith('.enc'):
                            original_filename = filename[:-4] or 'decrypted_file'
                        else:
                            original_filename = 'decrypted_' + filename
                        decrypted_path = os.path.join(app.config['DECRYPTED_FOLDER'], original_filename)
                        with open(decrypted_path, 'wb') as f:
                            f.write(decrypted)
                        os.remove(file_path)
                        return send_file(decrypted_path, as_attachment=True, download_name=original_filename)
                    else:
                        message = 'Decryption failed. Wrong password or data is corrupted.'
                        status = 'error'
                        password_value = ''
                        uploaded_filename = filename  # Preserve for retry
                except Exception as e:
                    message = f'Decryption failed: {str(e)}'
                    status = 'error'
                    password_value = ''
                    uploaded_filename = filename  # Preserve for retry

            if os.path.exists(file_path) and status == 'error' and action == 'encrypt':
                os.remove(file_path)

    return render_template('image.html',
                           message=message,
                           action=action,
                           status=status,
                           uploaded_filename=uploaded_filename,
                           password_value=password_value)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
