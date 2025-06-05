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
    When decryption fails, the uploaded file is *not* deleted,
    the password field is cleared, and the filename is displayed.
    """
    message = ''
    uploaded_filename = '' # Stores the filename to display in the HTML
    status = ''
    action = request.form.get('action', 'encrypt') # Default action is encrypt
    password_value = '' # Stores the password input, cleared on decryption failure

    if request.method == 'POST':
        file = request.files.get('file') # Get the uploaded file object
        password = request.form.get('password', '')
        action = request.form.get('action') # Get the action (encrypt/decrypt) from the button clicked
        
        # Validate file and password input
        if not file or file.filename == '':
            message = 'Please select a file.'
            status = 'error'
        elif not password: # Password is required for both encryption and decryption
            message = 'Please enter a password.'
            status = 'error'
        else:
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                # Always save the file initially.
                # This ensures the file is available for processing or re-attempts.
                file.save(file_path)
                uploaded_filename = filename # Store the filename for display in the template
            except PermissionError:
                message = f"Permission denied: cannot save file to {file_path}. Check folder permissions."
                status = 'error'
                # Render template immediately on permission error
                return render_template('image.html',
                                    message=message,
                                    action=action,
                                    status=status,
                                    uploaded_filename=uploaded_filename, # Pass the preserved filename
                                    password_value=password_value)

            # Read the content of the saved file
            with open(file_path, 'rb') as f:
                data = f.read()

            if action == 'encrypt':
                try:
                    encrypted = encrypt_data(data, password)
                    encrypted_filename = filename + '.enc'
                    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted)
                    # Delete the original uploaded file only after successful encryption
                    os.remove(file_path) 
                    # Send the encrypted file back to the user for download
                    return send_file(encrypted_path, as_attachment=True, download_name=encrypted_filename)
                except Exception as e:
                    message = f'Encryption failed: {str(e)}'
                    status = 'error'
                    # If encryption fails, clean up the original uploaded file
                    if os.path.exists(file_path):
                        os.remove(file_path)

            elif action == 'decrypt':
                try:
                    decrypted = decrypt_data(data, password)
                    if decrypted is not None:
                        # Decryption was successful
                        # Determine the original filename for the decrypted file
                        if filename.lower().endswith('.enc'):
                            original_filename = filename[:-4] # Remove the '.enc' extension
                            if not original_filename: # Handle edge case like "file.enc" where base is empty
                                original_filename = 'decrypted_file'
                        else:
                            original_filename = 'decrypted_' + filename # Prepend for non-.enc files

                        decrypted_path = os.path.join(app.config['DECRYPTED_FOLDER'], original_filename)
                        with open(decrypted_path, 'wb') as f:
                            f.write(decrypted)
                        # Delete the original uploaded file (which was likely the .enc file)
                        # only after successful decryption and saving the decrypted version.
                        os.remove(file_path) 
                        # Send the decrypted file back to the user for download
                        return send_file(decrypted_path, as_attachment=True, download_name=original_filename)
                    else:
                        # Decryption failed (e.g., wrong password, corrupted data header)
                        message = 'Decryption failed. Wrong password or data is corrupted.'
                        status = 'error'
                        # *** IMPORTANT: The uploaded file (file_path) is NOT deleted here. ***
                        # This allows the user to try again with the same file without re-uploading.
                        password_value = '' # Clear the password field in the form
                except Exception as e:
                    # Catch any other unexpected errors during the decryption process
                    message = f'Decryption failed: {str(e)}'
                    status = 'error'
                    # *** IMPORTANT: The uploaded file (file_path) is NOT deleted here. ***
                    password_value = '' # Clear the password field in the form
            
            # This final cleanup block handles cases where an error occurred AFTER file save
            # but it's not a decryption failure (which intentionally keeps the file).
            # For example, if an encryption attempt failed after saving the file.
            if os.path.exists(file_path) and status == 'error' and action == 'encrypt':
                os.remove(file_path)

    # Render the HTML template with the current state:
    # - message: any success or error message
    # - action: the last attempted action (encrypt/decrypt)
    # - status: 'error' if an error occurred
    # - uploaded_filename: the name of the file that was last uploaded/processed
    # - password_value: empty if decryption failed, otherwise whatever was entered
    return render_template('image.html',
                         message=message,
                         action=action,
                         status=status,
                         uploaded_filename=uploaded_filename,
                         password_value=password_value)

if __name__ == '__main__':
    # Run the Flask application.
    # debug=True is useful for development (auto-reloads, shows errors),
    # but should be set to False in a production environment for security.
    app.run(debug=True)
