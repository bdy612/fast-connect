import random
import string
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import json

class Encription:
    # Encryption type constants
    CAESAR_SUBSTITUTION = 1
    VIGENERE = 2
    AES = 3
    
    @staticmethod
    def get_encryption_types():
        """Return a list of available encryption types"""
        return [
            {"name": "Caesar+Substitution Cipher", "value": Encription.CAESAR_SUBSTITUTION},
            {"name": "Vigenère Cipher", "value": Encription.VIGENERE},
            {"name": "AES Encryption", "value": Encription.AES}
        ]
    
    @staticmethod
    def encrypt(text, params, encryption_type=CAESAR_SUBSTITUTION):
        """
        Encrypt the given text using the specified encryption type and parameters
        Returns a dictionary with encrypted text and information needed for decryption
        """
        if encryption_type == Encription.CAESAR_SUBSTITUTION:
            encrypted_text, substitution_key = Encription._encrypt_caesar_substitution(text, params["shift"])
            return {
                "type": encryption_type,
                "text": encrypted_text,
                "params": {
                    "shift": params["shift"],
                    "substitution_key": substitution_key
                }
            }
        
        elif encryption_type == Encription.VIGENERE:
            encrypted_text = Encription._encrypt_vigenere(text, params["key"])
            return {
                "type": encryption_type,
                "text": encrypted_text,
                "params": {
                    "key": params["key"]
                }
            }
        
        elif encryption_type == Encription.AES:
            encrypted_data = Encription._encrypt_aes(text, params["password"])
            return {
                "type": encryption_type,
                "text": encrypted_data["ciphertext"],
                "params": {
                    "password": params["password"],
                    "salt": encrypted_data["salt"],
                    "iv": encrypted_data["iv"]
                }
            }
        
        else:
            raise ValueError("Unknown encryption type")
    
    @staticmethod
    def decrypt(encryption_result):
        """
        Decrypt text using the information in the encryption_result dictionary
        """
        encryption_type = encryption_result["type"]
        encrypted_text = encryption_result["text"]
        params = encryption_result["params"]
        
        if encryption_type == Encription.CAESAR_SUBSTITUTION:
            return Encription._decrypt_caesar_substitution(
                encrypted_text, 
                params["shift"], 
                params["substitution_key"]
            )
        
        elif encryption_type == Encription.VIGENERE:
            return Encription._decrypt_vigenere(encrypted_text, params["key"])
        
        elif encryption_type == Encription.AES:
            return Encription._decrypt_aes(
                encrypted_text,
                params["password"],
                params["salt"],
                params["iv"]
            )
        
        else:
            raise ValueError("Unknown encryption type")
    
    @staticmethod
    def _encrypt_caesar_substitution(text, shift):
        """
        Encrypt text using a Caesar cipher with a random substitution table
        """
        # Generate substitution key (random mapping for each letter)
        alphabet = string.ascii_lowercase
        shuffled = list(alphabet)
        random.shuffle(shuffled)
        substitution_key = ''.join(shuffled)
        
        # Create translation tables
        caesar_table = str.maketrans(
            alphabet,
            alphabet[shift:] + alphabet[:shift]
        )
        substitution_table = str.maketrans(alphabet, substitution_key)
        
        # Apply Caesar cipher then substitution
        caesar_text = text.lower().translate(caesar_table)
        encrypted_text = caesar_text.translate(substitution_table)
        
        return encrypted_text, substitution_key
    
    @staticmethod
    def _decrypt_caesar_substitution(text, shift, substitution_key):
        """
        Decrypt text that was encrypted with Caesar cipher and substitution
        """
        alphabet = string.ascii_lowercase
        
        # Create reverse translation tables
        reverse_substitution = str.maketrans(substitution_key, alphabet)
        reverse_caesar = str.maketrans(
            alphabet[shift:] + alphabet[:shift],
            alphabet
        )
        
        # First reverse the substitution, then the Caesar shift
        substitution_reversed = text.translate(reverse_substitution)
        decrypted_text = substitution_reversed.translate(reverse_caesar)
        
        return decrypted_text
    
    @staticmethod
    def _shift_vigenere(text, key, direction):
        """Shift each English letter by its key letter; keeps case and leaves everything else as is"""
        key = key.lower()
        key_length = len(key)
        result = []

        for i, char in enumerate(text):
            if char.isascii() and char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                key_num = ord(key[i % key_length]) - ord('a')
                result.append(chr((ord(char) - base + direction * key_num) % 26 + base))
            else:
                # Digits, punctuation and non-English letters pass through unchanged
                result.append(char)

        return ''.join(result)

    @staticmethod
    def _encrypt_vigenere(text, key):
        """
        Encrypt text using a Vigenère cipher
        """
        return Encription._shift_vigenere(text, key, 1)
    
    @staticmethod
    def _decrypt_vigenere(text, key):
        """
        Decrypt text that was encrypted with a Vigenère cipher
        """
        return Encription._shift_vigenere(text, key, -1)
    
    @staticmethod
    def _encrypt_aes(text, password):
        """
        Encrypt text using AES-256 with password-based key derivation
        """
        # Generate a random salt
        salt = get_random_bytes(32)
        
        # Generate key from password and salt using SHA-256
        key = hashlib.sha256(password.encode() + salt).digest()
        
        # Create cipher with a random IV (initialization vector)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the plaintext to a multiple of 16 bytes
        padded_text = pad(text.encode(), AES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_text)
        
        # Encode binary data as base64 strings for storage/transmission
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }
    
    @staticmethod
    def _decrypt_aes(ciphertext_b64, password, salt_b64, iv_b64):
        """
        Decrypt text that was encrypted with AES
        """
        try:
            # Convert base64 strings back to bytes
            ciphertext = base64.b64decode(ciphertext_b64)
            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            
            # Regenerate the key from password and salt
            key = hashlib.sha256(password.encode() + salt).digest()
            
            # Create cipher for decryption
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Decrypt and unpad
            padded_text = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_text, AES.block_size)
            
            return plaintext.decode('utf-8')
        except ValueError as e:
            raise ValueError(f"Decryption error: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to decrypt: {str(e)}")
    
    @staticmethod
    def encode_encryption_data(encryption_result):
        """
        Convert encryption result to a compact string for transmission
        """
        # Convert bytes to base64 strings for JSON serialization
        # Make a deep copy to avoid modifying the original
        result_copy = dict(encryption_result)
        
        if "params" in result_copy:
            params_copy = dict(result_copy["params"])
            
            # Handle binary data
            for key, value in params_copy.items():
                if isinstance(value, bytes):
                    params_copy[key] = base64.b64encode(value).decode('utf-8')
            
            result_copy["params"] = params_copy
        
        # Convert to JSON string
        return json.dumps(result_copy)
    
    @staticmethod
    def decode_encryption_data(json_string):
        """
        Convert a JSON string back to encryption result for decryption
        """
        try:
            data = json.loads(json_string)
            
            # Convert base64 strings back to bytes if needed
            if "params" in data:
                for key, value in data["params"].items():
                    # Check if this might be base64 encoded bytes
                    try:
                        if isinstance(value, str) and key in ["salt", "iv"]:
                            data["params"][key] = value  # Keep as string, will decode in decrypt
                    except:
                        pass  # Not base64, keep as is
            
            return data
        except Exception as e:
            raise ValueError(f"Failed to decode encryption data: {str(e)}")
    
    @staticmethod
    def encrypt_file(file_path, params, encryption_type=AES):
        """
        Encrypt a file and return base64 encoded data for transmission
        """
        import os
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Convert binary data to base64 for text-based encryption
        file_b64 = base64.b64encode(file_data).decode('utf-8')
        
        # Encrypt the base64 string
        encrypted_result = Encription.encrypt(file_b64, params, encryption_type)
        
        # Add filename
        encrypted_result['filename'] = os.path.basename(file_path)
        encrypted_result['original_size'] = len(file_data)
        
        return encrypted_result
    
    @staticmethod
    def decrypt_file(encryption_result, output_path):
        """
        Decrypt file data and save to output_path
        """
        # Decrypt to get base64 string
        decrypted_b64 = Encription.decrypt(encryption_result)
        
        # Decode base64 to binary
        file_data = base64.b64decode(decrypted_b64)
        
        # Write to file
        with open(output_path, 'wb') as f:
            f.write(file_data)
        
        return output_path
    
    @staticmethod
    def encrypt_folder(folder_path, params, encryption_type=AES):
        """
        Encrypt all files in a folder and return as a package
        """
        import os
        import zipfile
        import tempfile
        
        # Create a temporary zip file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip.close()
        
        # Zip the folder
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
        
        # Encrypt the zip file
        encrypted_result = Encription.encrypt_file(temp_zip.name, params, encryption_type)
        encrypted_result['is_folder'] = True
        encrypted_result['folder_name'] = os.path.basename(folder_path)
        
        # Clean up temp file
        os.unlink(temp_zip.name)
        
        return encrypted_result
    
    @staticmethod
    def decrypt_folder(encryption_result, output_path):
        """
        Decrypt folder package and extract to output_path
        """
        import os
        import zipfile
        import tempfile
        
        # Create temp file for decrypted zip
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip.close()
        
        # Decrypt to temp zip file
        Encription.decrypt_file(encryption_result, temp_zip.name)
        
        # Extract zip
        with zipfile.ZipFile(temp_zip.name, 'r') as zipf:
            zipf.extractall(output_path)
        
        # Clean up
        os.unlink(temp_zip.name)
        
        return output_path