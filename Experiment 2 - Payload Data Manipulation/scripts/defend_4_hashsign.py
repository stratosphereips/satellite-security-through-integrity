# Copyright (C) 2024-2026 Juani Bousquet
# Repository: https://github.com/stratosphereips/satellite-security-through-integrity
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# ADDITIONAL RESTRICTION (per GPL v2 Section 7):
# This software may not be used, in whole or in part, for commercial purposes
# without prior written permission from the copyright holder.
# Commercial use includes, but is not limited to, use in a commercial product,
# use in a service offered for a fee, or use by a for-profit organization.
# For commercial licensing inquiries, contact: juanibuqt@gmail.com
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>

import os
from pathlib import Path
from wolfcrypt import ciphers, hashes
from wolfcrypt.utils import h2b, b2h

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def colored_print(color, level, message):
    """Print colored messages with level prefix"""
    print(f"{color}[{level}] {message}{Colors.RESET}")

class ImageHashSigner:
    def __init__(self, key_dir, payload_dir):
        self.private_key = Path(key_dir) / "private.der"
        self.payload_dir = Path(payload_dir)
        
        # Verify directories and key exist
        if not self.private_key.exists():
            raise FileNotFoundError(f"Private key not found: {self.private_key}")
        if not self.payload_dir.exists():
            raise FileNotFoundError(f"Payload directory not found: {self.payload_dir}")
            
        # Load private key
        try:
            with open(self.private_key, 'rb') as f:
                key_data = f.read()
                self.rsa = ciphers.RsaPrivate(key_data)
                colored_print(Colors.GREEN, "INFO", "Successfully loaded private key")
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error loading private key: {e}")
            raise

    def calculate_sha3_256(self, file_path):
        """Calculate SHA3-256 hash of file using wolfcrypt."""
        try:
            colored_print(Colors.BLUE, "DEBUG", f"Reading file for hashing: {file_path}")
            
            # Initialize SHA3-256
            sha3 = hashes.Sha3('sha3-256')
            
            # Read and hash file in chunks
            with open(file_path, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    sha3.update(chunk)
                    
            # Get the final digest and convert to clean hex string
            hash_bytes = sha3.digest()
            hash_hex = b2h(hash_bytes)
            
            # Clean up the hash string - remove b prefix and quotes
            clean_hash = str(hash_hex).strip("b'\"")
            
            colored_print(Colors.BLUE, "DEBUG", f"Generated hash: {clean_hash}")
            return clean_hash
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error calculating hash for {file_path}: {e}")
            raise

    def sign_hash_with_wolfssl(self, hash_value, temp_dir):
        """Sign hash value using WolfSSL."""
        try:
            colored_print(Colors.BLUE, "DEBUG", "Converting hash to bytes for signing")
            hash_bytes = h2b(hash_value)
            
            colored_print(Colors.BLUE, "DEBUG", "Signing hash with RSA key")
            signature = self.rsa.sign(hash_bytes)
            
            # Convert signature to clean hex string
            signature_hex = b2h(signature)
            clean_signature = str(signature_hex).strip("b'\"")
            
            colored_print(Colors.BLUE, "DEBUG", f"Generated signature (first 64 chars): {clean_signature[:64]}...")
            return clean_signature
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error during signing: {e}")
            raise

    def store_hash_and_signature(self, image_path, hash_value, signature):
        """Store hash and signature alongside the image."""
        try:
            # Ensure we're dealing with clean strings
            hash_str = str(hash_value).strip("b'\"")
            sig_str = str(signature).strip("b'\"")
            
            # Create hash file
            hash_file = image_path.with_suffix('.hash')
            colored_print(Colors.BLUE, "DEBUG", f"Writing hash to file: {hash_file}")
            with open(hash_file, "w") as f:
                f.write(hash_str)
            
            # Create signature file
            sig_file = image_path.with_suffix('.sig')
            colored_print(Colors.BLUE, "DEBUG", f"Writing signature to file: {sig_file}")
            with open(sig_file, "w") as f:
                f.write(sig_str)
                
            colored_print(Colors.GREEN, "INFO", f"Successfully stored hash and signature for {image_path.name}")
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error storing hash and signature: {e}")
            raise

    def process_image(self, image_path):
        """Process a single image: hash, sign, and store."""
        try:
            image_path = Path(image_path)
            colored_print(Colors.BLUE, "DEBUG", f"Processing image: {image_path}")
            
            if not image_path.exists():
                raise FileNotFoundError(f"Image not found: {image_path}")

            # Skip if hash and signature files already exist
            if image_path.with_suffix('.hash').exists() and image_path.with_suffix('.sig').exists():
                colored_print(Colors.YELLOW, "INFO", f"Skipping {image_path.name} - already processed")
                return True

            colored_print(Colors.GREEN, "INFO", f"Processing image: {image_path.name}")
            
            # Calculate hash
            hash_value = self.calculate_sha3_256(image_path)
            colored_print(Colors.GREEN, "INFO", f"Generated hash: {hash_value}")
            
            # Sign hash
            signature = self.sign_hash_with_wolfssl(hash_value, image_path.parent)
            colored_print(Colors.GREEN, "INFO", f"Generated signature: {signature[:64]}...")
            
            # Store results
            self.store_hash_and_signature(image_path, hash_value, signature)
            
            colored_print(Colors.GREEN, "INFO", f"Successfully processed {image_path.name}")
            return True
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Failed to process {image_path.name}: {e}")
            return False

    def process_directory(self):
        """Process all images in the payload directory."""
        # Supported image extensions
        image_extensions = {'.tif', '.tiff', '.jpg', '.jpeg', '.png'}
        
        # Count for statistics
        total_files = 0
        successful = 0
        failed = 0
        skipped = 0

        colored_print(Colors.GREEN, "INFO", f"Starting batch processing in {self.payload_dir}")
        
        # List all files
        colored_print(Colors.BLUE, "DEBUG", "Scanning directory for image files...")
        files_found = list(self.payload_dir.iterdir())
        colored_print(Colors.BLUE, "DEBUG", f"Found {len(files_found)} total files")
        
        # Process each file
        for file_path in files_found:
            if file_path.is_file():
                ext = file_path.suffix.lower()
                colored_print(Colors.BLUE, "DEBUG", f"Checking file: {file_path.name} with extension: {ext}")
                
                if ext in image_extensions:
                    total_files += 1
                    colored_print(Colors.BLUE, "DEBUG", f"Found image file: {file_path.name}")
                    try:
                        if self.process_image(file_path):
                            successful += 1
                        else:
                            failed += 1
                    except Exception as e:
                        colored_print(Colors.RED, "ERROR", f"Error processing {file_path.name}: {e}")
                        failed += 1
                else:
                    skipped += 1
                    colored_print(Colors.BLUE, "DEBUG", f"Skipping non-image file: {file_path.name}")

        # Print statistics
        stats = f"""
Batch processing completed:
- Total files processed: {total_files}
- Successfully processed: {successful}
- Failed to process: {failed}
- Skipped (non-image): {skipped}
"""
        colored_print(Colors.GREEN, "INFO", stats)

def main():
    """Main function to run the image hash signer."""
    try:
        # Make sure payload directory exists and has files
        payload_dir = Path("payload")
        if not payload_dir.exists():
            os.makedirs(payload_dir)
            colored_print(Colors.YELLOW, "WARNING", f"Created payload directory: {payload_dir}")
        else:
            files = list(payload_dir.iterdir())
            colored_print(Colors.GREEN, "INFO", f"Found {len(files)} files in payload directory")
            for f in files:
                colored_print(Colors.BLUE, "DEBUG", f"Found file: {f.name}")
        
        key_dir = Path("key")
        if not key_dir.exists() or not (key_dir / "private.der").exists():
            raise FileNotFoundError("Key directory or private.der not found!")
        
        processor = ImageHashSigner(key_dir, payload_dir)
        processor.process_directory()
        
    except Exception as e:
        colored_print(Colors.RED, "ERROR", f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
