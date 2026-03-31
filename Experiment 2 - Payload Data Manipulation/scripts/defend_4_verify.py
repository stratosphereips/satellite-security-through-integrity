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

class ImageSignatureVerifier:
    def __init__(self, key_dir, payload_dir):
        self.public_key = Path(key_dir) / "public.der"
        self.payload_dir = Path(payload_dir)
        
        # Verify directories and key exist
        if not self.public_key.exists():
            raise FileNotFoundError(f"Public key not found: {self.public_key}")
        if not self.payload_dir.exists():
            raise FileNotFoundError(f"Payload directory not found: {self.payload_dir}")
            
        # Load public key
        try:
            with open(self.public_key, 'rb') as f:
                key_data = f.read()
                self.rsa = ciphers.RsaPublic(key_data)
                colored_print(Colors.GREEN, "INFO", "Successfully loaded public key")
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error loading public key: {e}")
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
            clean_hash = str(hash_hex).strip("b'\"")
            
            colored_print(Colors.BLUE, "DEBUG", f"Generated hash: {clean_hash}")
            return clean_hash
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error calculating hash for {file_path}: {e}")
            raise

    def verify_signature(self, hash_value, signature_hex):
        """Verify the signature using the public key."""
        try:
            colored_print(Colors.BLUE, "DEBUG", f"Converting hash and signature for verification")
            hash_bytes = h2b(hash_value)
            signature_bytes = h2b(signature_hex)
            
            # Verify signature
            colored_print(Colors.BLUE, "DEBUG", "Verifying signature with public key")
            verified_hash = self.rsa.verify(signature_bytes)
            
            # Compare the decrypted hash with our hash
            if verified_hash == hash_bytes:
                return True
            return False
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Error during signature verification: {e}")
            return False

    def verify_image(self, image_path):
        """Verify a single image's hash and signature."""
        try:
            image_path = Path(image_path)
            colored_print(Colors.BLUE, "DEBUG", f"Verifying image: {image_path}")
            
            if not image_path.exists():
                colored_print(Colors.RED, "ERROR", f"Image not found: {image_path}")
                return False, "Image file not found"

            # Check if hash and signature files exist
            hash_file = image_path.with_suffix('.hash')
            sig_file = image_path.with_suffix('.sig')
            
            if not hash_file.exists():
                colored_print(Colors.RED, "ERROR", f"Hash file not found for {image_path.name}")
                return False, "Hash file not found"
                
            if not sig_file.exists():
                colored_print(Colors.RED, "ERROR", f"Signature file not found for {image_path.name}")
                return False, "Signature file not found"

            # Read stored hash and signature
            with open(hash_file, "r") as f:
                stored_hash = f.read().strip()
            with open(sig_file, "r") as f:
                stored_sig = f.read().strip()

            # Calculate current hash
            current_hash = self.calculate_sha3_256(image_path)
            
            # Compare hashes
            if current_hash != stored_hash:
                colored_print(Colors.YELLOW, "WARNING", f"Hash mismatch for {image_path.name}")
                colored_print(Colors.BLUE, "DEBUG", f"Stored hash:   {stored_hash}")
                colored_print(Colors.BLUE, "DEBUG", f"Current hash:  {current_hash}")
                return False, "Image has been modified (hash mismatch)"

            # Verify signature
            if not self.verify_signature(current_hash, stored_sig):
                colored_print(Colors.YELLOW, "WARNING", f"Invalid signature for {image_path.name}")
                return False, "Invalid signature"

            colored_print(Colors.GREEN, "INFO", f"Successfully verified {image_path.name}")
            return True, "Verification successful"
            
        except Exception as e:
            colored_print(Colors.RED, "ERROR", f"Failed to verify {image_path.name}: {e}")
            return False, str(e)

    def verify_directory(self):
        """Verify all images in the payload directory."""
        # Supported image extensions
        image_extensions = {'.tif', '.tiff', '.jpg', '.jpeg', '.png'}
        
        # Count for statistics
        total_files = 0
        verified = 0
        failed = 0
        skipped = 0

        colored_print(Colors.GREEN, "INFO", f"Starting verification in {self.payload_dir}")
        results = []
        
        # Process each file
        for file_path in self.payload_dir.iterdir():
            if file_path.is_file():
                ext = file_path.suffix.lower()
                colored_print(Colors.BLUE, "DEBUG", f"Checking file: {file_path.name}")
                
                if ext in image_extensions:
                    total_files += 1
                    colored_print(Colors.BLUE, "DEBUG", f"Verifying image file: {file_path.name}")
                    
                    # Verify the image
                    is_valid, message = self.verify_image(file_path)
                    
                    # Store result
                    results.append({
                        'file': file_path.name,
                        'status': 'VERIFIED' if is_valid else 'FAILED',
                        'message': message
                    })
                    
                    if is_valid:
                        verified += 1
                    else:
                        failed += 1
                else:
                    skipped += 1
                    colored_print(Colors.BLUE, "DEBUG", f"Skipping non-image file: {file_path.name}")

        # Print statistics
        stats = f"""
Verification completed:
- Total files processed: {total_files}
- Successfully verified: {verified}
- Failed verification: {failed}
- Skipped (non-image): {skipped}
"""
        colored_print(Colors.GREEN, "INFO", stats)
        return results

def main():
    """Main function to run the image verifier."""
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
        if not key_dir.exists() or not (key_dir / "public.der").exists():
            raise FileNotFoundError("Key directory or public.der not found!")
        
        verifier = ImageSignatureVerifier(key_dir, payload_dir)
        results = verifier.verify_directory()
        
        # Print results in a readable format
        print("\nVerification Results:")
        print("-" * 60)
        for result in results:
            color = Colors.GREEN if result['status'] == 'VERIFIED' else Colors.RED
            print(f"File: {result['file']}")
            print(f"Status: {color}{result['status']}{Colors.RESET}")
            print(f"Message: {result['message']}")
            print("-" * 60)
        
    except Exception as e:
        colored_print(Colors.RED, "ERROR", f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
