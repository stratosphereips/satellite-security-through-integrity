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
import random
import shutil
from pathlib import Path

# ANSI color codes for better output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def colored_print(color, level, message):
    """Print colored messages with level prefix"""
    print(f"{color}[{level}] {message}{Colors.RESET}")

def create_backup(file_path):
    """Create a backup of the original file"""
    try:
        backup_path = str(file_path) + '.bak'
        shutil.copy2(file_path, backup_path)
        colored_print(Colors.GREEN, "INFO", f"Backup created: {backup_path}")
        return True
    except Exception as e:
        colored_print(Colors.RED, "ERROR", f"Failed to create backup: {str(e)}")
        return False

def modify_payload_data(file_path):
    """Modify the payload data with random changes"""
    try:
        # Create backup first
        if not create_backup(file_path):
            return False

        # Open and read the file
        colored_print(Colors.BLUE, "DEBUG", f"Reading file: {file_path}")
        with open(file_path, 'rb') as file:
            data = bytearray(file.read())

        # Modify random bytes (10% of the file)
        colored_print(Colors.BLUE, "DEBUG", f"Modifying {len(data) // 10} bytes")
        for _ in range(len(data) // 10):
            index = random.randint(0, len(data) - 1)
            data[index] = data[index] ^ random.randint(1, 255)

        # Write modified data back
        with open(file_path, 'wb') as file:
            file.write(data)
        
        colored_print(Colors.GREEN, "SUCCESS", f"Modified payload: {file_path}")
        return True
    
    except Exception as e:
        colored_print(Colors.RED, "ERROR", f"Failed to modify payload: {str(e)}")
        return False

def find_payload_files(directory):
    """Find all relevant payload files in directory"""
    try:
        payload_dir = Path(directory)
        if not payload_dir.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        # List for found files
        payload_files = []
        
        # Supported image extensions
        image_extensions = {'.tif', '.tiff', '.jpg', '.jpeg', '.png'}
        
        # Find all matching files
        colored_print(Colors.BLUE, "DEBUG", f"Scanning directory: {directory}")
        for file_path in payload_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in image_extensions:
                payload_files.append(file_path)
                colored_print(Colors.BLUE, "DEBUG", f"Found payload file: {file_path.name}")
        
        return payload_files

    except Exception as e:
        colored_print(Colors.RED, "ERROR", f"Error scanning directory: {str(e)}")
        return []

def main():
    """Main function to run the payload modifier"""
    try:
        # Your payload directory path
        payload_dir = "payload"
        
        # Find payload files
        colored_print(Colors.GREEN, "INFO", f"Searching for payload files in: {payload_dir}")
        payload_files = find_payload_files(payload_dir)
        
        if not payload_files:
            colored_print(Colors.YELLOW, "WARNING", "No payload files found")
            return
        
        colored_print(Colors.GREEN, "INFO", f"Found {len(payload_files)} payload files")
        
        # Process each file
        modified = 0
        failed = 0
        
        for file_path in payload_files:
            if modify_payload_data(file_path):
                modified += 1
            else:
                failed += 1
        
        # Print results
        results = f"""
Modification completed:
- Total files found: {len(payload_files)}
- Successfully modified: {modified}
- Failed to modify: {failed}
"""
        colored_print(Colors.GREEN, "INFO", results)
        
    except Exception as e:
        colored_print(Colors.RED, "ERROR", f"Fatal error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
