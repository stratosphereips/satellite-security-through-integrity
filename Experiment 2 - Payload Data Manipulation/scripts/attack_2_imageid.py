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

#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime
import sys
import re
import unicodedata

class SatelliteImageScanner:
    def __init__(self):
        # Extended file support
        self.extensions = {
            '.jpg', '.jpeg', '.tiff', '.tif', '.png',  # Image files
            '.xmp', '.aux.xml', '_meta.json', '.json'  # Metadata files
        }
        self.found_images = []
        self.log_file = f'satellite_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        
        # Extended satellite prefixes
        self.satellite_prefixes = {
            'LANDSAT', 'SENTINEL', 'GOES', 'NOAA', 'MODIS', 'SPOT',
            'L8', 'L9', 'S1A', 'S1B', 'S2A', 'S2B', 'G16', 'G17',
            'SKYFI', 'SKYSAT'  # Added new prefixes
        }
        
        # Extended patterns
        self.patterns = [
            # Previous patterns
            r'\d{8}_\d{6}',           # YYYYMMDD_HHMMSS
            r'\d{4}\d{3}',            # YYYYDDD (Year + Day of Year)
            r'L[C-O]0[1-9]_L\d[A-C]\d{6}_\d{8}',
            r'LC08_L[1-2][A-C]\d{2}_\d{6}_\d{8}',
            r'S[12][AB]_MSIL[1-2][ABC]_\d{8}T\d{6}',
            r'GOES\d{2}_ABI_L[1-2]_\w+_\d{12}',
            r'[A-Z0-9]{3,}_[A-Z0-9]{2,}_\d{3}_\d{3}',
            r'T\d{2}[A-Z]{3}_\d{8}T\d{6}',
            
            # New SkyFi patterns
            r'SkyFi_[\w-]+_\d{4}-\d{2}-\d{2}_\d{4}Z',  # SkyFi timestamp
            r'\d{4}-\d{2}-\d{2}_\d{4}Z',               # General timestamp
            r'MULTISPECTRAL_(?:LOW|HIGH)',             # Resolution indicator
        ]
        self.compiled_patterns = [re.compile(pattern, re.UNICODE) for pattern in self.patterns]

    def log_message(self, message, level="INFO"):
        """Write message to log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, 'a') as f:
            f.write(f"{timestamp} - {level} - {message}\n")

    def is_image_file(self, filename):
        """Check if file has a valid image extension"""
        return os.path.splitext(filename.lower())[1] in self.extensions

    def is_satellite_image_name(self, filename):
        """Check if filename matches common satellite image naming patterns"""
        try:
            # Normalize unicode characters
            basename = os.path.splitext(filename)[0]
            normalized_name = unicodedata.normalize('NFKD', basename)
            
            # Check if starts with known satellite prefix
            if any(normalized_name.upper().startswith(prefix) for prefix in self.satellite_prefixes):
                return True
            
            # Check against regex patterns
            if any(pattern.search(normalized_name) for pattern in self.compiled_patterns):
                return True
            
            # Check for combined indicators
            indicators = ['MULTISPECTRAL', 'SKYFI', 'Z_', '_LOW_', '_HIGH_']
            if any(indicator in normalized_name.upper() for indicator in indicators):
                return True
            
            # Check for related metadata files
            if any(filename.endswith(ext) for ext in ['.xmp', '.aux.xml', '_meta.json']):
                base_path = os.path.splitext(filename)[0]
                if any(os.path.exists(f"{base_path}{ext}") for ext in ['.tif', '.png', '.jpg']):
                    return True
            
            # Check for underscore-separated components with numbers
            parts = normalized_name.split('_')
            if len(parts) >= 3 and any(part.isdigit() for part in parts):
                return True
            
            return False
        except Exception as e:
            self.log_message(f"Error in name checking for {filename}: {str(e)}", "ERROR")
            return False

    def check_jpeg_metadata(self, file_path):
        """
        Check for metadata in JPEG files by analyzing file structure
        Returns tuple of (metadata_dict, has_metadata)
        """
        metadata = {}
        try:
            with open(file_path, 'rb') as f:
                # Check for JPEG signature
                if f.read(2) != b'\xFF\xD8':
                    return None, False

                while True:
                    marker = f.read(2)
                    if len(marker) < 2:
                        break

                    # Check for JPEG segment markers
                    if marker[0] != 0xFF:
                        break

                    # EOI marker
                    if marker[1] == 0xD9:
                        break

                    # Skip empty markers
                    if marker[1] == 0xD8:
                        continue

                    # Read length
                    length_bytes = f.read(2)
                    if len(length_bytes) < 2:
                        break
                    length = (length_bytes[0] << 8) + length_bytes[1] - 2

                    # Check for EXIF marker (0xE1)
                    if marker[1] == 0xE1:
                        exif_data = f.read(length)
                        if exif_data.startswith(b'Exif\x00\x00'):
                            metadata['has_exif'] = True
                            return metadata, True
                    else:
                        # Skip this segment
                        f.seek(length, 1)

        except Exception as e:
            self.log_message(f"Error checking JPEG metadata for {file_path}: {str(e)}", "ERROR")

        return metadata, False

    def check_tiff_metadata(self, file_path):
        """
        Check for metadata in TIFF files by analyzing file structure
        Returns tuple of (metadata_dict, has_metadata)
        """
        metadata = {}
        try:
            with open(file_path, 'rb') as f:
                # Check TIFF header
                header = f.read(4)
                if header not in (b'II*\x00', b'MM\x00*'):  # Intel or Motorola byte order
                    return None, False

                metadata['has_ifd'] = True
                return metadata, True

        except Exception as e:
            self.log_message(f"Error checking TIFF metadata for {file_path}: {str(e)}", "ERROR")

        return metadata, False

    def get_file_info(self, file_path):
        """
        Get basic file information using file command
        """
        try:
            file_output = subprocess.check_output(['file', '-b', file_path], 
                                               stderr=subprocess.PIPE).decode()
            return {'file_type': file_output.strip()}
        except Exception as e:
            self.log_message(f"Error getting file info for {file_path}: {str(e)}", "ERROR")
            return {}

    def extract_metadata(self, image_path):
        """
        Extract metadata using file analysis
        Returns tuple of (metadata_dict, has_metadata)
        """
        metadata = self.get_file_info(image_path)
        file_ext = os.path.splitext(image_path.lower())[1]
        
        try:
            if file_ext in {'.jpg', '.jpeg'}:
                meta, has_metadata = self.check_jpeg_metadata(image_path)
            elif file_ext in {'.tiff', '.tif'}:
                meta, has_metadata = self.check_tiff_metadata(image_path)
            else:
                meta, has_metadata = {}, False

            if meta:
                metadata.update(meta)
            return metadata, has_metadata

        except Exception as e:
            self.log_message(f"Error extracting metadata from {image_path}: {str(e)}", "ERROR")
            return None, False

    def get_file_size(self, file_path):
        """Get file size in human-readable format"""
        try:
            size = os.path.getsize(file_path)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        except:
            return "Unknown"

    def scan_directory(self, start_path):
        """Scan directory recursively for images with metadata"""
        try:
            for root, _, files in os.walk(start_path):
                for filename in files:
                    if self.is_image_file(filename):
                        full_path = os.path.join(root, filename)
                        try:
                            if os.access(full_path, os.R_OK):
                                # First check name pattern
                                if self.is_satellite_image_name(filename):
                                    file_size = self.get_file_size(full_path)
                                    metadata = self.get_file_info(full_path)
                                    self.log_message(f"Satellite image found (naming pattern): {full_path}")
                                    self.found_images.append({
                                        'path': full_path,
                                        'size': file_size,
                                        'metadata': metadata,
                                        'match_type': 'naming_pattern'
                                    })
                                    self._print_finding(filename, full_path, file_size, metadata, True)
                                else:
                                    # If not a satellite name pattern, check metadata
                                    metadata, has_metadata = self.extract_metadata(full_path)
                                    if metadata and has_metadata:
                                        file_size = self.get_file_size(full_path)
                                        self.log_message(f"Image with metadata found: {full_path}")
                                        self.found_images.append({
                                            'path': full_path,
                                            'size': file_size,
                                            'metadata': metadata,
                                            'match_type': 'metadata'
                                        })
                                        self._print_finding(filename, full_path, file_size, metadata, False)
                            
                        except Exception as e:
                            self.log_message(f"Error processing file {full_path}: {str(e)}", "ERROR")
                            
        except Exception as e:
            self.log_message(f"Error scanning directory {start_path}: {str(e)}", "ERROR")

    def _print_finding(self, filename, full_path, file_size, metadata, is_pattern_match):
        """Print formatted information about found image"""
        if is_pattern_match:
            print("\nSatellite image found! (identified by naming pattern)")
        else:
            print("\nPossible satellite image found! (has metadata)")
            
        print(f"File: {filename}")
        print(f"Path: {full_path}")
        print(f"Size: {file_size}")
        print("File Information:")
        
        if 'file_type' in metadata:
            print(f"File Type: {metadata['file_type']}")
        if 'has_exif' in metadata:
            print("Contains: EXIF metadata")
        if 'has_ifd' in metadata:
            print("Contains: TIFF Image File Directory")

def main():
    scanner = SatelliteImageScanner()
    
    if len(sys.argv) > 1:
        start_path = sys.argv[1]
    else:
        start_path = "/"
    
    print(f"\nStarting scan from: {start_path}")
    print("This may take a while depending on the directory size...\n")
    
    scanner.scan_directory(start_path)
    
    pattern_matches = sum(1 for img in scanner.found_images if img.get('match_type') == 'naming_pattern')
    metadata_matches = sum(1 for img in scanner.found_images if img.get('match_type') == 'metadata')
    
    print(f"\nScan complete! Found {len(scanner.found_images)} total images:")
    print(f"- {pattern_matches} identified by naming pattern")
    print(f"- {metadata_matches} identified by metadata")
    print(f"Check the log file '{scanner.log_file}' for detailed information.")

if __name__ == "__main__":
    main()
