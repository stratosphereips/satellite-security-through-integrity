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
import json
import re
from datetime import datetime
import sys

class MetadataCoordinateExtractor:
    def __init__(self):
        self.metadata_extensions = {
            '.json', '_meta.json', '.txt', '.xmp', '.xml', '.aux.xml'
        }
        self.found_coordinates = []
        self.log_file = f'coordinate_extraction_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        self.output_dir = 'extracted_coordinates'
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def log_message(self, message, level="INFO"):
        """Write message to log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, 'a') as f:
            f.write(f"{timestamp} - {level} - {message}\n")

    def is_metadata_file(self, filename):
        """Check if file is a metadata file"""
        return any(filename.endswith(ext) for ext in self.metadata_extensions)

    def extract_coordinates_from_json(self, content):
        """Extract coordinates from JSON content"""
        coords = []
        try:
            data = json.loads(content)
            
            # Check for GeoJSON-style footprint
            if 'footprint' in data:
                if 'coordinates' in data['footprint']:
                    coords.extend(data['footprint']['coordinates'][0])
                    return coords, 'geojson_footprint'
            
            # Check for direct lat/lon pairs
            if all(k in data for k in ['latitude', 'longitude']):
                coords.append([data['longitude'], data['latitude']])
                return coords, 'direct_latlon'
            
            # Check nested metadata/telemetry
            nested_keys = ['metadata', 'telemetry', 'location']
            for key in nested_keys:
                if key in data and isinstance(data[key], dict):
                    nested = data[key]
                    if all(k in nested for k in ['latitude', 'longitude']):
                        coords.append([nested['longitude'], nested['latitude']])
                        return coords, 'nested_latlon'
            
            # Check for corner coordinates
            corner_patterns = ['corner', 'bound', 'extent']
            for key in data.keys():
                if any(pattern in key.lower() for pattern in corner_patterns):
                    if isinstance(data[key], dict) and all(k in data[key] for k in ['latitude', 'longitude']):
                        coords.append([data[key]['longitude'], data[key]['latitude']])
            
            if coords:
                return coords, 'corner_coordinates'
                    
        except Exception as e:
            self.log_message(f"Error parsing JSON: {str(e)}", "ERROR")
        
        return coords, None

    def extract_coordinates_from_xml(self, content):
        """Extract coordinates from XML content"""
        coords = []
        try:
            # Extract GeoTransform
            geotransform_match = re.search(r'<GeoTransform>(.*?)</GeoTransform>', content, re.DOTALL)
            if geotransform_match:
                transform_values = [float(x) for x in geotransform_match.group(1).split(',')]
                if len(transform_values) == 6:
                    upper_left = [transform_values[0], transform_values[3]]
                    coords.append(upper_left)
                    return coords, 'geotransform'

            # Look for explicit coordinate tags
            coord_patterns = [
                r'<Coordinates?[^>]*>(.*?)</Coordinates?>',
                r'<GeoPosition[^>]*>(.*?)</GeoPosition>',
                r'<Location[^>]*>(.*?)</Location>'
            ]
            
            for pattern in coord_patterns:
                matches = re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    coord_content = match.group(1)
                    # Extract decimal degrees
                    dd_matches = re.finditer(r'(-?\d+\.\d+)', coord_content)
                    coord_values = [float(m.group(1)) for m in dd_matches]
                    if len(coord_values) >= 2:
                        coords.append([coord_values[0], coord_values[1]])
            
            if coords:
                return coords, 'xml_coordinates'
                
        except Exception as e:
            self.log_message(f"Error parsing XML: {str(e)}", "ERROR")
        
        return coords, None

    def extract_coordinates_from_text(self, content):
        """Extract coordinates from text content"""
        coords = []
        try:
            # Decimal degrees pattern
            dd_pattern = r'(-?\d+\.\d+)[,\s]+(-?\d+\.\d+)'
            dd_matches = re.finditer(dd_pattern, content)
            for match in dd_matches:
                coord = [float(match.group(1)), float(match.group(2))]
                if -180 <= coord[0] <= 180 and -90 <= coord[1] <= 90:
                    coords.append(coord)
            
            if coords:
                return coords, 'decimal_degrees'
            
            # DMS pattern
            dms_pattern = r'(\d+)°\s*(\d+)\'\s*(\d+(\.\d+)?)"([NS])[,\s]+(\d+)°\s*(\d+)\'\s*(\d+(\.\d+)?)"([EW])'
            dms_matches = re.finditer(dms_pattern, content)
            for match in dms_matches:
                lat = float(match.group(1)) + float(match.group(2))/60 + float(match.group(3))/3600
                if match.group(5) == 'S':
                    lat = -lat
                lon = float(match.group(6)) + float(match.group(7))/60 + float(match.group(8))/3600
                if match.group(10) == 'W':
                    lon = -lon
                coords.append([lon, lat])
            
            if coords:
                return coords, 'dms'
                
        except Exception as e:
            self.log_message(f"Error parsing text: {str(e)}", "ERROR")
        
        return coords, None

    def extract_coordinates(self, file_path):
        """Extract coordinates from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            coords = []
            format_found = None
            
            # Try JSON first
            if file_path.endswith(('.json', '_meta.json')):
                coords, format_found = self.extract_coordinates_from_json(content)
            
            # Try XML
            elif file_path.endswith(('.xml', '.xmp', '.aux.xml')):
                coords, format_found = self.extract_coordinates_from_xml(content)
            
            # Try text
            else:
                coords, format_found = self.extract_coordinates_from_text(content)

            if coords:
                # Save coordinates to output directory
                base_name = os.path.basename(file_path)
                output_filename = os.path.join(
                    self.output_dir,
                    f"{os.path.splitext(base_name)[0]}_coordinates.txt"
                )
                
                with open(output_filename, 'w') as f:
                    f.write(f"Source: {file_path}\n")
                    f.write(f"Format: {format_found}\n")
                    f.write("Coordinates (Longitude, Latitude):\n")
                    for coord in coords:
                        f.write(f"{coord[0]}, {coord[1]}\n")
                
                self.found_coordinates.append({
                    'source_file': file_path,
                    'format': format_found,
                    'coordinates': coords,
                    'output_file': output_filename
                })
                
                self.log_message(f"Extracted coordinates from {file_path} ({format_found})")
                print(f"\nFound coordinates in: {file_path}")
                print(f"Format: {format_found}")
                print("Coordinates:")
                for coord in coords:
                    print(f"  Longitude: {coord[0]}, Latitude: {coord[1]}")
                print(f"Saved to: {output_filename}\n")
                
        except Exception as e:
            self.log_message(f"Error processing file {file_path}: {str(e)}", "ERROR")

    def scan_directory(self, start_path):
        """Scan directory recursively for metadata files"""
        try:
            print(f"\nStarting scan from: {start_path}")
            print("Looking for metadata files...\n")
            
            for root, _, files in os.walk(start_path):
                for filename in files:
                    if self.is_metadata_file(filename):
                        full_path = os.path.join(root, filename)
                        if os.access(full_path, os.R_OK):
                            self.extract_coordinates(full_path)
            
            print("\nScan complete!")
            print(f"Found coordinates in {len(self.found_coordinates)} files")
            print(f"Results saved in '{self.output_dir}' directory")
            print(f"Check '{self.log_file}' for detailed log")
            
        except Exception as e:
            self.log_message(f"Error scanning directory {start_path}: {str(e)}", "ERROR")
            print(f"\nError scanning directory: {str(e)}")

def main():
    extractor = MetadataCoordinateExtractor()
    
    if len(sys.argv) > 1:
        start_path = sys.argv[1]
    else:
        start_path = "."
    
    extractor.scan_directory(start_path)

if __name__ == "__main__":
    main()
