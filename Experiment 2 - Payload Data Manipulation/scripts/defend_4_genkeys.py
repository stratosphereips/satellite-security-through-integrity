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

from wolfcrypt import ciphers
from wolfcrypt.utils import h2b, b2h
import os

def generate_key_pair(private_key_path, public_key_path):
    """Generate RSA key pair compatible with wolfcrypt."""
    try:
        # Create a new RSA key with 2048 bits
        rsa = ciphers.RsaPrivate.make_key(2048)
        
        # Export private and public keys
        private_key, public_key = rsa.encode_key()
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(private_key)
            
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
            
        print(f"Successfully generated keys:")
        print(f"Private key: {private_key_path}")
        print(f"Public key: {public_key_path}")
        
    except Exception as e:
        print(f"Error generating keys: {e}")
        raise

if __name__ == "__main__":
    # Create key directory if it doesn't exist
    key_dir = "key"
    os.makedirs(key_dir, exist_ok=True)
    
    # Generate key file paths
    private_key_path = os.path.join(key_dir, "private.der")
    public_key_path = os.path.join(key_dir, "public.der")
    
    generate_key_pair(private_key_path, public_key_path)
