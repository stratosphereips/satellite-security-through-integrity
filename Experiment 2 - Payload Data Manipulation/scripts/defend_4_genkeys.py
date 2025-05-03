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
