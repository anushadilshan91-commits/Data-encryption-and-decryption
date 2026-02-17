import base64
import os
import getpass  # This hides your typing!
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# --- 1. CONFIGURATION ---
# I am setting the password here, but getpass will hide it in the terminal
MASTER_PASSWORD = "anusha" 
SALT = b'venom_static_salt' 

def generate_key_from_password(password: str):
    """Generates a secure key from the text password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# --- 2. MAIN SYSTEM ---
def main():
    print("="*40)
    print("      VENOM SECURE SYSTEM v3.0      ")
    print("="*40)

    # getpass.getpass() makes your typing invisible!
    user_input = getpass.getpass("Enter Master Password: ")

    if user_input != MASTER_PASSWORD:
        print("\n❌ Access Denied! Wrong Password.")
        return

    # Create the locker engine
    key = generate_key_from_password(user_input)
    cipher_suite = Fernet(key)

    print("\n✅ Access Granted!")
    print("[1] SENDER: Create an Encrypted Code")
    print("[2] RECEIVER: Decrypt a Pasted Code")
    
    choice = input("\nChoose (1 or 2): ")

    if choice == "1":
        # --- SENDER MODE ---
        message = input("\nType the secret message: ")
        encrypted_text = cipher_suite.encrypt(message.encode()).decode()
        
        print("\n" + "-"*50)
        print("🔐 COPY THIS CODE EXACTLY:")
        print(encrypted_text)
        print("-" * 50)
        print("Tip: Send this code to your friend.")

    elif choice == "2":
        # --- RECEIVER MODE ---
        print("\n--- Manual Decryption Mode ---")
        pasted_code = input("Paste the ENCRYPTED code here: ").strip()
        
        try:
            # We clean the code with .strip() to avoid the "Corrupted" error
            decrypted_message = cipher_suite.decrypt(pasted_code.encode()).decode()
            print("\n" + "="*40)
            print(f"🔓 SECRET MESSAGE: {decrypted_message}")
            print("="*40)
        except Exception:
            print("\n❌ [Error] Decryption failed!")
            print("Reason: You pasted the wrong code or used the wrong password.")
    
    else:
        print("\nInvalid choice. Goodbye!")

if __name__ == "__main__":
    main()