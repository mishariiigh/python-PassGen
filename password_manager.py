import hashlib
import getpass

# Store users and hashed passwords
password_manager = {}

def hash_password(password: str) -> str:
    """Return the SHA-256 hash of the password."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_account():
    """Create a new account with username and password."""
    username = input("Enter your username: ").strip()
    if username in password_manager:
        print("Username already exists! Try a different one.")
        return

    password = getpass.getpass("Enter your password: ").strip()
    if not password:
        print("Password cannot be empty!")
        return

    password_manager[username] = hash_password(password)
    print("Account created successfully!")

def login():
    """Log in with existing username and password."""
    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ").strip()

    if password_manager.get(username) == hash_password(password):
        print("User logged in successfully!")
    else:
        print("Failed to log in!")

def main():
    """Main loop for account management."""
    while True:
        print("\nOptions:")
        print("1 - Create an account")
        print("2 - Login")
        print("0 - Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            create_account()
        elif choice == "2":
            login()
        elif choice == "0":
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
