from tkinter import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
from tkinter import filedialog
from stegano import lsb
import os

class AuthenticationGUI:
    def __init__(self, master):
        self.master = master
        master.title("Sign-up and Login")
        master.geometry("400x200")
        master.resizable(False, False)
        master.configure(bg="#283747")

        self.label = Label(master, text="Choose an action:", font=("Helvetica", 14), bg="#283747", fg="white")
        self.label.pack(pady=10)

        self.signup_button = Button(master, text="Sign Up", font=("Helvetica", 12), command=self.show_signup)
        self.signup_button.pack(pady=10)

        self.login_button = Button(master, text="Login", font=("Helvetica", 12), command=self.show_login)
        self.login_button.pack(pady=10)

        self.result_label = Label(master, text="", font=("Helvetica", 12), bg="#283747", fg="white")
        self.result_label.pack()

    def show_signup(self):
        self.master.withdraw()  # Hide the current window
        signup_window = Toplevel(self.master)
        SignupGUI(signup_window, self)

    def show_login(self):
        self.master.withdraw()  # Hide the current window
        login_window = Toplevel(self.master)
        LoginGUI(login_window, self)


class SignupGUI:
    def __init__(self, master, auth_gui):
        self.master = master
        master.title("Sign Up")
        master.geometry("400x250")
        master.resizable(False, False)
        master.configure(bg="#283747")

        self.auth_gui = auth_gui

        self.label_username = Label(master, text="Username:", font=("Helvetica", 12), bg="#283747", fg="white")
        self.label_username.pack(pady=5)

        self.entry_username = Entry(master, width=30, font=("Helvetica", 12))
        self.entry_username.pack(pady=5)

        self.label_password = Label(master, text="Password:", font=("Helvetica", 12), bg="#283747", fg="white")
        self.label_password.pack(pady=5)

        self.entry_password = Entry(master, width=30, font=("Helvetica", 12), show="*")
        self.entry_password.pack(pady=5)

        self.signup_button = Button(master, text="Sign Up", font=("Helvetica", 12), command=self.signup)
        self.signup_button.pack(pady=10)

        self.result_label = Label(master, text="", font=("Helvetica", 12), bg="#283747", fg="white")
        self.result_label.pack()

    def signup(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        # Check if the username already exists
        if self.check_username_exists(username):
            self.result_label.config(text="Username already exists.")
        else:
            # Save the new credentials
            self.save_credentials(username, password)
            self.result_label.config(text="Sign-up successful.")
            self.auth_gui.show_login()
            self.master.destroy()

    def check_username_exists(self, username):
        # Read existing usernames from the file
        with open("usernames.txt", "r") as file:
            existing_usernames = [line.strip() for line in file.readlines()]

        return username in existing_usernames

    def save_credentials(self, username, password):
        # Save the new credentials to the file
        with open("usernames.txt", "a") as file:
            file.write(username + "\n")

        with open("credentials.txt", "a") as file:
            file.write(username + " " + password + "\n")


class LoginGUI:
    def __init__(self, master, auth_gui):
        self.master = master
        master.title("Login")
        master.geometry("400x200")
        master.resizable(False, False)
        master.configure(bg="#283747")

        self.auth_gui = auth_gui

        self.label_username = Label(master, text="Username:", font=("Helvetica", 12), bg="#283747", fg="white")
        self.label_username.pack(pady=5)

        self.entry_username = Entry(master, width=30, font=("Helvetica", 12))
        self.entry_username.pack(pady=5)

        self.label_password = Label(master, text="Password:", font=("Helvetica", 12), bg="#283747", fg="white")
        self.label_password.pack(pady=5)

        self.entry_password = Entry(master, width=30, font=("Helvetica", 12), show="*")
        self.entry_password.pack(pady=5)

        self.login_button = Button(master, text="Login", font=("Helvetica", 12), command=self.login)
        self.login_button.pack(pady=10)

        self.result_label = Label(master, text="", font=("Helvetica", 12), bg="#283747", fg="white")
        self.result_label.pack()

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        # Check if the entered credentials are valid
        if self.check_credentials(username, password):
            self.result_label.config(text="Login successful.")
            self.auth_gui.master.deiconify()  # Show the main window
            self.master.destroy()
            # If login is successful, you can proceed with the steganography application
            TripleDESEncryptionSteganographyGUI(self.auth_gui.master)
        else:
            self.result_label.config(text="Invalid username or password.")

    def check_credentials(self, username, password):
        # Read existing usernames and passwords from the file
        with open("credentials.txt", "r") as file:
            existing_credentials = [line.split() for line in file.readlines()]

        return any(entry == [username, password] for entry in existing_credentials)


class TripleDESEncryptionSteganographyGUI:
    def __init__(self, master):
        self.master = master
        master.title("3DES Encryption, Steganography, and Decryption")
        master.geometry("800x600")
        master.resizable(False, False)
        master.configure(bg="#283747")

        self.label = Label(master, text="Enter Text:", font=("Helvetica", 14), bg="#283747", fg="white")
        self.label.pack(pady=10)

        self.text_entry = Text(master, wrap=WORD, width=60, height=5, font=("Helvetica", 12))
        self.text_entry.pack()

        self.encrypt_button = Button(master, text="Encrypt and Hide", font=("Helvetica", 12), command=self.encrypt_and_hide)
        self.encrypt_button.pack(pady=10)

        self.encrypted_text_box = Text(master, wrap=WORD, width=60, height=5, font=("Helvetica", 12))
        self.encrypted_text_box.pack()

        self.decrypt_button = Button(master, text="Reveal and Decrypt", font=("Helvetica", 12), command=self.reveal_and_decrypt)
        self.decrypt_button.pack(pady=10)

        self.result_label = Label(master, text="", font=("Helvetica", 12), bg="#283747", fg="white")
        self.result_label.pack()

    def encrypt_text(self, text):
        key = os.urandom(24)  # Generate a random 24-byte key for TripleDES
        iv = os.urandom(8)    # Generate a random 8-byte IV for TripleDES

        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv))  # Use CFB mode
        encryptor = cipher.encryptor()

        # Encrypt the text
        encrypted_text = encryptor.update(text.encode('utf-8')) + encryptor.finalize()

        # Encode key and IV for later use during decryption
        encoded_key = b64encode(key).decode('utf-8')
        encoded_iv = b64encode(iv).decode('utf-8')

        return f"{encoded_key}:{encoded_iv}:{b64encode(encrypted_text).decode('utf-8')}"

    def decrypt_text(self, encrypted_text):
        try:
            # Split the encoded string into key, IV, and encrypted text
            encoded_key, encoded_iv, encoded_encrypted_text = encrypted_text.split(':')

            key = b64decode(encoded_key)
            iv = b64decode(encoded_iv)
            encrypted_text = b64decode(encoded_encrypted_text)

            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv))  # Use CFB mode
            decryptor = cipher.decryptor()

            # Decrypt the text
            decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()

            return decrypted_text.decode('utf-8')

        except Exception as e:
            raise ValueError(f"Decryption Error: {str(e)}")

    def encrypt_and_hide(self):
        text = self.text_entry.get("1.0", END).strip()
        if not text:
            self.result_label.config(text="Please enter text to hide.")
            return

        image_path = filedialog.askopenfilename(title="Select an Image")
        if not image_path:
            self.result_label.config(text="Please select an image.")
            return

        encrypted_text = self.encrypt_text(text)

        # Perform steganography
        secret = lsb.hide(image_path, encrypted_text)
        secret.save("steganographic_image.png")

        self.result_label.config(text="Text successfully encrypted and saved as steganographic_image.png.")
        self.encrypted_text_box.delete(1.0, END)  # Clear previous content
        self.encrypted_text_box.insert(INSERT, encrypted_text)

    def reveal_and_decrypt(self):
        image_path = filedialog.askopenfilename(title="Select the Steganographic Image")
        if not image_path:
            self.result_label.config(text="Please select the steganographic image.")
            return

        # Perform steganography decryption
        secret = lsb.reveal(image_path)
        encrypted_text = secret

        # Decrypt the text using TripleDES
        try:
            decrypted_text = self.decrypt_text(encrypted_text)
            self.result_label.config(text=f"Decrypted Text:\n{decrypted_text}")

        except ValueError as ve:
            self.result_label.config(text=str(ve))


if __name__ == "__main__":
    root = Tk()
    app = AuthenticationGUI(root)
    root.mainloop()
