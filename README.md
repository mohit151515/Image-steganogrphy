# 🔒 Secure Image Steganography Using Gradio

## 📌 Overview
This project allows you to **hide secret messages inside images securely** using steganography and retrieve them using a password. It features a **Gradio-based web UI** for easy interaction.

## ✨ Features
- **Encrypt** a message inside an image using a password
- **Decrypt** the hidden message with the correct password
- **Gradio-based UI** for a seamless experience

## 🖥️ Installation & Usage
### 1️⃣ Install Dependencies
First, clone the repository and install the required packages:
```sh
pip install -r requirements.txt
```

### 2️⃣ Run the Gradio App
```sh
python app.py
```
This will launch the Gradio web interface in your browser.

## 🛠️ Technologies Used
- **Python**
- **Gradio** (for UI)
- **OpenCV** (for image processing)
- **NumPy**
- **Pillow** (for image handling)

## 📷 Example Usage
1. Upload an image.
2. Enter a message and password for encryption.
3. Download the encrypted image.
4. Upload the encrypted image, enter the password, and retrieve the hidden message.

## 🛡️ Security Note
- The message is stored securely using hashed passwords.
- Ensure you use **large images** for better security.

## 📜 License
MIT License - Free to use and modify!

## 💡 Contributing
Pull requests are welcome! If you find issues or have improvements, feel free to open one.

## 📬 Contact
For any questions, reach out via GitHub issues.

🚀 **Happy Steganography!**


