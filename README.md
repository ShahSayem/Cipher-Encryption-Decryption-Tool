# 🔐 Vernam Cipher - Streamlit Encryption Tool

A secure, character-based encryption/decryption tool built with **Streamlit**, implementing the **Vernam Cipher (One-Time Pad)** with added features like:

- ✅ Custom CHARSET for maximum character support
- ✅ Base64 encoding for safe storage and sharing
- ✅ Key generation, encryption, and decryption with validation
- ✅ User-friendly interface for text operations

---

## 🌐 Live Demo

🔗 [vernamcipher.streamlit.app](https://vernamcipher.streamlit.app/)

---

## 🚀 Features

- 🔤 Encrypt & decrypt **text** securely using a random key
- 🔑 Automatically generates a secure key of the same length
- 🔐 Uses a stable and extended character set to support special symbols, punctuation, whitespace, and control characters
- 🧼 Filters out unsupported characters and warns users
- 📦 Base64 encodes both ciphertext and key for sharing
- 💥 Full validation with informative error messages

---

## 🧩 Character Set

The app supports a wide range of characters via a custom `CHARSET` defined as a **list** (not string) for safe index handling:

```python
CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\"",.<>?/\\`~\n\t\r"
)
```

✅ This includes:

- Letters and digits
- All standard punctuation
- Whitespace: spaces, tabs, newlines
- Control character: `\r` (carriage return)

---

## 📋 How to Use

### ▶️ Run Locally

```bash
# Clone the repository
git clone https://github.com/ShahSayem/Vernam-Cipher-Encryption-Decryption-Tool.git
cd Vernam-Cipher-Encryption-Decryption-Tool

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run vernam_cipher.py
```

### 🧑‍💻 From the UI:

1. Select **Encrypt Text** or **Decrypt Text** from the sidebar
2. Enter text or Base64 content
3. View encrypted/decrypted result
4. Copy key and result using Streamlit's copy-friendly layout

---

## 📁 File Structure

```
vernam-cipher-streamlit/
├── vernam_cipher.py       # Main Streamlit application
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
```

---

## 📦 `requirements.txt`

```
streamlit>=1.30.0
```

You can add more dependencies later if needed for file support or zip compression.

---

## 📌 To Improve or Extend

- ✅ Add file encryption support
- ✅ Package encrypted file + key into a `.zip`
- 🔐 Add password protection
- 🧾 Add support for Unicode or emojis via UTF-8 byte handling

---

## 📜 License

This project is licensed under the MIT License.

---

## ✨ Developed by

**Shah Sayem Ahmad**\
🔗 [vernamcipher.streamlit.app](https://vernamcipher.streamlit.app/)

