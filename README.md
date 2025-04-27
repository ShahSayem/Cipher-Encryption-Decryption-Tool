# 🔐 Cipher Encryption-Decryption Tool

A secure, user-friendly encryption and decryption tool built with **Streamlit**, implementing classic ciphers:

- ✅ **Vernam Cipher**
- ✅ **Rail Fence Cipher**
- ✅ **Caesar Cipher**

All enhanced with validation, Base64 encoding where needed, and a clean modern UI.

---

## 🌐 Live Demo

🔗 [ciphertool.streamlit.app](https://ciphertool.streamlit.app/)

---

## 🚀 Features

- 🔤 Encrypt & decrypt **text** securely with multiple ciphers
- 🔑 Auto key generation (Vernam)
- 🧼 Filters out unsupported characters (Vernam)
- 📦 Base64 encoding/decoding for Vernam Cipher
- 🎛️ Adjustable parameters (like rails for Rail Fence and shift for Caesar)
- 💥 Full validation with informative error messages
- 🎨 Interactive, mobile-friendly Streamlit UI

---

## 🧩 Character Set (Vernam Cipher)

The app supports a wide range of characters for Vernam encryption using a custom CHARSET:

```python
CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\"",.<>?/\\`~\n\t\r"
)
```

✅ Includes:
- Letters (A-Z, a-z)
- Digits (0-9)
- Standard punctuation
- Whitespace: space, tab, newline
- Carriage return (`\r`)

---

## 📋 How to Use

### ▶️ Run Locally

```bash
# Clone the repository
git clone https://github.com/ShahSayem/Cipher-Encryption-Decryption-Tool.git
cd Cipher-Encryption-Decryption-Tool

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run cipher_tool.py
```

### 🧑‍💻 Using the UI:

1. Select your cipher (Vernam, Rail Fence, Caesar) from sidebar
2. Choose **Encrypt** or **Decrypt**
3. Enter the required input
4. View encrypted/decrypted result
5. Copy output easily with Streamlit's built-in copy functionality

---

## 📁 File Structure

```
Cipher-Encryption-Decryption-Tool/
├── cipher_tool.py        # Main Streamlit application
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
```

---

## 📦 `requirements.txt`

```
streamlit>=1.30.0
```

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
**[Shah Sayem Ahmad](https://shahsayem.netlify.app/)** 
**[Md Mahmud Hossain Ferdous](https://www.linkedin.com/in/ferdousmh/)** 
**[Hasan Ahmad](https://www.linkedin.com/in/hasan-ahmad-502391204/)** 

---

## 🌐 Links
🔗 [Cipher Encryption-Decryption Tool](https://ciphertool.streamlit.app/)
🔗 [GitHub Repository](https://github.com/ShahSayem/Cipher-Encryption-Decryption-Tool)
