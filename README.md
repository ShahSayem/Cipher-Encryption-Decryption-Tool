# 🔐 Cipher Encryption-Decryption Tool

A secure, interactive encryption and decryption tool built with **Streamlit**, implementing multiple classic cryptographic techniques:

* ✅ **Vernam Cipher** (One-Time Pad)
* ✅ **Rail Fence Cipher** (Transposition Cipher)
* ✅ **Caesar Cipher** (Substitution Cipher)
* ✅ **Hill Cipher** (Classic & Modern variants)

All ciphers are implemented with secure handling, validation, dynamic key generation (where applicable), and clean UI features for usability.

---

## 🌐 Live Demo

🔗 [ciphertool.streamlit.app](https://ciphertool.streamlit.app/)

---

## 🚀 Features

* 🔤 Encrypt & decrypt **text** securely using four classical ciphers
* 🧠 Supports both **simple and matrix-based encryption schemes**
* 🔑 **Auto key generation** for Vernam Cipher
* 📦 **Base64 encoding** (used for key and ciphertext in Vernam)
* 🧼 Filters unsupported characters (Vernam)
* 🧮 Customizable shift and key values (Caesar, Hill)
* 🎛️ Configurable parameters: number of rails (Rail Fence), matrix size and alphabet (Hill)
* 📲 Mobile-friendly, interactive Streamlit UI
* 🧾 Informative feedback and input validation

---

## 🔠 Character Set (for Vernam & Modern Hill)

```python
CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\"",.<>?/\\`~\n\t\r"
)
```

✅ Includes:

* Uppercase & lowercase letters
* Digits 0–9
* Punctuation/symbols
* Whitespace: space, tab (`\t`), newline (`\n`), carriage return (`\r`)

---

## 🛠️ Ciphers Overview

### 🔐 Vernam Cipher

* Character-level encryption using one-time pad
* Uses same-length key (auto-generated)
* Output is Base64 encoded for safe sharing

### 🚉 Rail Fence Cipher

* Rearranges characters based on zig-zag pattern
* Requires number of rails (≥2)

### 🍀 Caesar Cipher

* Each character is shifted by a fixed integer value
* Printable ASCII (from space to `~`) is supported

### 🔺 Hill Cipher

* Matrix-based cipher using 2x2 or 3x3 key matrix
* Supports **Classic (A–Z)** and **Modern (full charset)** versions
* Key must match matrix dimensions (length 4 for 2x2, 9 for 3x3)
* Includes matrix inversion modulo `len(charset)` for decryption

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

### 🧑‍💻 From the UI:

1. Choose a cipher from the sidebar
2. Select Encrypt or Decrypt
3. Provide plaintext/ciphertext and optional key or settings
4. Press the action button
5. See the result and copy from the output box

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
streamlit==1.35
numpy>=1.24.0
streamlit-navigation-bar
```

---

## 📌 Potential Improvements

* 📂 Add file upload & encryption support
* 🔐 Secure `.zip` packaging of encrypted message & key
* 🌍 Add UTF-8 support for full Unicode and emoji handling
* 🚀 Dockerfile for local containerized deployment
* 💡 Add dynamic cipher comparison or visualization

---

## 📜 License

This project is licensed under the **MIT License**.

---

## ✨ Developed by

* **[Shah Sayem Ahmad](https://shahsayem.netlify.app/)**
* **[Md Mahmud Hossain Ferdous](https://www.linkedin.com/in/ferdousmh/)**
* **[Hasan Ahmad](https://www.linkedin.com/in/hasan-ahmad-502391204/)**
* **[Muhammad Nadim](https://www.linkedin.com/in/muhammad-nadim-183b2921a/)**

---

## 🌐 Links

* 🔗 [Cipher Encryption-Decryption Tool](https://ciphertool.streamlit.app/)
* 🔗 [GitHub Repository](https://github.com/ShahSayem/Cipher-Encryption-Decryption-Tool)
* 🔗 [GitHub Repository for Flutter app](https://github.com/MHFerdous/Crypto-Project)
