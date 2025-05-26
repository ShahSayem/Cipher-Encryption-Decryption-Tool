import base64
import secrets
import streamlit as st
import numpy as np
from streamlit_navigation_bar import st_navbar

# -----------------------------------
# Charset and Helper Functions
# -----------------------------------
CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~\n\t\r"
)

CHARSET2 = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~"
)

ALPHABET = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

def show_about():
    st.header("👨‍💻 Meet the Developers")
    st.markdown("---")

    developers = [
        {
            "name": "Md Mahmud Hossain Ferdous",
            "id": "2122020003",
            "email": "mahmudhossainferdous@gmail.com",
            "profile": "https://www.linkedin.com/in/ferdousmh/",
            "photo": "https://media.licdn.com/dms/image/v2/D5603AQGAsCkHMOL_mw/profile-displayphoto-shrink_400_400/profile-displayphoto-shrink_400_400/0/1694715292090?e=1753920000&v=beta&t=iDkEOLEUMhLmqRWDVlDXwmm6TWTfkmnNMR7tpaSgKjo"
        },
        {
            "name": "Muhammad Nadim",
            "id": "2122020018",
            "email": "nadimthere0085@gmail.com",
            "profile": "https://www.linkedin.com/in/muhammad-nadim-183b2921a/",
            "photo": "https://media.licdn.com/dms/image/v2/D4E03AQFp80mAifNDTQ/profile-displayphoto-shrink_400_400/profile-displayphoto-shrink_400_400/0/1690458140061?e=1753920000&v=beta&t=t7Y4c-gkKY8MJV8u4dxdjjVTe4LmccBk5oiY7bWS-Og"
        },
        {
            "name": "Hasan Ahmad",
            "id": "2122020030",
            "email": "softenghasan25@gmail.com",
            "profile": "https://www.linkedin.com/in/hasan-ahmad-502391204/",
            "photo": "https://media.licdn.com/dms/image/v2/D5603AQH7Ctm2T7xoTg/profile-displayphoto-shrink_400_400/profile-displayphoto-shrink_400_400/0/1726560534662?e=1753920000&v=beta&t=etDupAZiTqAhzlV7jkn3UBELyhQu8KcGBAj3UdpcqFk"
        },
        {
            "name": "Shah Sayem Ahmad",
            "id": "2122020043",
            "email": "shahsayemahmad@gmail.com",
            "profile": "https://shahsayem.netlify.app",
            "photo": "https://avatars.githubusercontent.com/u/68594531?s=400&u=36e37ad1ee9f678c531196a1016de2397c5c8be7&v=4"
        }
    ]

    profile_text = ""
        
    for dev in developers:
        if dev["profile"] == "https://shahsayem.netlify.app":
            profile_text = "Portfolio"
        else:
            profile_text = "LinkedIn"

        st.markdown(f"""
        <div style='display: flex; align-items: center; gap: 20px; padding: 16px; margin-bottom: 16px; background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 12px;'>
            <img src="{dev['photo']}" width="100" height="100" style="border-radius: 50%; border: 2px solid #ccc;" alt="profile photo">
            <div>
                <h4 style="margin-bottom: 5px;">{dev['name']}</h4>
                <p style='margin: 2px 0;'>🆔 <b>ID:</b> {dev["id"]}</p>
                <p style='margin: 2px 0;'>📧 <b>Email:</b> <a href='mailto:{dev["email"]}'>{dev["email"]}</a></p>
                <p style='margin: 2px 0;'>🔗 <b>Profile:</b> <a href='{dev["profile"]}' target='_blank'>{profile_text}</a></p>
            </div>
        </div>
        """, unsafe_allow_html=True)

if len(CHARSET) != len(set(CHARSET)):
    st.error("❌ CHARSET has duplicate characters!")

def clean_unsupported(text):
    cleaned = ''.join(c for c in text if c in CHARSET)
    removed = [c for c in text if c not in CHARSET]
    return cleaned, removed

def char_to_index(c):
    if c not in CHARSET:
        raise ValueError(f"Unsupported character: '{c}'")
    return CHARSET.index(c)

def index_to_char(i):
    return CHARSET[i % len(CHARSET)]

def generate_key(length):
    return ''.join(secrets.choice(CHARSET) for _ in range(length))

def vernam_encrypt(plaintext, key):
    if len(plaintext) != len(key):
        raise ValueError("Key length must match plaintext length for encryption.")
    return ''.join(index_to_char((char_to_index(p) + char_to_index(k)) % len(CHARSET)) for p, k in zip(plaintext, key))

def vernam_decrypt(ciphertext, key):
    if len(ciphertext) != len(key):
        raise ValueError("Key length must match ciphertext length for decryption.")
    return ''.join(index_to_char((char_to_index(c) - char_to_index(k) + len(CHARSET)) % len(CHARSET)) for c, k in zip(ciphertext, key))

def encode_base64(text):
    return base64.b64encode(text.encode()).decode()

def decode_base64(encoded_text):
    return base64.b64decode(encoded_text.encode()).decode()

def encrypt_rail_fence(text, key):
    if key <= 1 or not text:
        return text
    rails = ['' for _ in range(key)]
    row, direction_down = 0, False
    for char in text:
        rails[row] += char
        if row == 0 or row == key - 1:
            direction_down = not direction_down
        row += 1 if direction_down else -1
    return ''.join(rails)

def decrypt_rail_fence(cipher, key):
    if key <= 1 or not cipher:
        return cipher
    pattern = ['' for _ in range(len(cipher))]
    row, direction_down = 0, None
    for i in range(len(cipher)):
        pattern[i] = row
        if row == 0:
            direction_down = True
        elif row == key - 1:
            direction_down = False
        row += 1 if direction_down else -1
    row_counts = [pattern.count(r) for r in range(key)]
    index = 0
    rows = []
    for count in row_counts:
        rows.append(list(cipher[index:index + count]))
        index += count
    result, row_indices = [], [0] * key
    for r in pattern:
        result.append(rows[r][row_indices[r]])
        row_indices[r] += 1
    return ''.join(result)

def caesar_encrypt(text, shift):
    result = ''
    for char in text:
        ascii_code = ord(char)
        if 32 <= ascii_code <= 126:
            shifted = (ascii_code - 32 + shift) % 95 + 32
            result += chr(shifted)
        else:
            result += char
    return result

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift % 95)

# -----------------------------------
# Hill Cipher Functions
# -----------------------------------

def text_to_numbers(text, charset):
    return [charset.index(c) for c in text]

def numbers_to_text(numbers, charset):
    return ''.join(charset[n % len(charset)] for n in numbers)

def matrix_mod_inv(matrix, modulus):
    n = matrix.shape[0]
    det = int(round(np.linalg.det(matrix))) % modulus
    if np.gcd(det, modulus) != 1:
        raise ValueError(f"Matrix determinant ({det}) is not invertible modulo {modulus}. Try with a different key!")
    det_inv = pow(det, -1, modulus)

    if n == 2:
        a, b, c, d = matrix.flatten()
        adj = np.array([[d, -b], [-c, a]])
    elif n == 3:
        adj = np.zeros((3, 3), dtype=int)
        for r in range(3):
            for c in range(3):
                minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
                sign = (-1) ** (r + c)
                adj[c][r] = sign * int(round(np.linalg.det(minor)))  # note transpose
    else:
        raise ValueError("Only 2x2 and 3x3 matrices are supported.")

    return (det_inv * adj) % modulus

def hill_process(text, key_text, mode, size, charset):
    modulus = len(charset)
    if charset == ALPHABET:
        text = text.upper()
        key_text = key_text.upper()

    unsupported_text = [c for c in text if c not in charset]
    unsupported_key = [c for c in key_text if c not in charset]
    if unsupported_text or unsupported_key:
        raise ValueError(
            f"Unsupported characters detected in Text or Key!\n\n"
            f"Allowed characters: 'A-Z' and 'a-z' for Classic Hill Cipher."
        )    
    text = ''.join(c for c in text if c in charset)
    
    n = size
    key_nums = text_to_numbers(key_text, charset)
    if len(key_nums) != n * n:
        raise ValueError(f"Key must consist of {n*n} characters!")
    key_matrix = np.array(key_nums).reshape(n, n)
    if len(text) % n != 0:
        text += charset[0] * (n - len(text) % n)
    chunks = [text[i:i + n] for i in range(0, len(text), n)]
    result = ''
    if mode == 'decrypt':
        key_matrix = matrix_mod_inv(key_matrix, modulus)
    for chunk in chunks:
        vec = np.array(text_to_numbers(chunk, charset)).reshape(n, 1)
        res = np.dot(key_matrix, vec) % modulus
        result += numbers_to_text(res.flatten(), charset)
    return result

# -----------------------------------
# Streamlit UI
# -----------------------------------

st.set_page_config(page_title="🔐 Cipher Tools", layout="wide")

page = st_navbar(["Cipher Tools", "About Us"])
if page == "About Us":
    show_about()
else:
    st.title("🔐 Cipher Tools :")
    st.caption("Encrypt and decrypt your text using classic ciphers with a modern touch!")

    st.sidebar.title("🔄 Navigation")
    cipher_choice = st.sidebar.radio("Choose a Cipher", ["Rail Fence Cipher", "Hill Cipher",  "Caesar Cipher", "Vernam Cipher"])

    st.sidebar.markdown("---")
    st.sidebar.caption("Made with ❤️ by")
    st.sidebar.caption("Ferdous, Nadim, Hasan & Sayem")

    st.divider()

    if cipher_choice == "Vernam Cipher":
        st.header("✨ Vernam Cipher")
        option = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)

        if option == "Encrypt":
            plaintext = st.text_area("Enter Plaintext")
            if st.button("🔒 Encrypt") and plaintext:
                cleaned_text, removed_chars = clean_unsupported(plaintext)
                if removed_chars:
                    st.warning(f"Removed unsupported characters !!!")
                if not cleaned_text:
                    st.error("Plaintext is empty after cleaning.")
                else:
                    key = generate_key(len(cleaned_text))
                    ciphertext = vernam_encrypt(cleaned_text, key)
                    st.success("Encryption Successful!")
                    with st.expander("🔐 View Encrypted Text & Key"):
                        st.text("Encrypted Text:")
                        st.code(encode_base64(ciphertext), "text")
                        st.text("Generated Key:")
                        st.code(encode_base64(key), "text")

        else:
            encoded_cipher = st.text_area("Enter Base64 Encrypted Text")
            encoded_key = st.text_area("Enter Base64 Key")
            if st.button("🔓 Decrypt") and encoded_cipher and encoded_key:
                try:
                    decoded_cipher = decode_base64(encoded_cipher)
                    key = decode_base64(encoded_key)
                    if len(decoded_cipher) != len(key):
                        st.error("Key length mismatch.")
                    else:
                        decrypted = vernam_decrypt(decoded_cipher, key)
                        st.success("Decryption Successful!")
                        st.code(decrypted, "text")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    elif cipher_choice == "Rail Fence Cipher":
        st.header("🚉 Rail Fence Cipher")
        option = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)

        if option == "Encrypt":
            plaintext = st.text_area("Enter Plaintext")
            key = st.number_input("Number of Rails", min_value=2, step=1)
            if st.button("🔒 Encrypt") and plaintext:
                ciphertext = encrypt_rail_fence(plaintext, int(key))
                st.success("Encryption Successful!")
                st.code(ciphertext, "text")

        else:
            ciphertext = st.text_area("Enter Ciphertext")
            key = st.number_input("Number of Rails", min_value=2, step=1)
            if st.button("🔓 Decrypt") and ciphertext:
                plaintext = decrypt_rail_fence(ciphertext, int(key))
                st.success("Decryption Successful!")
                st.code(plaintext, "text")

    elif cipher_choice == "Caesar Cipher":
        st.header("🍀 Caesar Cipher")
        option = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)

        if option == "Encrypt":
            plaintext = st.text_area("Enter Plaintext")
            shift = st.slider("Shift Amount", min_value=1, max_value=25, value=3)
            if st.button("🔒 Encrypt") and plaintext:
                ciphertext = caesar_encrypt(plaintext, shift)
                st.success("Encryption Successful!")
                st.code(ciphertext, "text")

        else:
            ciphertext = st.text_area("Enter Ciphertext")
            shift = st.slider("Shift Amount", min_value=1, max_value=25, value=3)
            if st.button("🔓 Decrypt") and ciphertext:
                plaintext = caesar_decrypt(ciphertext, shift)
                st.success("Decryption Successful!")
                st.code(plaintext, "text")

    elif cipher_choice == "Hill Cipher":
        st.header("🔺 Hill Cipher")

        section = st.selectbox("Choose Type", ["Classic Hill Cipher (A-Z only)", "Modern Hill Cipher (95-char set)"])
        action = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)
        matrix_type = st.selectbox("Matrix Size", ["2x2", "3x3"], key="hill_type")
        text = st.text_area("Enter Plaintext" if action == "Encrypt" else "Enter Ciphertext")

        matrix_type = st.selectbox("Matrix Size", ["2x2", "3x3"], key="matrix_type")
        key_text = st.text_input("Enter Key Text (4 characters)" if matrix_type=="2x2" else "Enter Key Text (9 characters)")

        button_label = "🔒 Encrypt" if action == "Encrypt" else "🔓 Decrypt"

        if st.button(button_label) and text and key_text:
            try:
                mode = 'encrypt' if action == "Encrypt" else 'decrypt'
                size = 2 if matrix_type == "2x2" else 3
                charset = ALPHABET if "Classic" in section else CHARSET2
                result = hill_process(text, key_text, mode, size, charset)
                st.success(f"{action}ion Successful!")
                st.code(result, "text")
            except Exception as e:
                st.error(f"Error: {str(e)}")

    st.divider()
    st.caption("🍀 Secure your message with style!")
