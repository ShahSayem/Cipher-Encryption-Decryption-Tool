import base64
import os
import secrets

import streamlit as st

# Character Set (includes letters, digits, punctuation, whitespace, symbols, brackets, new lines, tabs)
CHARSET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~\n\t\r"
)


def clean_unsupported(text):
    plaintext =  ''.join(c for c in text if c in CHARSET)
    rem_char = [c for c in text if c not in CHARSET]
    return plaintext, rem_char

def char_to_index(c):
    if c not in CHARSET:
        raise ValueError(f"Unsupported character: '{c}'")
    return CHARSET.index(c)

def index_to_char(i):
    return CHARSET[i]

def generate_key(length):
    return ''.join(secrets.choice(CHARSET) for _ in range(length))

def vernam_encrypt(plaintext, key):
    if len(plaintext) != len(key):
        raise ValueError("Key length must match plaintext.")
    return ''.join(index_to_char((char_to_index(p) + char_to_index(k)) % len(CHARSET)) for p, k in zip(plaintext, key))

def vernam_decrypt(ciphertext, key):
    if len(ciphertext) != len(key):
        raise ValueError("Key length must match ciphertext.")
    return ''.join(index_to_char((char_to_index(c) - char_to_index(k) + len(CHARSET)) % len(CHARSET)) for c, k in zip(ciphertext, key))

def encode_base64(text):
    return base64.b64encode(text.encode()).decode()

def decode_base64(encoded_text):
    return base64.b64decode(encoded_text.encode()).decode()

st.set_page_config(page_title="Vernam Cipher Tool", layout="centered")
st.title("🔐 Vernam Cipher - Secure Encryption Tool")

option = st.sidebar.selectbox("Choose Action", ["Encrypt Text", "Decrypt Text"])

if option == "Encrypt Text":
    plaintext = st.text_area("Enter Plaintext").rstrip('\r\n')

    if st.button("Encrypt") and plaintext:
        key = generate_key(len(plaintext))
        ciphertext = vernam_encrypt(plaintext, key)
        encoded = encode_base64(ciphertext)

        st.success("Encryption Successful!")
        st.text("Encrypted Text:")
        st.code(encoded, language='text')
        
        st.text("Generated Key:")
        st.code(key, language='text')

elif option == "Decrypt Text":
    encoded_cipher = st.text_area("Enter Base64 Encrypted Text")
    key = st.text_input("Enter Key", type="password")

    if st.button("Decrypt") and encoded_cipher and key:
        try:
            decoded_cipher = decode_base64(encoded_cipher)

            if len(decoded_cipher) != len(key):
                st.error("❌ Key length must match the decoded ciphertext length.")
                st.warning(f"Decoded ciphertext length: {len(decoded_cipher)} | Key length: {len(key)}")
            else:
                decrypted = vernam_decrypt(decoded_cipher, key)
                st.success("Decryption Successful!")
                st.text("Decrypted Text:")
                st.code(decrypted, language='text')
        except Exception as e:
            st.error(f"Error: {str(e)}")
