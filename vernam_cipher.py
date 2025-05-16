import base64
import secrets
import streamlit as st

# -----------------------------------
# Charset and Helper Functions
# -----------------------------------
CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~\n\t\r"
)

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
    return CHARSET[i]

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
        rows.append(list(cipher[index:index+count]))
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
        if 32 <= ascii_code <= 126:  # Printable ASCII range
            shifted = (ascii_code - 32 + shift) % 95 + 32
            result += chr(shifted)
        else:
            result += char  # Leave non-printable characters (like \n) unchanged
    return result

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift % 95)


# -----------------------------------
# Streamlit UI
# -----------------------------------

st.set_page_config(page_title="🔐 Cipher Tools", layout="wide")
st.title("🔐 Cipher Tools :")
st.caption("Encrypt and decrypt your text using classic ciphers!")

st.sidebar.title("🔄 Navigation")
cipher_choice = st.sidebar.radio("Choose a Cipher", ["Vernam Cipher", "Rail Fence Cipher", "Caesar Cipher"])

st.sidebar.markdown("---")
st.sidebar.caption("Made with ❤️")
st.sidebar.caption("by Ferdous, Nadim, Hasan & Sayem")

st.divider()

if cipher_choice == "Vernam Cipher":
    st.header("✨ Vernam Cipher")
    option = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)

    if option == "Encrypt":
        plaintext = st.text_area("Enter Plaintext")
        if st.button("🔒 Encrypt") and plaintext:
            cleaned_text, removed_chars = clean_unsupported(plaintext)
            if removed_chars:
                st.warning(f"Removed unsupported characters: {removed_chars}")
            if not cleaned_text:
                st.error("Plaintext is empty after cleaning.")
            else:
                key = generate_key(len(cleaned_text))
                ciphertext = vernam_encrypt(cleaned_text, key)
                st.success("Encryption Successful!")
                with st.expander("🔐 View Encrypted Text & Key"):
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

st.divider()
st.caption("🍀 Secure your message with style!")
