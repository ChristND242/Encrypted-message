import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
import base64
from io import BytesIO
import time
from hashlib import sha256
import json

# --------------------- LANGUAGE DICTIONARY ---------------------
LANG = {
    "en": {
        "title": "🔒 Enhanced Encrypted Messaging Tool",
        "help_title": "Help - How to Use the App",
        "help_content": """
        **Welcome to the Enhanced Encrypted Messaging Tool!**

        ### Introduction to Cryptography
        Cryptography is the art of securing information through the use of codes so that only intended recipients can understand it. This app allows you to use several cryptographic techniques to encrypt and decrypt messages and files.

        ### Features and How to Use Them:

        1. **Symmetric Encryption (Fernet)**:
            - **Encryption**: Type a message, choose the time limit, and click 'Encrypt with Fernet' to get the encrypted message along with the Fernet key.
            - **Decryption**: Input the encrypted message and the Fernet key to decrypt it within the time limit.

        2. **Asymmetric Encryption (RSA)**:
            - **Encryption**: Type a message and click 'Encrypt Message with RSA' to get the encrypted message using the RSA public key.
            - **Decryption**: Input the encrypted message and your RSA private key to decrypt it.

        3. **AES Encryption (Password-Based)**:
            - **Encryption**: Enter a password, type a message, and click 'Encrypt Message with AES' to get the encrypted message.
            - **Decryption**: Input the encrypted message and the same password to decrypt it.

        4. **File Encryption (Time-Bound)**:
            - **Encryption**: Upload a file, choose the time limit, and click 'Encrypt File' to get the encrypted file along with the Fernet key.
            - **Decryption**: Upload the encrypted file and input the Fernet key to decrypt it within the time limit.

        5. **Encryption Workflow Visualization**:
            - **Encryption Workflow**: Visualize each step involved in encrypting a message.
            - **Decryption Workflow**: Visualize each step involved in decrypting a message.

        ### Key Terms:
        - **Encryption**: The process of converting readable data (plaintext) into unreadable data (ciphertext).
        - **Decryption**: The process of converting ciphertext back into plaintext.
        - **Symmetric Encryption**: The same key is used for both encryption and decryption.
        - **Asymmetric Encryption**: Uses two keys—a public key for encryption and a private key for decryption.
        - **Time-Bound Encryption**: Encrypted data can only be decrypted for a certain period of time.

        Enjoy securing your messages and files with cryptography!
        """,
        "symmetric": "🔒 Symmetric Encryption (Fernet)",
        "message": "Enter a message to encrypt:",
        "expiry_label": "Select time for message expiration:",
        "encrypt_button": "Encrypt with Fernet",
        "decrypt_header": "🔓 Decrypt Symmetric Encrypted Message",
        "decrypt_message": "Enter the encrypted message (Base64 encoded):",
        "decrypt_key": "Enter the Fernet key:",
        "decrypt_button": "Decrypt Message",
        "key_label": "Symmetric Encryption Key (Fernet)",
        "public_key": "🔑 RSA Public Key",
        "rsa_message": "Enter a message to encrypt with RSA:",
        "rsa_encrypt": "Encrypt Message with RSA",
        "rsa_decrypt_header": "🔓 Decrypt RSA Encrypted Message",
        "rsa_decrypt_message": "Enter the encrypted RSA message (Base64 encoded):",
        "rsa_private_key": "Enter the RSA Private Key (PEM format):",
        "rsa_decrypt": "Decrypt RSA Message",
        "aes_header": "🔒 AES Password-Based Encryption",
        "aes_message": "Enter a message to encrypt with AES:",
        "aes_password": "Enter a password for AES encryption:",
        "aes_encrypt": "Encrypt Message with AES",
        "aes_decrypt_header": "🔓 Decrypt AES Encrypted Message",
        "aes_decrypt_message": "Enter the encrypted AES message (Base64 encoded):",
        "aes_decrypt_password": "Enter the AES password:",
        "aes_decrypt": "Decrypt AES Message",
        "file_encrypt_header": "🔒 File Encryption (Time-Bound)",
        "upload_file": "Choose a file to encrypt:",
        "file_expiry_label": "Select time for file expiration:",
        "encrypt_file_button": "Encrypt File",
        "file_decrypt_header": "🔓 Decrypt Encrypted File",
        "upload_encrypted_file": "Upload the encrypted file (Base64 encoded):",
        "file_decrypt_key": "Enter the Fernet key:",
        "decrypt_file_button": "Decrypt File",
        "workflow_encryption": "🔍 Encryption Workflow Visualization",
        "workflow_input": "Enter a message to visualize the encryption workflow:",
        "visualize_button": "Visualize Encryption Workflow",
        "workflow_decryption": "🔍 Decryption Workflow Visualization",
        "decryption_workflow_input": "Enter an encrypted message to visualize the decryption workflow:",
        "visualize_decrypt_button": "Visualize Decryption Workflow",
        "error_expired": "❌ Error: Decryption failed due to expired key or incorrect key.",
        "enter_valid_message": "⚠️ Please enter a valid message to visualize.",
        "copy_key": "📋 Copy Key",
        "download_key": "⬇️ Download Key",
        "select_time_unit": "Select Time Unit:",
        "time_quantity": "Enter Time Quantity:",
        "rsa_encryption_error": "⚠️ Please enter a message to encrypt with RSA.",
        "aes_encryption_error": "⚠️ Please enter both the message and password for AES encryption.",
        "file_encryption_error": "⚠️ Please upload a file to encrypt.",
        "file_decryption_error": "⚠️ Please upload the encrypted file and enter the Fernet key.",
        "combined_download_label": "Download Combined Encrypted File and Key:",
        "combined_download_button": "Download Combined File",
        "upload_combined_file": "Upload Combined Encrypted File:",
        "decrypt_combined_button": "Decrypt Combined File",
        "fernet_key_for_decryption": "Enter the Fernet Key for Decryption:",
    },
    "fr": {
        "title": "🔒 Outil Amélioré de Messagerie Chiffrée",
        "help_title": "Aide - Comment Utiliser l'Application",
        "help_content": """
        **Bienvenue dans l'Outil Amélioré de Messagerie Chiffrée !**

        ### Introduction à la Cryptographie
        La cryptographie est l'art de sécuriser les informations à l'aide de codes, de sorte que seuls les destinataires prévus puissent les comprendre. Cette application vous permet d'utiliser plusieurs techniques cryptographiques pour chiffrer et déchiffrer des messages et des fichiers.

        ### Fonctionnalités et Comment les Utiliser:

        1. **Chiffrement Symétrique (Fernet)** :
            - **Chiffrement** : Tapez un message, choisissez la durée, et cliquez sur 'Chiffrer avec Fernet' pour obtenir le message chiffré ainsi que la clé Fernet.
            - **Déchiffrement** : Saisissez le message chiffré et la clé Fernet pour le déchiffrer dans le délai imparti.

        2. **Chiffrement Asymétrique (RSA)** :
            - **Chiffrement** : Tapez un message et cliquez sur 'Chiffrer le Message avec RSA' pour obtenir le message chiffré en utilisant la clé publique RSA.
            - **Déchiffrement** : Saisissez le message chiffré et votre clé privée RSA pour le déchiffrer.

        3. **Chiffrement AES (Basé sur Mot de Passe)** :
            - **Chiffrement** : Entrez un mot de passe, tapez un message, et cliquez sur 'Chiffrer le Message avec AES' pour obtenir le message chiffré.
            - **Déchiffrement** : Saisissez le message chiffré et le même mot de passe pour le déchiffrer.

        4. **Chiffrement de Fichier (Limité dans le Temps)** :
            - **Chiffrement** : Téléchargez un fichier, choisissez la durée, et cliquez sur 'Chiffrer le Fichier' pour obtenir le fichier chiffré ainsi que la clé Fernet.
            - **Déchiffrement** : Téléchargez le fichier chiffré et saisissez la clé Fernet pour le déchiffrer dans le délai imparti.

        5. **Visualisation du Processus de Chiffrement** :
            - **Processus de Chiffrement** : Visualisez chaque étape impliquée dans le chiffrement d'un message.
            - **Processus de Déchiffrement** : Visualisez chaque étape impliquée dans le déchiffrement d'un message.

        ### Termes Clés :
        - **Chiffrement** : Le processus de conversion des données lisibles (texte en clair) en données illisibles (texte chiffré).
        - **Déchiffrement** : Le processus de conversion du texte chiffré en texte clair.
        - **Chiffrement Symétrique** : La même clé est utilisée pour le chiffrement et le déchiffrement.
        - **Chiffrement Asymétrique** : Utilise deux clés : une clé publique pour le chiffrement et une clé privée pour le déchiffrement.
        - **Chiffrement Limité dans le Temps** : Les données chiffrées ne peuvent être déchiffrées que pendant une certaine période.

        Profitez de la sécurisation de vos messages et fichiers grâce à la cryptographie !
        """,
        "symmetric": "🔒 Chiffrement Symétrique (Fernet)",
        "message": "Entrez un message à chiffrer :",
        "expiry_label": "Sélectionnez la durée d'expiration du message :",
        "encrypt_button": "Chiffrer avec Fernet",
        "decrypt_header": "🔓 Déchiffrer le Message Chiffré Symétriquement",
        "decrypt_message": "Entrez le message chiffré (encodé en Base64) :",
        "decrypt_key": "Entrez la clé Fernet :",
        "decrypt_button": "Déchiffrer le Message",
        "key_label": "Clé de Chiffrement Symétrique (Fernet)",
        "public_key": "🔑 Clé Publique RSA",
        "rsa_message": "Entrez un message à chiffrer avec RSA :",
        "rsa_encrypt": "Chiffrer le Message avec RSA",
        "rsa_decrypt_header": "🔓 Déchiffrer le Message Chiffré RSA",
        "rsa_decrypt_message": "Entrez le message RSA chiffré (encodé en Base64) :",
        "rsa_private_key": "Entrez la Clé Privée RSA (format PEM) :",
        "rsa_decrypt": "Déchiffrer le Message RSA",
        "aes_header": "🔒 Chiffrement AES Basé sur Mot de Passe",
        "aes_message": "Entrez un message à chiffrer avec AES :",
        "aes_password": "Entrez un mot de passe pour le chiffrement AES :",
        "aes_encrypt": "Chiffrer le Message avec AES",
        "aes_decrypt_header": "🔓 Déchiffrer le Message Chiffré AES",
        "aes_decrypt_message": "Entrez le message AES chiffré (encodé en Base64) :",
        "aes_decrypt_password": "Entrez le mot de passe AES :",
        "aes_decrypt": "Déchiffrer le Message AES",
        "file_encrypt_header": "🔒 Chiffrement de Fichier (Limité dans le Temps)",
        "upload_file": "Choisissez un fichier à chiffrer :",
        "file_expiry_label": "Sélectionnez la durée d'expiration du fichier :",
        "encrypt_file_button": "Chiffrer le Fichier",
        "file_decrypt_header": "🔓 Déchiffrer le Fichier Chiffré",
        "upload_encrypted_file": "Téléchargez le fichier chiffré (Base64 encodé) :",
        "file_decrypt_key": "Entrez la clé Fernet :",
        "decrypt_file_button": "Déchiffrer le Fichier",
        "workflow_encryption": "🔍 Visualisation du Processus de Chiffrement",
        "workflow_input": "Entrez un message pour visualiser le processus de chiffrement :",
        "visualize_button": "Visualiser le Processus de Chiffrement",
        "workflow_decryption": "🔍 Visualisation du Processus de Déchiffrement",
        "decryption_workflow_input": "Entrez un message chiffré pour visualiser le processus de déchiffrement :",
        "visualize_decrypt_button": "Visualiser le Processus de Déchiffrement",
        "error_expired": "❌ Erreur : Déchiffrement échoué en raison de la clé expirée ou incorrecte.",
        "enter_valid_message": "⚠️ Veuillez entrer un message valide pour visualiser.",
        "copy_key": "📋 Copier la Clé",
        "download_key": "⬇️ Télécharger la Clé",
        "select_time_unit": "Sélectionnez l'Unité de Temps :",
        "time_quantity": "Entrez la Quantité de Temps :",
        "rsa_encryption_error": "⚠️ Veuillez entrer un message à chiffrer avec RSA.",
        "aes_encryption_error": "⚠️ Veuillez entrer à la fois le message et le mot de passe pour le chiffrement AES.",
        "file_encryption_error": "⚠️ Veuillez télécharger un fichier à chiffrer.",
        "file_decryption_error": "⚠️ Veuillez télécharger le fichier chiffré et entrer la clé Fernet.",
        "combined_download_label": "Télécharger le Fichier Chiffré et la Clé Combinés :",
        "combined_download_button": "Télécharger le Fichier Combiné",
        "upload_combined_file": "Téléchargez le Fichier Chiffré Combiné :",
        "decrypt_combined_button": "Déchiffrer le Fichier Combiné",
        "fernet_key_for_decryption": "Entrez la Clé Fernet pour le Déchiffrement :",
    }
}

# --------------------- TIME UNIT TRANSLATION ---------------------
TIME_UNITS = {
    "en": ["Seconds", "Minutes", "Hours", "Days", "Weeks", "Months", "Years"],
    "fr": ["Secondes", "Minutes", "Heures", "Jours", "Semaines", "Mois", "Années"]
}

# --------------------- TIME UNIT CONVERSION FUNCTION ---------------------
def convert_time_to_seconds(quantity, unit, language):
    """
    Converts the given time quantity and unit to seconds.

    Args:
        quantity (int): The amount of time.
        unit (str): The unit of time.
        language (str): Language code ("en" or "fr").

    Returns:
        int: Time in seconds.
    """
    unit = unit.lower()
    if language == "en":
        mapping = {
            "seconds": 1,
            "minutes": 60,
            "hours": 3600,
            "days": 86400,
            "weeks": 604800,
            "months": 2592000,  # Approximation: 30 days
            "years": 31536000    # Approximation: 365 days
        }
    else:  # French
        mapping = {
            "secondes": 1,
            "minutes": 60,
            "heures": 3600,
            "jours": 86400,
            "semaines": 604800,
            "mois": 2592000,     # Approximation: 30 days
            "années": 31536000   # Approximation: 365 days
        }
    return quantity * mapping.get(unit, 1)

# --------------------- AES ENCRYPTION FUNCTIONS ---------------------
def encrypt_aes(message, key):
    """
    Encrypts a message using AES (EAX mode) with a password-derived key.

    Args:
        message (str): The plaintext message to encrypt.
        key (str): The password to derive the AES key.

    Returns:
        str: The encrypted message encoded in Base64.
    """
    key = sha256(key.encode()).digest()  # Derive a 32-byte key from the password
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    encrypted_data = nonce + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_aes(ciphertext, key):
    """
    Decrypts an AES-encrypted message using a password-derived key.

    Args:
        ciphertext (str): The encrypted message encoded in Base64.
        key (str): The password to derive the AES key.

    Returns:
        str or None: The decrypted message if successful, else None.
    """
    try:
        key = sha256(key.encode()).digest()  # Derive a 32-byte key from the password
        encrypted_data = base64.b64decode(ciphertext)
        nonce = encrypted_data[:16]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(encrypted_data[16:])
        return plaintext.decode('utf-8')
    except Exception:
        return None

# --------------------- FILE ENCRYPTION FUNCTIONS ---------------------
def encrypt_file(file_bytes, key):
    """
    Encrypts file bytes using Fernet.

    Args:
        file_bytes (bytes): The binary data of the file to encrypt.
        key (bytes): The Fernet key.

    Returns:
        bytes: The encrypted file data.
    """
    fernet_cipher = Fernet(key)
    encrypted_file = fernet_cipher.encrypt(file_bytes)
    return encrypted_file

def decrypt_file(encrypted_file_bytes, key):
    """
    Decrypts file bytes using Fernet.

    Args:
        encrypted_file_bytes (bytes): The encrypted file data.
        key (bytes): The Fernet key.

    Returns:
        bytes or None: The decrypted file data if successful, else None.
    """
    try:
        fernet_cipher = Fernet(key)
        decrypted_file = fernet_cipher.decrypt(encrypted_file_bytes)
        return decrypted_file
    except InvalidToken:
        return None
    except Exception:
        return None

# --------------------- PAGE CONFIGURATION ---------------------
st.set_page_config(page_title="Enhanced Encryption Tool", layout="wide", page_icon="🔒")

# --------------------- LANGUAGE SELECTION ---------------------
language = st.sidebar.selectbox("Choose Language / Choisissez la langue", ["English", "Français"])


if language == "English":
    lang = LANG.get("en", LANG["en"])  # Defaults to English if the key is missing
    lang_code = "en"
elif language == "Français":
    lang = LANG.get("fr", LANG["en"])  # Defaults to English if the key is missing
    lang_code = "fr"
else:
    lang = LANG["en"]  
    lang_code = "en"

# --------------------- HELP SECTION ---------------------
st.sidebar.title(lang["help_title"])
st.sidebar.markdown(lang["help_content"])

# --------------------- RSA KEY GENERATION ---------------------
# Generate RSA keys if not already in session
if 'rsa_private_key' not in st.session_state:
    st.session_state.rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    st.session_state.rsa_private_key_pem = st.session_state.rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    st.session_state.rsa_public_key_pem = st.session_state.rsa_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

# --------------------- TABS CREATION ---------------------
tabs = st.tabs([
    lang["symmetric"],
    lang["rsa_encrypt"],
    lang["aes_header"],
    lang["file_encrypt_header"],
    lang["workflow_encryption"],
    lang["workflow_decryption"]
])

# --------------------- SYMMETRIC ENCRYPTION TAB ---------------------
with tabs[0]:
    st.header(lang["symmetric"])

    # Encryption Section
    st.subheader("🔒 " + "Encryption")
    message = st.text_area(lang["message"], height=100, key="symmetric_message_input")

    st.markdown("**" + lang["expiry_label"] + "**")
    time_unit = st.selectbox(lang["select_time_unit"], TIME_UNITS[lang_code], key="symmetric_time_unit")
    time_quantity = st.number_input(lang["time_quantity"], min_value=1, step=1, key="symmetric_time_quantity")

    if st.button(lang["encrypt_button"], key="symmetric_encrypt_button"):
        if message:
            ttl_seconds = convert_time_to_seconds(time_quantity, time_unit, lang_code)
            fernet_key = Fernet.generate_key()
            fernet_cipher = Fernet(fernet_key)
            encrypted_message = fernet_cipher.encrypt(message.encode())
            encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
            fernet_key_b64 = fernet_key.decode('utf-8')

            st.success("✅ Message encrypted successfully!")
            st.markdown("**Encrypted Message (Base64 encoded):**")
            st.code(encrypted_message_b64, language="text")

            st.markdown("**" + lang["key_label"] + ":**")
            st.code(fernet_key_b64, language="text")

            # Provide options to copy or download the key
            col1, col2 = st.columns(2)
            with col1:
                if st.button(lang["copy_key"], key="copy_symmetric_key"):
                    st.write("🔑 **Fernet Key Copied to Clipboard!**")
                    st.experimental_set_query_params(fernet_key=fernet_key_b64)
            with col2:
                st.download_button(label=lang["download_key"], data=fernet_key_b64, file_name="fernet_key.key")

            # Option to download encrypted message and key together
            st.subheader("📥 Download Encrypted Data and Key Together")
            combined_data_txt = f"Encrypted Message:\n{encrypted_message_b64}\n\nFernet Key:\n{fernet_key_b64}"
            st.download_button(
                label="⬇️ Download Combined Encrypted Data and Key",
                data=combined_data_txt,
                file_name="encrypted_data_and_key.txt",
                mime="text/plain",
                key="download_combined_symmetric"
            )

        else:
            st.error("⚠️ Please enter a message to encrypt.")

    # Decryption Section
    st.subheader(lang["decrypt_header"])
    decrypt_message = st.text_area(lang["decrypt_message"], height=100, key="symmetric_decrypt_message_input")
    decrypt_key = st.text_input(lang["decrypt_key"], key="symmetric_decrypt_key_input")

    if st.button(lang["decrypt_button"], key="symmetric_decrypt_button"):
        if decrypt_message and decrypt_key:
            try:
                # Validate Fernet key format
                if len(decrypt_key.encode()) != 44:
                    raise ValueError("Invalid Fernet key length.")

                encrypted_message_bytes = base64.b64decode(decrypt_message)
                fernet_cipher = Fernet(decrypt_key.encode())
                decrypted_message = fernet_cipher.decrypt(encrypted_message_bytes).decode('utf-8')
                st.success("✅ Message decrypted successfully!")
                st.code(decrypted_message, language="text")
            except (InvalidToken, ValueError, base64.binascii.Error):
                st.error(lang["error_expired"])
            except Exception:
                st.error(lang["error_expired"])
        else:
            st.error("⚠️ Please enter both the encrypted message and the Fernet key.")

# --------------------- ASYMMETRIC ENCRYPTION (RSA) TAB ---------------------
with tabs[1]:
    st.header(lang["public_key"])

    # Display RSA Public Key
    st.subheader(lang["public_key"])
    public_key_pem = st.session_state.rsa_public_key_pem
    st.code(public_key_pem, language="text")

    # Provide options to copy or download the public key
    col1, col2 = st.columns(2)
    with col1:
        if st.button(lang["copy_key"], key="copy_rsa_public_key"):
            st.write("🔑 **RSA Public Key Copied to Clipboard!**")
            st.experimental_set_query_params(rsa_public_key=public_key_pem)
    with col2:
        st.download_button(label=lang["download_key"], data=public_key_pem, file_name="rsa_public_key.pem")

    # Encryption Section
    st.subheader("🔒 " + "Encryption")
    rsa_message = st.text_area(lang["rsa_message"], height=100, key="rsa_message_input")

    if st.button(lang["rsa_encrypt"], key="rsa_encrypt_button"):
        if rsa_message:
            try:
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                encrypted_rsa_message = public_key.encrypt(
                    rsa_message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_rsa_message_b64 = base64.b64encode(encrypted_rsa_message).decode('utf-8')

                st.success("✅ RSA Message encrypted successfully!")
                st.markdown("**Encrypted RSA Message (Base64 encoded):**")
                st.code(encrypted_rsa_message_b64, language="text")

                # Option to download encrypted message and public key together
                st.subheader("📥 Download Encrypted Data and Public Key Together")
                combined_data_txt = f"Encrypted RSA Message:\n{encrypted_rsa_message_b64}\n\nPublic Key:\n{public_key_pem}"
                st.download_button(
                    label="⬇️ Download Combined Encrypted Data and Public Key",
                    data=combined_data_txt,
                    file_name="encrypted_rsa_data_and_key.txt",
                    mime="text/plain",
                    key="download_combined_rsa"
                )

            except Exception:
                st.error(lang["rsa_encryption_error"])
        else:
            st.error(lang["rsa_encryption_error"])

    # Decryption Section
    st.subheader(lang["rsa_decrypt_header"])
    rsa_decrypt_message = st.text_area(lang["rsa_decrypt_message"], height=100, key="rsa_decrypt_message_input")
    rsa_private_key_input = st.text_area(lang["rsa_private_key"], height=200, key="rsa_private_key_input")

    if st.button(lang["rsa_decrypt"], key="rsa_decrypt_button"):
        if rsa_decrypt_message and rsa_private_key_input:
            try:
                # Validate RSA private key format
                private_key = serialization.load_pem_private_key(
                    rsa_private_key_input.encode(),
                    password=None,
                )
                encrypted_rsa_message_bytes = base64.b64decode(rsa_decrypt_message)
                decrypted_rsa_message = private_key.decrypt(
                    encrypted_rsa_message_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8')
                st.success("✅ RSA Message decrypted successfully!")
                st.code(decrypted_rsa_message, language="text")
            except (ValueError, InvalidToken, base64.binascii.Error):
                st.error(lang["error_expired"])
            except Exception:
                st.error(lang["error_expired"])
        else:
            st.error("⚠️ Please enter both the encrypted RSA message and the RSA private key.")

# --------------------- AES ENCRYPTION TAB ---------------------
with tabs[2]:
    st.header(lang["aes_header"])

    # Encryption Section
    st.subheader("🔒 " + "Encryption")
    aes_message = st.text_area(lang["aes_message"], height=100, key="aes_message_input")
    aes_password = st.text_input(lang["aes_password"], key="aes_password_input", type="password")

    if st.button(lang["aes_encrypt"], key="aes_encrypt_button"):
        if aes_message and aes_password:
            encrypted_aes_message = encrypt_aes(aes_message, aes_password)
            if encrypted_aes_message:
                st.success("✅ AES Message encrypted successfully!")
                st.markdown("**Encrypted AES Message (Base64 encoded):**")
                st.code(encrypted_aes_message, language="text")
            else:
                st.error(lang["aes_encryption_error"])
        else:
            st.error(lang["aes_encryption_error"])

    # Decryption Section
    st.subheader(lang["aes_decrypt_header"])
    aes_decrypt_message = st.text_area(lang["aes_decrypt_message"], height=100, key="aes_decrypt_message_input")
    aes_decrypt_password = st.text_input(lang["aes_decrypt_password"], key="aes_decrypt_password_input", type="password")

    if st.button(lang["aes_decrypt"], key="aes_decrypt_button"):
        if aes_decrypt_message and aes_decrypt_password:
            decrypted_aes_message = decrypt_aes(aes_decrypt_message, aes_decrypt_password)
            if decrypted_aes_message:
                st.success("✅ AES Message decrypted successfully!")
                st.code(decrypted_aes_message, language="text")
            else:
                st.error(lang["error_expired"])
        else:
            st.error("⚠️ Please enter both the encrypted AES message and the AES password.")

            

# --------------------- FILE ENCRYPTION (TIME-BOUND) TAB ---------------------
with tabs[3]:
    st.header(lang["file_encrypt_header"])

    # Encryption Section
    st.subheader("🔒 " + "Encryption")
    uploaded_file = st.file_uploader(lang["upload_file"], type=None, key="file_upload_input")

    st.markdown("**" + lang["file_expiry_label"] + "**")
    file_time_unit = st.selectbox(lang["select_time_unit"], TIME_UNITS[lang_code], key="file_time_unit")
    file_time_quantity = st.number_input(lang["time_quantity"], min_value=1, step=1, key="file_time_quantity")

    if st.button(lang["encrypt_file_button"], key="encrypt_file_button"):
        if uploaded_file:
            try:
                ttl_seconds = convert_time_to_seconds(file_time_quantity, file_time_unit, lang_code)
                fernet_key = Fernet.generate_key()
                fernet_cipher = Fernet(fernet_key)
                file_bytes = uploaded_file.read()
                encrypted_file = encrypt_file(file_bytes, fernet_key)
                encrypted_file_b64 = base64.b64encode(encrypted_file).decode('utf-8')
                fernet_key_b64 = fernet_key.decode('utf-8')

                st.success("✅ File encrypted successfully!")
                st.markdown("**Encrypted File (Base64 encoded):**")
                st.code(encrypted_file_b64, language="text")

                st.markdown("**" + lang["key_label"] + ":**")
                st.code(fernet_key_b64, language="text")

                # Provide options to copy or download the key
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(lang["copy_key"], key="copy_file_fernet_key"):
                        st.write("🔑 **Fernet Key Copied to Clipboard!**")
                        st.experimental_set_query_params(fernet_key=fernet_key_b64)
                with col2:
                    st.download_button(label=lang["download_key"], data=fernet_key_b64, file_name="fernet_key.key")

                # Option to download the encrypted file
                st.markdown("---")
                st.markdown("**" + "🔗 Encrypted File Download:" + "**")
                st.download_button(
                    label="⬇️ Download Encrypted File",
                    data=encrypted_file_b64,
                    file_name="encrypted_file.b64",
                    mime="text/plain"
                )

                # Option to download combined key and encrypted file as JSON
                combined_data = {
                    "fernet_key": fernet_key_b64,
                    "encrypted_file": encrypted_file_b64
                }
                combined_json = json.dumps(combined_data, indent=4)
                st.markdown("**" + lang["combined_download_label"] + "**")
                st.download_button(
                    label=lang["combined_download_button"],
                    data=combined_json,
                    file_name="encrypted_file_with_key.json",
                    mime="application/json"
                )

            except Exception:
                st.error(lang["file_encryption_error"])
        else:
            st.error(lang["file_encryption_error"])

    # Decryption Section
    st.subheader(lang["file_decrypt_header"])
    uploaded_encrypted_file = st.file_uploader(lang["upload_encrypted_file"], type=None, key="encrypted_file_upload_input")
    file_decrypt_key = st.text_input(lang["file_decrypt_key"], key="file_decrypt_key_input")

    # Option to upload combined file
    st.markdown("**" + "OR" + "**")
    uploaded_combined_file = st.file_uploader(lang["upload_combined_file"], type=["json"], key="combined_file_upload_input")

    if st.button(lang["decrypt_file_button"], key="decrypt_file_button"):
        if uploaded_encrypted_file and file_decrypt_key:
            try:
                # Validate Fernet key format
                if len(file_decrypt_key.encode()) != 44:
                    raise ValueError("Invalid Fernet key length.")

                encrypted_file_b64 = uploaded_encrypted_file.read().decode('utf-8')
                encrypted_file_bytes = base64.b64decode(encrypted_file_b64)
                fernet_cipher = Fernet(file_decrypt_key.encode())
                decrypted_file = decrypt_file(encrypted_file_bytes, file_decrypt_key.encode())
                decrypted_file_b64 = base64.b64encode(decrypted_file).decode('utf-8')

                st.success("✅ File decrypted successfully!")
                st.markdown("**Decrypted File (Base64 encoded):**")
                st.code(decrypted_file_b64, language="text")

                # Provide option to download decrypted file
                st.download_button(
                    label="⬇️ Download Decrypted File",
                    data=decrypted_file,
                    file_name="decrypted_file",
                    mime="application/octet-stream"
                )

            except (InvalidToken, ValueError, base64.binascii.Error):
                st.error(lang["file_decryption_error"])
            except Exception:
                st.error(lang["file_decryption_error"])

        elif uploaded_combined_file:
            try:
                combined_json = uploaded_combined_file.read().decode('utf-8')
                combined_data = json.loads(combined_json)
                fernet_key_b64 = combined_data.get("fernet_key")
                encrypted_file_b64 = combined_data.get("encrypted_file")

                if not fernet_key_b64 or not encrypted_file_b64:
                    raise ValueError("Invalid combined file format.")

                # Validate Fernet key format
                if len(fernet_key_b64.encode()) != 44:
                    raise ValueError("Invalid Fernet key length.")

                encrypted_file_bytes = base64.b64decode(encrypted_file_b64)
                fernet_cipher = Fernet(fernet_key_b64.encode())
                decrypted_file = decrypt_file(encrypted_file_bytes, fernet_key_b64.encode())
                decrypted_file_b64 = base64.b64encode(decrypted_file).decode('utf-8')

                st.success("✅ Combined File decrypted successfully!")
                st.markdown("**Decrypted File (Base64 encoded):**")
                st.code(decrypted_file_b64, language="text")

                # Provide option to download decrypted file
                st.download_button(
                    label="⬇️ Download Decrypted File",
                    data=decrypted_file,
                    file_name="decrypted_file",
                    mime="application/octet-stream"
                )

            except (InvalidToken, ValueError, json.JSONDecodeError, base64.binascii.Error):
                st.error(lang["file_decryption_error"])
            except Exception:
                st.error(lang["file_decryption_error"])
        else:
            st.error(lang["file_decryption_error"])

# --------------------- ENCRYPTION WORKFLOW VISUALIZATION TAB ---------------------
with tabs[4]:
    st.header(lang["workflow_encryption"])
    workflow_message = st.text_input(lang["workflow_input"], key="workflow_encryption_input")

    if st.button(lang["visualize_button"], key="workflow_visualize_button"):
        if workflow_message:
            # Generate Fernet key and cipher
            fernet_key = Fernet.generate_key()
            fernet_cipher = Fernet(fernet_key)

            # Encrypt the message
            encrypted_message = fernet_cipher.encrypt(workflow_message.encode())
            encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
            fernet_key_b64 = fernet_key.decode('utf-8')

            # Store encrypted message and key in session state for later use
            st.session_state["fernet_key_b64"] = fernet_key_b64
            st.session_state["encrypted_message_b64"] = encrypted_message_b64

            # Define the steps for visualization
            steps = [
                ("Original Message", workflow_message),
                ("Message as Bytes", str(workflow_message.encode())),
                ("Fernet Key", fernet_key_b64),
                ("Message Encrypted (Base64)", encrypted_message_b64)
            ]

            # Display each step
            for step, description in steps:
                st.subheader(step)
                st.code(description, language="text")

            st.markdown("---")  # Separator

            # Option to download encrypted message and key together
            st.subheader("📥 Download Encrypted Data and Key Together")
            combined_data = {
                "encrypted_message": encrypted_message_b64,
                "fernet_key": fernet_key_b64
            }
            combined_json = json.dumps(combined_data, indent=4)

            st.download_button(
                label="⬇️ Download Combined Encrypted Data and Key",
                data=combined_json,
                file_name="encrypted_data_and_key.json",
                mime="application/json",
                key="download_combined"
            )

            st.markdown("---")  # Separator

            # Option to download encrypted message separately
            st.subheader("📥 Download Encrypted Message")
            st.download_button(
                label="⬇️ Download Encrypted Message (Base64)",
                data=encrypted_message_b64,
                file_name="encrypted_message.txt",
                mime="text/plain",
                key="download_encrypted_message"
            )

            st.markdown("---")  # Separator

            # Option to download Fernet key separately
            st.subheader("🔑 Download Fernet Key")
            st.download_button(
                label="⬇️ Download Fernet Key",
                data=fernet_key_b64,
                file_name="fernet_key.key",
                mime="text/plain",
                key="download_fernet_key"
            )

            st.markdown("---")  # Separator

            # Optionally, allow users to copy the key and encrypted message to clipboard
            st.subheader("📋 Copy Encrypted Data and Key")
            col1, col2 = st.columns(2)
            with col1:
                # Using Streamlit's experimental clipboard functionality
                st.button(
                    label=lang["copy_key"],
                    key="copy_symmetric_key",
                    on_click=lambda: st.session_state.update({"copied_symmetric_key": True})
                )
                if st.session_state.get("copied_symmetric_key"):
                    st.success("🔑 **Fernet Key Copied to Clipboard!**")
            with col2:
                st.button(
                    label="📋 Copy Encrypted Message",
                    key="copy_encrypted_message",
                    on_click=lambda: st.session_state.update({"copied_encrypted_message": True})
                )
                if st.session_state.get("copied_encrypted_message"):
                    st.success("🔒 **Encrypted Message Copied to Clipboard!**")

            # Implement actual clipboard copy using Streamlit components or JavaScript
            # Below is a simple implementation using Streamlit's components
            # Note: This requires the user to click the copy buttons again to trigger the copy
            if st.session_state.get("copied_symmetric_key"):
                components.html(f"""
                    <script>
                        navigator.clipboard.writeText("{fernet_key_b64}");
                    </script>
                """, height=0, width=0)
                st.session_state["copied_symmetric_key"] = False  # Reset after copying

            if st.session_state.get("copied_encrypted_message"):
                components.html(f"""
                    <script>
                        navigator.clipboard.writeText("{encrypted_message_b64}");
                    </script>
                """, height=0, width=0)
                st.session_state["copied_encrypted_message"] = False  # Reset after copying

        else:
            st.error(lang["enter_valid_message"])


# --------------------- DECRYPTION WORKFLOW VISUALIZATION TAB ---------------------
with tabs[5]:
    st.header(lang["workflow_decryption"])
    
    # Option 1: Decryption via Uploaded Combined File
    st.subheader("🔓 Decryption via Uploaded Combined File")
    uploaded_combined_file = st.file_uploader(
        "Upload the combined Encrypted Message and Fernet Key file (JSON format):",
        type=["json"],
        key="decryption_combined_file_upload"
    )
    
    if uploaded_combined_file is not None:
        try:
            combined_data = json.load(uploaded_combined_file)
            encrypted_message_b64 = combined_data.get("encrypted_message")
            fernet_key = combined_data.get("fernet_key")
            
            if not encrypted_message_b64 or not fernet_key:
                st.error("❌ The uploaded file is missing the encrypted message or Fernet key.")
            else:
                # Attempt to decrypt
                try:
                    # Validate Fernet key format
                    if len(fernet_key.encode()) != 44:
                        raise ValueError("Invalid Fernet key length.")
                    
                    encrypted_message_bytes = base64.b64decode(encrypted_message_b64)
                    fernet_cipher = Fernet(fernet_key.encode())
                    decrypted_message = fernet_cipher.decrypt(encrypted_message_bytes).decode('utf-8')
                    
                    st.success("✅ File decrypted successfully!")
                    st.markdown("**Decrypted Message:**")
                    st.code(decrypted_message, language="text")
                    
                    # Option to download the decrypted message
                    st.download_button(
                        label="⬇️ Download Decrypted Message",
                        data=decrypted_message,
                        file_name="decrypted_message.txt"
                    )
                except (InvalidToken, ValueError, binascii.Error) as e:
                    st.error("❌ Decryption failed. Please ensure that the encrypted message and Fernet key are correct.")
        except json.JSONDecodeError:
            st.error("❌ Failed to parse the uploaded file. Please ensure it's a valid JSON file.")
    
    st.markdown("---")  # Separator
    
    # Option 2: Decryption via Manual Input
    st.subheader("🔓 Decryption via Manual Input")
    
    # Encrypted Message Input
    encrypted_message_input = st.text_area(
        "Enter the Encrypted Message (Base64 encoded):",
        height=100,
        key="manual_encrypted_message_input"
    )
    
    # Fernet Key Input
    fernet_key_input = st.text_input(
        "Enter the Fernet Key for Decryption:",
        key="manual_fernet_key_input",
        type="password"  # Hide the key input for security
    )
    
    # Decrypt Button
    if st.button(
        "🔍 Visualize Decryption Workflow",
        key="visualize_decrypt_button"
    ):
        if encrypted_message_input and fernet_key_input:
            try:
                # Validate Fernet key format
                if len(fernet_key_input.encode()) != 44:
                    raise ValueError("Invalid Fernet key length.")
                
                # Decode the encrypted message from Base64
                encrypted_message_bytes = base64.b64decode(encrypted_message_input)
                
                # Initialize Fernet cipher
                fernet_cipher = Fernet(fernet_key_input.encode())
                
                # Decrypt the message
                decrypted_message = fernet_cipher.decrypt(encrypted_message_bytes).decode('utf-8')
                
                # Define the steps for visualization
                steps = [
                    ("Encrypted Message (Base64)", encrypted_message_input),
                    ("Encrypted Message as Bytes", str(encrypted_message_bytes)),
                    ("Fernet Key Used for Decryption", "Provided by User"),
                    ("Message Decrypted", decrypted_message)
                ]
                
                # Display each step
                for step, description in steps:
                    st.subheader(step)
                    st.code(description, language="text")
                
                # Option to download the decrypted message
                st.download_button(
                    label="⬇️ Download Decrypted Message",
                    data=decrypted_message,
                    file_name="decrypted_message.txt"
                )
            except (InvalidToken, ValueError, binascii.Error) as e:
                st.error("❌ Decryption failed. Please ensure that the encrypted message and Fernet key are correct.")
            except Exception as e:
                st.error("❌ An unexpected error occurred during decryption.")
        else:
            st.error("⚠️ Please enter both the encrypted message and the Fernet key.")
    
    st.markdown("---")  # Separator
    
    # Option 3: Download Encrypted Data and Key Together
    st.subheader("📥 Download Encrypted Data and Key Together")
    
    if st.session_state.get("fernet_key_b64") and st.session_state.get("encrypted_message_b64"):
        combined_data = {
            "encrypted_message": st.session_state["encrypted_message_b64"],
            "fernet_key": st.session_state["fernet_key_b64"]
        }
        combined_json = json.dumps(combined_data, indent=4)
        
        st.download_button(
            label="⬇️ Download Combined Encrypted Data and Key",
            data=combined_json,
            file_name="encrypted_data_and_key.json",
            mime="application/json"
        )
    else:
        st.info("🔒 Encrypted message and key are not available for download.")


# Footer
st.markdown("""
    <footer style='text-align: center; padding: 10px; font-size: 14px; color: #ABB2B9;'>
    Created with ❤️ by Christ.ND
    </footer>
    <style>
        /* Hide Streamlit menu */
        #MainMenu {visibility: hidden;}


        /* Optional: Hide the "Made with Streamlit" watermark in the bottom-right corner */
        .css-1outpf7 {display: none;}
    </style>
    """, unsafe_allow_html=True)

# Custom CSS for animated background and initials
st.markdown(
    """
    <style>
    body {
        background: radial-gradient(ellipse at bottom, #1b2735 0%, #090a0f 100%);
        height: 100vh;
        overflow: hidden;
        display: flex;
        font-family: 'Anton', sans-serif;
        justify-content: center;
        align-items: center;
        perspective: 1000px;
    }

    .container {
        position: relative;
        display: grid;
        grid-template-rows: repeat(20, 5vh);
        grid-template-columns: repeat(20, 5vw);
        transform-style: preserve-3d;
    }

    .monitor {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        transform-style: preserve-3d;
    }

    .trigger {
        &:hover ~ .monitor .camera {
            transform: rotateY(-30deg);
        }
    }

    .camera {
        position: absolute;
        width: 100%;
        height: 100%;
        transform-style: preserve-3d;
        transition: 500ms;
        transform: rotateY(-30deg);
    }

    .vr {
        position: absolute;
        top: 50%;
        left: 50%;
        width: 350px;  /* Adjust size as needed */
        height: 350px; /* Adjust size as needed */
        transform: translate(-50%, -50%);
        transform-style: preserve-3d;
    }

    .vr_layer {
        position: absolute;
        display: flex;
        justify-content: center;
        align-items: center;
        width: 100%;
        height: 100%;
        border: 1px solid rgba(255, 255, 255, 0.2);
        background: rgba(9, 255, 255, 0.006);
        border-radius: 10px;
        transform: preserve-3d;
    }

    .vr_layer_item {
        width: 70%;
        height: 70%;
        border: 3px solid #fff;
        border-radius: 100%;
        background: rgba(0, 0, 0, 0.05);
        animation: sphere 3000ms cubic-bezier(0.215, 0.610, 0.355, 1.000) alternate infinite, color 5000ms linear alternate infinite;
        transition: 500ms;
    }

    @keyframes sphere {
        0% {
            transform: scale(0) rotateZ(45deg);
        }
        100% {
            transform: scale(1) rotateZ(45deg);
        }
    }

    @keyframes color {
        0% {
            border-color: #f55;
        }
        100% {
            border-color: #5f5;
        }
    }

    .initials {
        position: absolute;
        top: 50%;
        left: 50%;
        width: 100px;  /* Adjust size as needed */
        height: 100px; /* Adjust size as needed */
        border-radius: 50%;
        background: rgba(9, 255, 255, 0.1);
        color: #fff;
        font-size: 48px; /* Size of initials */
        display: flex;
        justify-content: center;
        align-items: center;
        border: 3px solid rgba(255, 255, 255, 0.5);
        box-shadow: 0 0 20px rgba(0, 150, 255, 0.5);
        transform: translate(-50%, -50%);
        transition: transform 0.5s;
    }

    .initials:hover {
        transform: translate(-50%, -50%) rotateZ(15deg);
    }

    </style>
    """,
    unsafe_allow_html=True
)

# Add an HTML structure for the animation and initials
st.markdown(
    """
    <div class="container">
        <div class="trigger"></div>
        <div class="monitor">
            <div class="camera">
                <div class="vr">
                    <!-- 20 layers of VR items -->
                    <div class="vr_layer">
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                        <div class="vr_layer_item"></div>
                    </div>
                    <div class="initials">C.ND</div>
                </div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)
