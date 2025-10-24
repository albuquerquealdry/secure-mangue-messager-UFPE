# secure_messenger/crypto/encryption.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

AES_KEY_SIZE = 32  # 32 bytes = 256 bits
GCM_NONCE_SIZE = 12 # 12 bytes = 96 bits

def generate_aes_key() -> bytes:
    """Gera uma chave AES-256 aleatória."""
    return os.urandom(AES_KEY_SIZE)

def encrypt_aes_gcm(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    """
    Cifra dados usando AES-GCM (AEAD).
    
    Gera um 'nonce' (number used once) único para esta operação.
    A tag de autenticação é automaticamente anexada ao final do ciphertext
    pela biblioteca 'cryptography'.

    Args:
        plaintext (bytes): Os dados a serem cifrados.
        aes_key (bytes): A chave AES de 32 bytes.

    Returns:
        tuple: (ciphertext_with_tag, nonce)
               ciphertext_with_tag: Os dados cifrados + a tag de autenticação.
               nonce: O nonce de 12 bytes usado.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext deve ser 'bytes'.")
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("Chave AES deve ter 32 bytes.")

    # 1. Gerar um Nonce (Number Used Once)
    nonce = os.urandom(GCM_NONCE_SIZE)
    
    # 2. Inicializar o cifrador AES-GCM
    aesgcm = AESGCM(aes_key)
    
    # 3. Cifrar (sem dados associados, por isso 'None')
    # A biblioteca anexa a tag de autenticação (Auth Tag) ao final do ciphertext.
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    
    return ciphertext_with_tag, nonce

def decrypt_aes_gcm(ciphertext_with_tag: bytes, aes_key: bytes, nonce: bytes) -> bytes | None:
    """
    Decifra dados usando AES-GCM (AEAD).
    
    Verifica automaticamente a tag de autenticação. Se a tag for inválida
    (ou seja, o ciphertext ou o nonce foram adulterados), 
    levanta uma exceção 'InvalidTag'.

    Args:
        ciphertext_with_tag (bytes): Os dados cifrados com a tag.
        aes_key (bytes): A chave AES de 32 bytes.
        nonce (bytes): O nonce de 12 bytes usado na cifragem.

    Returns:
        bytes: O plaintext original, ou None se a decifragem falhar.
    """
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("Chave AES deve ter 32 bytes.")
        
    try:
        aesgcm = AESGCM(aes_key)
        
        # Tenta decifrar e verificar a tag ao mesmo tempo
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext
    except InvalidTag:
        # FALHA NA INTEGRIDADE! O ciphertext foi adulterado.
        print(" FALHA DE INTEGRIDADE (AEAD): Tag de autenticação inválida!")
        return None
    except Exception as e:
        print(f"Erro ao decifrar AES-GCM: {e}")
        return None

# --- Funções RSA (Criptografia Assimétrica para "embrulhar" chaves) ---

def wrap_aes_key(aes_key: bytes, recipient_public_key: rsa.RSAPublicKey) -> bytes:
    """Embrulha (cifra) uma chave AES usando a chave pública RSA do destinatário."""
    wrapped_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key

def unwrap_aes_key(wrapped_key: bytes, recipient_private_key: rsa.RSAPrivateKey) -> bytes | None:
    """
    "Desembrulha" (decifra) uma chave AES usando a chave privada RSA do destinatário.
    Usa o padding OAEP.

    Args:
        wrapped_key (bytes): A chave AES cifrada.
        recipient_private_key (RSAPrivateKey): A chave privada do destinatário.

    Returns:
        bytes: A chave AES original (32 bytes), ou None se falhar.
    """
    try:
        aes_key = recipient_private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key
    except Exception as e:
        # Falha aqui significa que a chave privada está errada ou os dados estão corrompidos
        print(f"Erro ao desembrulhar chave AES: {e}")
        return None