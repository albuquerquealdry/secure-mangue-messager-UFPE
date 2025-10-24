# secure_messenger/crypto/signature.py
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def hash_blake2b(data: bytes) -> bytes:
    """
    Gera um hash BLAKE2b (64 bytes / 512 bits) para os dados fornecidos.
    Usado para verificação de integridade.

    Args:
        data (bytes): Os dados brutos (mensagem) para fazer o hash.

    Returns:
        bytes: O digest do hash.
    """
    # Usamos o 'blake2b' nativo do hashlib. 
    # O 'digest_size=64' é o padrão (512 bits), mas explicitamos para clareza.
    h = hashlib.blake2b(digest_size=64)
    h.update(data)
    return h.digest()

def sign_message(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Assina digitalmente os dados usando a chave privada RSA.

    O processo usa o padding PSS (o mais recomendado) e o hash SHA-256.
    A função de assinatura da biblioteca já calcula o hash internamente.

    Args:
        data (bytes): Os dados brutos (mensagem) a serem assinados.
        private_key (RSAPrivateKey): A chave privada do remetente.

    Returns:
        bytes: A assinatura digital.
    """
    if not isinstance(data, bytes):
        raise TypeError("Os dados para assinatura devem ser 'bytes'.")
        
    try:
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        print(f"Erro ao assinar mensagem: {e}")
        return None

def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verifica se a assinatura digital é válida para os dados,
    usando a chave pública do remetente.

    Args:
        data (bytes): Os dados brutos (mensagem) originais.
        signature (bytes): A assinatura recebida.
        public_key (RSAPublicKey): A chave pública do remetente.

    Returns:
        bool: True se a assinatura for válida, False caso contrário.
    """
    if not isinstance(data, bytes):
        raise TypeError("Os dados para verificação devem ser 'bytes'.")

    try:
        # A função 'verify' refaz o processo:
        # 1. Calcula o hash dos 'data' (com SHA256).
        # 2. Decifra a 'signature' com a 'public_key' (usando PSS).
        # 3. Compara os dois hashes.
        # Se forem idênticos, a assinatura é válida.
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Se a linha acima não levantar uma exceção, a assinatura é válida.
        return True
    except InvalidSignature:
        # Esta é a exceção esperada para uma assinatura inválida.
        print(" Verificação de assinatura falhou: Assinatura inválida!")
        return False
    except Exception as e:
        # Outros erros (ex: chave de tipo errado)
        print(f"Erro ao verificar assinatura: {e}")
        return False