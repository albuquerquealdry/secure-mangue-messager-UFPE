# secure_messenger/core/trust.py
import os
import json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERTS_DIR = "certs"
TRUST_STORE_FILE = os.path.join(CERTS_DIR, "trust_store.json")

# Cache para evitar I/O de disco repetitivo
_trust_store_cache = None
_loaded_public_keys = {}

def _load_trust_store():
    """Carrega o armazém de confiança (cacheado)."""
    global _trust_store_cache
    if _trust_store_cache:
        return _trust_store_cache
    
    try:
        with open(TRUST_STORE_FILE, 'r') as f:
            _trust_store_cache = json.load(f)
            return _trust_store_cache
    except FileNotFoundError:
        print(f" ERRO CRÍTICO: Armazém de Confiança '{TRUST_STORE_FILE}' não encontrado!")
        print("Execute o script '_generate_trust_store.py' primeiro.")
        return None
    except Exception as e:
        print(f"Erro ao carregar Armazém de Confiança: {e}")
        return None

def _calculate_file_hash(filepath: str) -> str | None:
    """Calcula o hash SHA-256 do conteúdo de um arquivo."""
    try:
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
            h = hashlib.sha256()
            h.update(file_bytes)
            return h.hexdigest()
    except Exception:
        return None

def get_trusted_public_key(user_name: str) -> rsa.RSAPublicKey | None:
    """
    Carrega uma chave pública SOMENTE se ela for confiável.
    
    1. Carrega o armazém de confiança.
    2. Pega o hash esperado para 'user_name'.
    3. Calcula o hash atual do arquivo .pem.
    4. Compara os hashes.
    5. Se bater, carrega e retorna a chave.
    
    Args:
        user_name (str): O usuário (ex: 'chico')
        
    Returns:
        RSAPublicKey: O objeto de chave pública, ou None se a verificação falhar.
    """
    # Usar cache de chaves para performance
    if user_name in _loaded_public_keys:
        return _loaded_public_keys[user_name]

    trust_store = _load_trust_store()
    if not trust_store or user_name not in trust_store:
        print(f" FALHA DE CONFIANÇA: Usuário '{user_name}' não está no Armazém de Confiança.")
        return None

    # 1. Obter dados do armazém
    key_info = trust_store[user_name]
    expected_hash = key_info['sha256_hash']
    key_file_path = os.path.join(CERTS_DIR, key_info['public_key_path'])

    # 2. Calcular hash atual do arquivo
    current_hash = _calculate_file_hash(key_file_path)

    # 3. Comparar
    if current_hash != expected_hash:
        print(f" ALERTA DE SEGURANÇA CRÍTICO! ")
        print(f"O arquivo de chave pública para '{user_name}' ({key_file_path}) FOI ADULTERADO!")
        print(f"Hash esperado: {expected_hash}")
        print(f"Hash   atual: {current_hash}")
        print("Operação abortada.")
        return None
        
    # 4. Se os hashes baterem, carregar a chave
    try:
        with open(key_file_path, 'rb') as f:
            public_key_pem = f.read()
            public_key = serialization.load_pem_public_key(public_key_pem)
            
        _loaded_public_keys[user_name] = public_key # Salvar no cache
        return public_key
    except Exception as e:
        print(f"Erro ao carregar chave pública confiável de '{user_name}': {e}")
        return None