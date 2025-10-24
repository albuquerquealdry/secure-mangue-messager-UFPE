# secure_messenger/crypto/keys.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Constantes
KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537
CERTS_DIR = "certs"

# Cache para chaves do sistema
_audit_key_cache = None

def generate_rsa_keys():
    """Gera um novo par de chaves RSA (pública e privada)."""
    print(f"Gerando novo par de chaves RSA ({KEY_SIZE} bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    public_key = private_key.public_key()
    print("Par de chaves gerado com sucesso.")
    return private_key, public_key

def save_keys(user_name: str, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
    """Salva o par de chaves (pública e privada) em arquivos .pem."""
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)

    private_key_path = os.path.join(CERTS_DIR, f"{user_name}_private.pem")
    public_key_path = os.path.join(CERTS_DIR, f"{user_name}_public.pem")

    # Esta função ainda usa input() pois só é chamada por scripts de setup
    print(f"\n--- Configurando chaves para '{user_name}' ---")
    password = input(f" Crie uma senha para proteger a chave privada de '{user_name}': ").strip()
    
    if not password:
        print("Senha não pode estar vazia. Abortando.")
        return

    try:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        print(f" Chave privada salva em: {private_key_path}")
    except Exception as e:
        print(f"Erro ao salvar chave privada: {e}")
        return

    try:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        print(f" Chave pública salva em: {public_key_path}")
    except Exception as e:
        print(f"Erro ao salvar chave pública: {e}")

def load_user_public_key(username):
    """Carrega a chave pública de um usuário do sistema."""
    public_key_path = os.path.join(CERTS_DIR, f"{username}_public.pem")
    
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        print(f"Erro ao carregar chave pública de {username}: {e}")
        return None

def load_private_key(user_name: str, password: str) -> rsa.RSAPrivateKey | None:
    """
    Carrega uma chave privada de um arquivo .pem USANDO UMA SENHA FORNECIDA.
    (Não usa mais input())
    """
    private_key_path = os.path.join(CERTS_DIR, f"{user_name}_private.pem")

    if not os.path.exists(private_key_path):
        print(f"Erro: Chave privada para '{user_name}' não encontrada.")
        return None

    if not password:
        print(f"Erro: Senha para '{user_name}' não fornecida.")
        return None

    try:
        with open(private_key_path, 'rb') as f:
            private_key_pem = f.read()
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode('utf-8')
            )
        return private_key
    except ValueError:
        print(f"Senha incorreta para o usuário '{user_name}'.")
        return None
    except Exception as e:
        print(f"Erro ao carregar chave privada de '{user_name}': {e}")
        return None

def get_audit_private_key() -> rsa.RSAPrivateKey | None:
    """
    Carrega a chave privada de auditoria (cacheada).
    Lê a senha da variável de ambiente 'AUDIT_KEY_PASSWORD'.
    """
    global _audit_key_cache
    if _audit_key_cache:
        return _audit_key_cache

    AUDIT_USER = "audit"
    password = os.environ.get("AUDIT_KEY_PASSWORD")
    
    if not password:
        print("="*50)
        print(" ERRO CRÍTICO DE SEGURANÇA ")
        print("A senha da chave de AUDITORIA não foi definida.")
        print("Defina a variável de ambiente 'AUDIT_KEY_PASSWORD'.")
        print("="*50)
        return None

    key = load_private_key(AUDIT_USER, password)
    if key:
        print("Chave de Auditoria carregada com sucesso.")
        _audit_key_cache = key # Salva no cache
        return key
    else:
        print("="*50)
        print(" ERRO CRÍTICO DE SEGURANÇA ")
        print("Falha ao carregar a chave de AUDITORIA. Senha errada?")
        print("="*50)
        return None

def load_private_key_interactive(user_name: str) -> rsa.RSAPrivateKey | None:
    """
    Função helper para nossos scripts de TESTE (ex: _teste_core_completo.py).
    Carrega a chave privada usando input() do console.
    NÃO DEVE SER USADA PELO FLASK.
    """
    password = input(f" [TESTE] Digite a senha da chave privada para '{user_name}': ").strip()
    return load_private_key(user_name, password)