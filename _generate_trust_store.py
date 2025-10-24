# secure_messenger/_generate_trust_store.py
import os
import json
import hashlib
import sys

# Garante que a pasta 'crypto' seja encontrada
try:
    from crypto.keys import generate_rsa_keys, save_keys, CERTS_DIR
except ModuleNotFoundError:
    print("Erro: Não foi possível encontrar o módulo 'crypto.keys'.")
    print("Certifique-se de que está executando este script da pasta raiz do projeto.")
    sys.exit(1)

TRUST_STORE_FILE = os.path.join(CERTS_DIR, "trust_store.json")
# Usuários do sistema (3 usuários + 1 auditor)
USERS = ["chico", "peixe", "maia", "audit"] 

def calculate_file_hash(filepath: str) -> str | None:
    """Calcula o hash SHA-256 do CONTEÚDO de um arquivo."""
    try:
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
            h = hashlib.sha256()
            h.update(file_bytes)
            return h.hexdigest()
    except FileNotFoundError:
        print(f"AVISO: Arquivo de chave não encontrado: {filepath}")
        return None
    except Exception as e:
        print(f"Erro ao calcular hash de {filepath}: {e}")
        return None

def generate_trust_store():
    """
    SCRIPT DE SETUP COMPLETO:
    1. Verifica se as chaves dos usuários existem. Se não, as gera.
    2. Calcula os hashes das chaves públicas existentes.
    3. Salva os hashes no 'trust_store.json'.
    """
    print("--- INICIANDO SCRIPT DE SETUP DE CHAVES E TRUST STORE ---")
    
    # --- PARTE 1: GERAÇÃO DE CHAVES (Se necessário) ---
    print("\n[PASSO 1 de 2] Verificando e gerando chaves de usuário...")
    
    # Garante que o diretório 'certs' exista
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)
        print(f"Diretório '{CERTS_DIR}' criado.")

    for user in USERS:
        priv_path = os.path.join(CERTS_DIR, f"{user}_private.pem")
        
        if not os.path.exists(priv_path):
            print(f"\nChaves para '{user}' não encontradas.")
            print(f"--- Gerando novas chaves para '{user}' ---")
            try:
                priv, pub = generate_rsa_keys()
                # A função save_keys vai pedir a senha interativamente
                save_keys(user, priv, pub)
            except Exception as e:
                print(f"FALHA: Erro ao gerar chaves para {user}: {e}")
                return # Aborta o script se uma geração de chave falhar
        else:
            print(f"Chaves para '{user}' já existem. Pulando geração.")

    print("\n[PASSO 1 de 2] Geração de chaves concluída.")

    # --- PARTE 2: GERAÇÃO DO TRUST STORE ---
    print("\n[PASSO 2 de 2] Gerando Armazém de Confiança (Trust Store)...")
    trust_store = {}
            
    # Calcular os hashes das chaves públicas
    for user in USERS:
        public_key_file = f"{user}_public.pem"
        public_key_path = os.path.join(CERTS_DIR, public_key_file)
        
        file_hash = calculate_file_hash(public_key_path)
        
        if file_hash:
            trust_store[user] = {
                "public_key_path": public_key_file,
                "sha256_hash": file_hash
            }
            print(f"  -> Usuário '{user}' registrado no Trust Store.")
        else:
            print(f"FALHA: Não foi possível calcular o hash da chave pública de '{user}'.")
            return

    # Salva o dicionário como JSON
    try:
        with open(TRUST_STORE_FILE, 'w') as f:
            json.dump(trust_store, f, indent=4)
        print(f"\nSUCESSO: Armazém de confiança salvo em {TRUST_STORE_FILE}")
        print("--- SETUP CONCLUÍDO ---")
    except Exception as e:
        print(f"FALHA: Erro ao salvar {TRUST_STORE_FILE}: {e}")

if __name__ == "__main__":
    # Este script agora é o único ponto de entrada para o setup de criptografia.
    generate_trust_store()