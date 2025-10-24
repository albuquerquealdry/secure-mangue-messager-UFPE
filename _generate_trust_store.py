# secure_messenger/_generate_trust_store.py
import os
import json
import hashlib

CERTS_DIR = "certs"
TRUST_STORE_FILE = os.path.join(CERTS_DIR, "trust_store.json")
USERS = ["chico", "peixe", "maia", "audit"] # 'audit' será para o Tópico 9

def calculate_file_hash(filepath: str) -> str | None:
    """Calcula o hash SHA-256 do CONTEÚDO de um arquivo."""
    try:
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
            # Usamos SHA-256 para o hash do arquivo (padrão para integridade de arquivos)
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
    Varre o diretório 'certs' em busca de chaves públicas
    e registra seus hashes no 'trust_store.json'.
    """
    print("--- Gerando Armazém de Confiança (Trust Store) ---")
    trust_store = {}
    
    for user in USERS:
        public_key_file = f"{user}_public.pem"
        public_key_path = os.path.join(CERTS_DIR, public_key_file)
        
        print(f"Processando: {public_key_path}")
        file_hash = calculate_file_hash(public_key_path)
        
        if file_hash:
            trust_store[user] = {
                "public_key_path": public_key_file,
                "sha256_hash": file_hash
            }
            print(f"  -> Hash: {file_hash[:10]}...")
            
    # Salva o dicionário como JSON
    try:
        with open(TRUST_STORE_FILE, 'w') as f:
            json.dump(trust_store, f, indent=4)
        print(f"\n SUCESSO: Armazém de confiança salvo em {TRUST_STORE_FILE}")
    except Exception as e:
        print(f" FALHA: Erro ao salvar {TRUST_STORE_FILE}: {e}")

if __name__ == "__main__":
    # IMPORTANTE: Antes de rodar este script,
    # certifique-se que você gerou as chaves de 'chico', 'peixe' e 'maia'
    # (rodando o _teste_chaves.py do Tópico 2)
    
    # (Vamos também gerar uma chave para o 'audit' que usaremos depois)
    from crypto.keys import generate_rsa_keys, save_keys
    
    audit_priv_path = os.path.join(CERTS_DIR, "audit_private.pem")
    if not os.path.exists(audit_priv_path):
        print("Gerando chaves para o usuário 'audit'...")
        # (Para o 'audit', podemos pular a senha no 'save_keys'
        # ou, para manter o padrão, apenas digite uma senha para ele)
        priv, pub = generate_rsa_keys()
        save_keys("audit", priv, pub) # Você precisará criar uma senha para 'audit'
    
    generate_trust_store()