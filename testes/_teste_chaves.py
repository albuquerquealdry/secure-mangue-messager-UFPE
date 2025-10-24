# secure_messenger/_teste_chaves.py
from crypto.keys import generate_rsa_keys, save_keys, load_keys
import os

usuarios = ["chico", "peixe", "maia", "audit"]

def generate_all_keys():
    """Gera e salva chaves para todos os usuários."""
    print("--- INICIANDO GERAÇÃO DE CHAVES ---")
    for user in USERS:
        # Verifica se as chaves já existem para não sobrescrever
        priv_path = os.path.join("certs", f"{user}_private.pem")
        if os.path.exists(priv_path):
            print(f"\nChaves para '{user}' já existem. Pulando geração.")
            continue
            
        private_key, public_key = generate_rsa_keys()
        save_keys(user, private_key, public_key)
    print("\n--- GERAÇÃO DE CHAVES CONCLUÍDA ---")

def test_load_all_keys():
    """Tenta carregar todas as chaves geradas."""
    print("\n--- INICIANDO TESTE DE CARREGAMENTO ---")
    for user in USERS:
        print(f"\nTentando carregar chaves para '{user}'...")
        private_key, public_key = load_keys(user)
        
        if private_key and public_key:
            print(f" Sucesso ao carregar chaves de '{user}'.")
        elif public_key:
            print(f"  Chave pública de '{user}' carregada, mas a privada falhou (provavelmente senha errada).")
        else:
            print(f" Falha ao carregar chaves de '{user}'.")

if __name__ == "__main__":
    # 1. Gerar as chaves
    generate_all_keys()
    
    # 2. Tentar carregar as chaves (exigirá as senhas que você acabou de criar)
    test_load_all_keys()