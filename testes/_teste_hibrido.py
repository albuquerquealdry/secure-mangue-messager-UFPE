# secure_messenger/_teste_hibrido.py
from crypto.keys import load_keys
from crypto.encryption import (
    generate_aes_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    wrap_aes_key,
    unwrap_aes_key
)
import os

print("Configurando teste de criptografia híbrida...")

# Usuários do teste
SENDER = "chico"     # Remetente
RECIPIENT = "peixe"  # Destinatário
WRONG_USER = "maia"  # Usuário incorreto (para teste de falha)

# Mensagem de teste
message = b"Esta e uma mensagem de teste ultra-secreta."

def run_hybrid_test():
    print("--- INICIANDO TESTE DE CRIPTOGRAFIA HIBRIDA ---")
    print(f"Remetente: {SENDER}, Destinatario: {RECIPIENT}")
    print(f"Mensagem original: {message.decode('utf-8')}\n")

    # 1. Carregar chaves
    # Precisamos da chave pública do Peixe (para cifrar)
    # e da chave privada do Peixe (para decifrar)
    print("Carregando chaves (digite as senhas quando solicitado)...")
    peixe_priv_key, peixe_pub_key = load_keys(RECIPIENT)
    
    # Também carregamos a de Chico, para o cenário de falha
    chico_priv_key, _ = load_keys(SENDER)

    if not peixe_priv_key or not peixe_pub_key or not chico_priv_key:
        print("Falha ao carregar chaves. Abortando.")
        return

    # --- LADO DO REMETENTE (Chico) ---
    print("\n--- LADO DO REMETENTE (Chico) ---")
    
    # Gerar chave AES de uso único
    aes_key = generate_aes_key()
    print(f"1. Chave AES gerada: {aes_key[:4].hex()}... (32 bytes)")

    # Cifrar a mensagem com AES-GCM
    ciphertext, nonce = encrypt_aes_gcm(message, aes_key)
    print(f"2. Mensagem cifrada com AES: {ciphertext[:10].hex()}...")
    print(f"3. Nonce gerado: {nonce.hex()}")

    # "Embrulhar" (cifrar) a chave AES com a chave pública do Peixe
    wrapped_aes_key = wrap_aes_key(aes_key, peixe_pub_key)
    print(f"4. Chave AES embrulhada com RSA: {wrapped_aes_key[:10].hex()}...")
    
    print("\n--- (Dados sendo enviados pela rede...) ---")
    # Pacote enviado: (ciphertext, nonce, wrapped_aes_key)
    
    print("\n--- LADO DO DESTINATÁRIO (Peixe) ---")

    # 5. "Desembrulhar" (decifrar) a chave AES com a chave privada do Peixe
    unwrapped_aes_key = unwrap_aes_key(wrapped_aes_key, peixe_priv_key)
    if not unwrapped_aes_key:
        print(" FALHA: Nao foi possivel desembrulhar a chave AES.")
        return
        
    print(f"1. Chave AES desembrulhada: {unwrapped_aes_key[:4].hex()}... (32 bytes)")

    # 6. Verificar se a chave recuperada é a mesma (teste de sanidade)
    if unwrapped_aes_key == aes_key:
        print("   -> Chave AES recuperada com sucesso!")
    else:
        print("   ->  FALHA: Chave AES recuperada nao confere!")
        return

    # 7. Decifrar a mensagem com a chave AES recuperada
    plaintext = decrypt_aes_gcm(ciphertext, unwrapped_aes_key, nonce)
    if not plaintext:
        print(" FALHA: Nao foi possivel decifrar a mensagem (falha de tag?).")
        return
        
    print(f"2. Mensagem decifrada: {plaintext.decode('utf-8')}")

    # 8. Verificação final
    if plaintext == message:
        print("\n SUCESSO: A mensagem original foi recuperada intacta!")
    else:
        print("\n FALHA: A mensagem decifrada e diferente da original.")

    print("\n--- CENARIO DE FALHA (Chico tenta ler a msg destinada ao Peixe) ---")
    
    try:
        # Chico tenta usar sua própria chave privada
        unwrapped_key_fail = unwrap_aes_key(wrapped_aes_key, chico_priv_key)
        if unwrapped_key_fail is None:
             # A biblioteca pode retornar None ou levantar exceção
             raise ValueError("Falha na decifragem")
        print(" FALHA: Chico conseguiu desembrulhar a chave (NAO DEVERIA!)")
    except Exception as e:
        print(f"   -> Erro ao desembrulhar: {e}")
        print(" SUCESSO: Falha ao desembrulhar a chave AES com a chave errada, como esperado.")


if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear') 
    run_hybrid_test()