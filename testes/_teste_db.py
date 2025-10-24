# secure_messenger/_teste_db.py
import os
import time
from db.database import (
    init_db,
    save_message,
    get_messages_for_user,
    get_message_by_id,
    mark_message_as_read,
    DB_PATH
)

def clear_db():
    """Limpa o banco de dados para um teste limpo."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("Banco de dados anterior removido.")

def run_db_test():
    print("--- INICIANDO TESTE DE BANCO DE DADOS ---")
    
    # 1. Limpar e Inicializar o DB
    clear_db()
    init_db()

    # 2. Simular o envio de 3 mensagens
    print("\n[Cenário 1] Salvando mensagens...")
    
    # Mensagem 1: Chico -> Peixe
    save_message(
        timestamp=str(time.time()),
        sender="chico",
        recipient="peixe",
        encrypted_message=b"ciphertext1_fake_data",
        nonce=b"nonce1",
        wrapped_aes_key=b"wrapped_key1",
        signature=b"sig1",
        hash_blake2b=b"hash1"
    )
    
    time.sleep(0.1) # Garante timestamps diferentes

    # Mensagem 2: Maia -> Peixe
    save_message(
        timestamp=str(time.time()),
        sender="maia",
        recipient="peixe",
        encrypted_message=b"ciphertext2_fake_data",
        nonce=b"nonce2",
        wrapped_aes_key=b"wrapped_key2",
        signature=b"sig2",
        hash_blake2b=b"hash2"
    )

    time.sleep(0.1)

    # Mensagem 3: Peixe -> Chico
    save_message(
        timestamp=str(time.time()),
        sender="peixe",
        recipient="chico",
        encrypted_message=b"ciphertext3_fake_data",
        nonce=b"nonce3",
        wrapped_aes_key=b"wrapped_key3",
        signature=b"sig3",
        hash_blake2b=b"hash3"
    )

    # 3. Testar a "Caixa de Entrada" do Peixe
    print("\n[Cenário 2] Verificando caixa de entrada de 'peixe'...")
    inbox_peixe = get_messages_for_user("peixe")
    
    if len(inbox_peixe) == 2:
        print(f" SUCESSO: 'peixe' tem 2 mensagens, como esperado.")
        print(f"  -> Msg 1: De {inbox_peixe[0]['sender']}, Status: {'Nao Lida' if inbox_peixe[0]['read_status'] == 0 else 'Lida'}")
        print(f"  -> Msg 2: De {inbox_peixe[1]['sender']}, Status: {'Nao Lida' if inbox_peixe[1]['read_status'] == 0 else 'Lida'}")
    else:
        print(f" FALHA: 'peixe' deveria ter 2 mensagens, mas tem {len(inbox_peixe)}.")

    # 4. Testar a leitura da mensagem 1 (Chico -> Peixe)
    print("\n[Cenário 3] 'peixe' tenta ler a mensagem de ID=1...")
    msg_id_1 = inbox_peixe[1]['id'] # Pegando o ID da primeira msg (ordem DESC)
    msg_completa = get_message_by_id(msg_id_1, "peixe")
    
    if msg_completa and msg_completa['sender'] == "chico":
        print(" SUCESSO: Mensagem ID=1 recuperada por 'peixe'.")
        print(f"   -> Conteúdo (fake): {msg_completa['encrypted_message']}")
        # Marcar como lida
        mark_message_as_read(msg_id_1)
        print("   -> Mensagem marcada como lida.")
    else:
        print(" FALHA: Nao foi possivel recuperar a mensagem ID=1.")

    # 5. Testar falha de segurança (Chico tenta ler msg do Peixe)
    print("\n[Cenário 4] 'chico' tenta ler a mensagem de ID=1 (destinada ao 'peixe')...")
    msg_fail = get_message_by_id(msg_id_1, "chico")
    
    if msg_fail is None:
        print(" SUCESSO: 'chico' foi impedido de ler a mensagem (retornou None).")
    else:
        print(" FALHA: 'chico' conseguiu ler uma mensagem que não era para ele.")

    # 6. Verificar status de leitura
    print("\n[Cenário 5] Verificando caixa de entrada de 'peixe' novamente...")
    inbox_peixe_final = get_messages_for_user("peixe")
    
    # Verificando a mensagem de ID=1
    msg_lida = next(m for m in inbox_peixe_final if m['id'] == msg_id_1)
    if msg_lida['read_status'] == 1:
        print(" SUCESSO: Mensagem ID=1 agora consta como 'Lida'.")
    else:
        print(" FALHA: Mensagem ID=1 nao foi marcada como lida.")

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear') 
    run_db_test()