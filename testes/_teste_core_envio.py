# secure_messenger/_teste_core_envio.py
import os
from db.database import init_db, get_db_connection, DB_PATH
from core.messaging import send_secure_message

SENDER = "chico"
RECIPIENT = "peixe"
MESSAGE = "Peixe, esta e a nossa primeira mensagem segura. O plano A esta em vigor."

def clear_db():
    """Limpa o banco de dados para um teste limpo."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("Banco de dados anterior removido.")

def check_db_entry():
    """Verifica manualmente no DB se a mensagem foi salva corretamente."""
    print("\nVerificando o banco de dados diretamente...")
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT * FROM messages WHERE sender = ? AND recipient = ?", (SENDER, RECIPIENT))
            msg = cursor.fetchone()
            
            if not msg:
                print(" FALHA: Nenhuma mensagem encontrada no banco de dados.")
                return False
            
            print(" SUCESSO: Mensagem encontrada no banco de dados.")
            print(f"  -> ID: {msg['id']}, De: {msg['sender']}, Para: {msg['recipient']}")
            
            # Verificar se os campos criptográficos (BLOBs) não estão vazios
            if (
                msg['encrypted_message'] and 
                msg['nonce'] and 
                msg['wrapped_aes_key'] and
                msg['signature'] and
                msg['hash_blake2b']
            ):
                print("  -> Todos os campos criptograficos estao preenchidos (BLOBs).")
                return True
            else:
                print(" FALHA: Um ou mais campos criptograficos estao vazios!")
                return False
                
    except Exception as e:
        print(f"Erro ao verificar o banco: {e}")
        return False


def run_send_test():
    print("--- INICIANDO TESTE DE ENVIO (CORE) ---")
    
    # 1. Preparar o DB
    clear_db()
    init_db()

    print("\n[Cenário 1] Tentando enviar mensagem...")
    print(f"Mensagem: '{MESSAGE}'")
    
    # 2. Chamar a função principal
    # Você precisará digitar as senhas de 'chico' e 'peixe' (Tópico 2)
    success = send_secure_message(SENDER, RECIPIENT, MESSAGE)

    if not success:
        print(" FALHA: A funcao send_secure_message() retornou False.")
        return
        
    # 3. Verificar o resultado no DB
    check_db_entry()

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear') 
    run_send_test()