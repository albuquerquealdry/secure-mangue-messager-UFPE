# secure_messenger/db/database.py
import sqlite3
import os

DB_NAME = "messages.db"
DB_PATH = os.path.join("db", DB_NAME)

def get_db_connection():
    """Cria e retorna uma conexão com o banco de dados SQLite."""
    conn = sqlite3.connect(DB_PATH)
    # Usar 'row_factory' nos permite acessar colunas pelo nome (como um dict)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Inicializa o banco de dados e cria a tabela 'messages' se ela não existir.
    """
    if os.path.exists(DB_PATH):
        print(f"Banco de dados '{DB_PATH}' já existe.")
    else:
        print(f"Criando novo banco de dados em '{DB_PATH}'...")
        
    # O 'schema' define a estrutura da nossa tabela
    # Armazenamos tudo como BLOB (Binary Large Object) para os dados cripto
    # e TEXT para os metadados.
    schema = """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        
        -- Pacote Criptográfico (Confidencialidade)
        encrypted_message BLOB NOT NULL, -- Ciphertext + Auth Tag
        nonce BLOB NOT NULL,
        wrapped_aes_key BLOB NOT NULL,
        
        -- Pacote de Verificação (Autenticidade/Integridade)
        signature BLOB NOT NULL,
        hash_blake2b BLOB NOT NULL,
        
        -- Status
        read_status INTEGER DEFAULT 0 -- 0 = Nao lida, 1 = Lida
    );
    """
    
    try:
        with get_db_connection() as conn:
            conn.execute(schema)
            conn.commit()
        print("Tabela 'messages' inicializada com sucesso.")
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados: {e}")

def save_message(
    timestamp: str,
    sender: str,
    recipient: str,
    encrypted_message: bytes,
    nonce: bytes,
    wrapped_aes_key: bytes,
    signature: bytes,
    hash_blake2b: bytes
) -> int | None:
    """
    Salva um pacote de mensagem segura completo no banco de dados.

    Args:
        Todos os campos do schema (exceto id e read_status).

    Returns:
        int: O ID da mensagem inserida, ou None em caso de falha.
    """
    sql = """
    INSERT INTO messages (
        timestamp, sender, recipient, encrypted_message, nonce, 
        wrapped_aes_key, signature, hash_blake2b
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        timestamp,
        sender,
        recipient,
        encrypted_message,
        nonce,
        wrapped_aes_key,
        signature,
        hash_blake2b
    )
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            print(f"Mensagem de '{sender}' para '{recipient}' salva no DB (ID: {cursor.lastrowid}).")
            return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Erro ao salvar mensagem: {e}")
        return None

def get_messages_for_user(recipient_name: str) -> list:
    """
    Busca no banco todas as mensagens (cabeçalhos) destinadas a um usuário.
    Não retorna o conteúdo, apenas os metadados para uma 'caixa de entrada'.

    Args:
        recipient_name (str): O nome do usuário (destinatário).

    Returns:
        list: Uma lista de dicts (sqlite3.Row) com as mensagens.
    """
    sql = "SELECT id, timestamp, sender, read_status FROM messages WHERE recipient = ? ORDER BY timestamp DESC"
    
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(sql, (recipient_name,))
            messages = cursor.fetchall()
            return messages
    except sqlite3.Error as e:
        print(f"Erro ao buscar mensagens para '{recipient_name}': {e}")
        return []

def get_message_by_id(message_id: int, recipient_name: str) -> sqlite3.Row | None:
    """
    Busca um pacote de mensagem completo pelo seu ID.
    Crucial: Também verifica se o 'recipient_name' é o dono da mensagem,
    para que um usuário não possa ler a mensagem de outro.

    Args:
        message_id (int): O ID da mensagem.
        recipient_name (str): O usuário que está tentando ler.

    Returns:
        sqlite3.Row: Um dict-like com todos os campos da mensagem, ou None.
    """
    sql = "SELECT * FROM messages WHERE id = ? AND recipient = ?"
    
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(sql, (message_id, recipient_name))
            message = cursor.fetchone()
            return message
    except sqlite3.Error as e:
        print(f"Erro ao buscar mensagem por ID '{message_id}': {e}")
        return None

def mark_message_as_read(message_id: int):
    """
    Atualiza o status da mensagem para 'lida' (read_status = 1).
    """
    sql = "UPDATE messages SET read_status = 1 WHERE id = ?"
    
    try:
        with get_db_connection() as conn:
            conn.execute(sql, (message_id,))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao marcar mensagem como lida: {e}")