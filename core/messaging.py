# secure_messenger/core/messaging.py
import os
from datetime import datetime, timezone, timedelta

# Importação de chaves modificada
from crypto.keys import load_private_key
from crypto.signature import hash_blake2b, sign_message, verify_signature
from crypto.encryption import (
    generate_aes_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    wrap_aes_key,
    unwrap_aes_key
)
from db.database import save_message, get_message_by_id, mark_message_as_read
from core.trust import get_trusted_public_key
from logs.audit import log_event
from cryptography.hazmat.primitives.asymmetric import rsa # Importar tipo

_PROCESSED_MESSAGES_CACHE = set()


def send_secure_message(
    sender_name: str, 
    recipient_name: str, 
    plaintext_message: str,
    sender_private_key: rsa.RSAPrivateKey
) -> bool:
    """
    Orquestra o envio.
    A chave privada do remetente é FORNECIDA (não carregada aqui).
    """
    print(f"\n--- Iniciando envio: {sender_name} -> {recipient_name} ---")

    if not sender_private_key:
        print("ERRO: Chave privada do remetente não fornecida.")
        log_event("CORE", f"Falha no envio: Chave privada de '{sender_name}' nao fornecida.", "FAILURE")
        return False

    print(f"Carregando chave pública CONFIÁVEL de '{recipient_name}' (para cifragem)...")
    recipient_public_key = get_trusted_public_key(recipient_name)
    
    if not recipient_public_key:
        print(f" ERRO: Falha ao carregar chave pública CONFIÁVEL de '{recipient_name}'.")
        log_event("SECURITY", f"Falha no envio: Chave publica confiavel de '{recipient_name}' nao encontrada.", "FAILURE")
        return False
        
    print("Chaves carregadas com sucesso.")

    try:
        message_bytes = plaintext_message.encode('utf-8')
    except Exception as e:
        print(f"Erro ao codificar mensagem: {e}")
        return False
        
    timestamp = datetime.now(timezone.utc).isoformat()

    hash_msg = hash_blake2b(message_bytes)
    aes_key = generate_aes_key()
    ciphertext_with_tag, aes_nonce = encrypt_aes_gcm(message_bytes, aes_key)
    wrapped_aes_key = wrap_aes_key(aes_key, recipient_public_key)
    print("Mensagem cifrada e chave AES embrulhada.")

    data_to_sign = f"{timestamp}:{sender_name}:{recipient_name}:".encode('utf-8') + hash_msg
    signature = sign_message(data_to_sign, sender_private_key)
    if not signature:
        print(" ERRO: Falha ao assinar a mensagem.")
        return False
    print("Manifesto da mensagem assinado digitalmente.")

    new_message_id = save_message(
        timestamp=timestamp, sender=sender_name, recipient=recipient_name,
        encrypted_message=ciphertext_with_tag, nonce=aes_nonce,
        wrapped_aes_key=wrapped_aes_key, signature=signature,
        hash_blake2b=hash_msg
    )

    if new_message_id:
        print(f" SUCESSO: Mensagem (ID: {new_message_id}) salva no banco...")
        log_event("CORE", f"Mensagem enviada de '{sender_name}' para '{recipient_name}'. ID={new_message_id}", "SUCCESS")
        return True
    else:
        print(" ERRO: Falha ao salvar a mensagem no banco de dados.")
        log_event("DB", f"Falha ao salvar msg de '{sender_name}' no DB.", "FAILURE")
        return False


def receive_secure_message(
    message_id: int, 
    recipient_name: str,
    recipient_private_key: rsa.RSAPrivateKey # <- CHAVE VEM COMO ARGUMENTO
) -> str | None:
    """
    Orquestra o recebimento.
    A chave privada do destinatário é FORNECIDA (não carregada aqui).
    """
    print(f"\n--- Iniciando recebimento: ID={message_id} para {recipient_name} ---")

    message_package = get_message_by_id(message_id, recipient_name)
    if not message_package:
        print(f" ERRO: Mensagem ID={message_id} não encontrada ou não pertence a '{recipient_name}'.")        
        log_event("DB", f"Tentativa de leitura da msg ID={message_id} por '{recipient_name}' falhou (nao encontrada).", "WARNING")
        return None

    sender_name = message_package['sender']
    print(f"Pacote encontrado. Remetente: '{sender_name}'.")

    cache_key = (recipient_name, message_id)
    if cache_key in _PROCESSED_MESSAGES_CACHE:
        print(" ALERTA DE SEGURANÇA: Tentativa de Replay! Esta mensagem já foi processada.")
        log_event("SECURITY", f"REPLAY ATTACK DETECTADO em msg ID={message_id} para '{recipient_name}'.", "FAILURE")
    
    try:
        msg_time = datetime.fromisoformat(message_package['timestamp'])
        time_diff = datetime.now(timezone.utc) - msg_time
        if time_diff > timedelta(days=1):
             print(" AVISO: Mensagem antiga (recebida há mais de 1 dia).")
    except ValueError:
        print(" ERRO: Timestamp da mensagem em formato inválido.")
        return None
    print("Verificação anti-replay/timestamp OK.")

    if not recipient_private_key:
        print(f" ERRO: Falha ao carregar chave privada de '{recipient_name}'.")
        log_event("CORE", f"Falha na leitura: Chave privada de '{recipient_name}' nao fornecida.", "FAILURE")
        return None

    print(f"Carregando chave pública CONFIÁVEL de '{sender_name}' (para verificação)...")
    sender_public_key = get_trusted_public_key(sender_name)
    
    if not sender_public_key:
        print(f" ERRO: Falha ao carregar chave pública CONFIÁVEL de '{sender_name}'.")
        log_event("SECURITY", f"Falha na leitura: Chave publica confiavel de '{sender_name}' nao encontrada.", "FAILURE")
        return None
        
    print("Chaves carregadas com sucesso.")

    data_to_verify = (
        f"{message_package['timestamp']}:"
        f"{message_package['sender']}:"
        f"{message_package['recipient']}:"
    ).encode('utf-8') + message_package['hash_blake2b']
    
    signature = message_package['signature']
    
    if not verify_signature(data_to_verify, signature, sender_public_key):
        print(" FALHA DE SEGURANÇA: Assinatura digital inválida!")
        log_event("SECURITY", f"VERIFICACAO DE ASSINATURA FALHOU. Msg ID={message_id} de '{sender_name}'.", "FAILURE")
        return None
    
    print(" Verificação de Assinatura OK (Autenticidade confirmada).")
    log_event("SECURITY", f"Verificacao de Assinatura OK. Msg ID={message_id}.", "INFO")

    wrapped_aes_key = message_package['wrapped_aes_key']
    aes_key = unwrap_aes_key(wrapped_aes_key, recipient_private_key)
    
    if not aes_key:
        print(f" FALHA DE SEGURANÇA: Não foi possível desembrulhar a chave AES.")
        log_event("SECURITY", f"FALHA AO DESEMBRULHAR CHAVE AES. Msg ID={message_id}.", "FAILURE")
        return None

    print(" Chave AES desembrulhada com sucesso.")

    ciphertext_with_tag = message_package['encrypted_message']
    nonce = message_package['nonce']
    plaintext_bytes = decrypt_aes_gcm(ciphertext_with_tag, aes_key, nonce)
    
    if not plaintext_bytes:
        print(" FALHA DE SEGURANÇA: Falha ao decifrar AES-GCM (InvalidTag).")
        log_event("SECURITY", f"FALHA AES-GCM (INVALID TAG). Msg ID={message_id}. (Ciphertext adulterado?)", "FAILURE")
        return None
    
    print(" Mensagem decifrada com AES-GCM (Tag de autenticação GCM válida).")

    local_hash = hash_blake2b(plaintext_bytes)
    received_hash = message_package['hash_blake2b']
    
    if local_hash != received_hash:
        print(" FALHA DE SEGURANÇA GRAVE: Hashes BLAKE2b não conferem!")
        log_event("SECURITY", f"FALHA GRAVE DE HASH. Msg ID={message_id}. (Inconsistencia de hash assinado!)", "FAILURE")
        return None

    print(" Verificação de Hash BLAKE2b OK (Integridade final confirmada).")

    mark_message_as_read(message_id)
    _PROCESSED_MESSAGES_CACHE.add(cache_key)
    
    print("\n--- MENSAGEM SEGURA RECEBIDA E VALIDADA ---")
    log_event("CORE", f"Mensagem ID={message_id} lida com sucesso por '{recipient_name}'.", "SUCCESS")
    
    try:
        return plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        print("Erro ao decodificar mensagem para UTF-8.")
        return None