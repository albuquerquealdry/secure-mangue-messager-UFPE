# secure_messenger/logs/audit.py
import os
from datetime import datetime, timezone

# Mudamos as importações!
from crypto.keys import get_audit_private_key
from crypto.signature import sign_message

LOGS_DIR = "logs"
LOG_FILE_PATH = os.path.join(LOGS_DIR, "audit.log")
SIG_FILE_PATH = os.path.join(LOGS_DIR, "audit.log.sig")

def log_event(level: str, message: str, status: str = "INFO"):
    """
    Registra um evento no arquivo de log (audit.log).
    """
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)

    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = f"[{timestamp}] [{level:<8}] [{status:<7}] {message}\n"
    
    try:
        with open(LOG_FILE_PATH, 'a', encoding='utf-8') as f:
            f.write(log_entry)
            
        # Agora tentamos assinar o log.
        # Esta função não pede mais input()
        sign_log()
        
    except Exception as e:
        print(f"ERRO CRÍTICO AO LOGAR: {e}")

def sign_log():
    """
    Assina o conteúdo completo do 'audit.log' e salva em 'audit.log.sig'.
    Usa a chave de auditoria carregada da variável de ambiente.
    """
    if not os.path.exists(LOG_FILE_PATH):
        return

    # 1. Carregar a chave privada de auditoria (via env var, cacheada)
    audit_private_key = get_audit_private_key()

    if not audit_private_key:
        print("ERRO DE LOG: Chave de auditoria não disponível. O log NÃO será assinado.")
        return

    # 2. Ler o conteúdo do log
    try:
        with open(LOG_FILE_PATH, 'rb') as f:
            log_data = f.read()
    except Exception as e:
        print(f"ERRO DE LOG: Não foi possível ler {LOG_FILE_PATH} para assinar: {e}")
        return

    # 3. Assinar os dados
    signature = sign_message(log_data, audit_private_key)
    
    if not signature:
        print("ERRO DE LOG: Falha ao gerar assinatura do log.")
        return

    # 4. Salvar a assinatura
    try:
        with open(SIG_FILE_PATH, 'wb') as f:
            f.write(signature)
    except Exception as e:
        print(f"ERRO DE LOG: Falha ao salvar assinatura {SIG_FILE_PATH}: {e}")