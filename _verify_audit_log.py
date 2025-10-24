# secure_messenger/_verify_audit_log.py
import os
import sys

# Garante que as pastas 'crypto', 'core', 'logs' sejam encontradas
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    from crypto.signature import verify_signature
    from core.trust import get_trusted_public_key # Usamos nosso "Porteiro"
    from logs.audit import LOG_FILE_PATH, SIG_FILE_PATH, LOGS_DIR
    from crypto.keys import CERTS_DIR
except ModuleNotFoundError:
    print("Erro: Não foi possível encontrar os módulos. Certifique-se que está na pasta raiz.")
    sys.exit(1)

AUDIT_USER = "audit"

def verify_log_integrity():
    """
    Verifica se a assinatura do log (audit.log.sig) corresponde
    ao conteúdo do log (audit.log), usando a chave pública
    confiável do usuário 'audit'.
    """
    print("--- INICIANDO VERIFICACAO DE INTEGRIDADE DO LOG DE AUDITORIA ---")

    if not os.path.exists(LOG_FILE_PATH) or not os.path.exists(SIG_FILE_PATH):
        print(" FALHA: Arquivo de log ou arquivo de assinatura não encontrado.")
        return False

    # 1. Carregar a chave pública CONFIÁVEL do 'audit'
    # (Não precisa de senha, usa o trust_store.json)
    print(f"Carregando chave pública confiável de '{AUDIT_USER}'...")
    audit_public_key = get_trusted_public_key(AUDIT_USER)
    
    if not audit_public_key:
        print(f" FALHA: Não foi possível carregar a chave de '{AUDIT_USER}'.")
        print("Verifique se o 'trust_store.json' está correto.")
        return False

    # 2. Ler o conteúdo do log
    try:
        with open(LOG_FILE_PATH, 'rb') as f:
            log_data = f.read()
    except Exception as e:
        print(f"Erro ao ler {LOG_FILE_PATH}: {e}")
        return False

    # 3. Ler a assinatura
    try:
        with open(SIG_FILE_PATH, 'rb') as f:
            signature = f.read()
    except Exception as e:
        print(f"Erro ao ler {SIG_FILE_PATH}: {e}")
        return False

    # 4. Verificar a assinatura
    print("Verificando assinatura do log...")
    is_valid = verify_signature(log_data, signature, audit_public_key)
    
    if is_valid:
        print("\n" + "="*60)
        print("   SUCESSO: Verificação de integridade do log APROVADA.")
        print("  O arquivo 'audit.log' é autêntico e não foi adulterado.")
        print("="*60)
        return True
    else:
        print("\n" + "!"*60)
        print("   ALERTA DE SEGURANÇA CRÍTICO!")
        print("  O arquivo 'audit.log' FALHOU na verificação de integridade!")
        print("  O LOG FOI ADULTERADO ou a assinatura está corrompida.")
        print("!"*60)
        return False

if __name__ == "__main__":
    # Permite que você rode este script manualmente também
    
    # Precisamos garantir que a chave de auditoria (via env var)
    # está configurada para que o 'get_trusted_public_key'
    # possa encontrar o 'trust_store' (que é gerado no init do app)
    # Em um cenário real, este script seria separado, mas aqui
    # ele depende da inicialização do app.
    
    verify_log_integrity()