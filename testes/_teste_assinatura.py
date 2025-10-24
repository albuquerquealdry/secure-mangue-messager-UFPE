# secure_messenger/_teste_assinatura.py
from crypto.keys import load_keys
from crypto.signature import hash_blake2b, sign_message, verify_signature
import os

USER_A = "chico"
USER_B = "peixe"

minha_mensagem_secreta = b"Peixe, amanha o ataque sera as 03:00. Nao se atrase. - Chico"

def run_signature_test():
    print(f"--- INICIANDO TESTE DE ASSINATURA (Remetente: {USER_A}) ---")

    # 1. Carregar chaves do Remetente (Chico)
    # Você precisará digitar a senha de 'chico' que criou no Tópico 2
    chico_priv_key, chico_pub_key = load_keys(USER_A)
    if not chico_priv_key:
        print(f"Falha ao carregar chave privada de {USER_A}. Abortando.")
        return

    # 2. Carregar chave pública de outro usuário (Peixe)
    # (Não precisamos da senha dele, só da chave pública)
    _, peixe_pub_key = load_keys(USER_B)
    if not peixe_pub_key:
        print(f"Falha ao carregar chave pública de {USER_B}. Abortando.")
        return

    print(f"\nMensagem Original: {minha_mensagem_secreta.decode('utf-8')}")

    # 3. Gerar Hash de Integridade (BLAKE2b)
    meu_hash = hash_blake2b(minha_mensagem_secreta)
    print(f"Hash BLAKE2b (Integridade): {meu_hash.hex()}") # .hex() para visualização

    # 4. Assinar a mensagem
    print(f"\nAssinando mensagem com a chave privada de {USER_A}...")
    assinatura = sign_message(minha_mensagem_secreta, chico_priv_key)
    if not assinatura:
        print("Falha ao gerar assinatura.")
        return
    print(f"Assinatura gerada (primeiros 20 bytes): {assinatura[:20].hex()}...")

    # Cenário 1: Verificação Válida (Destinatário correto)
    print(f"\n[Cenário 1] Verificando com a chave pública correta ({USER_A})...")
    is_valid = verify_signature(minha_mensagem_secreta, assinatura, chico_pub_key)
    if is_valid:
        print(" SUCESSO: Assinatura válida!")
    else:
        print(" FALHA: A assinatura deveria ser válida.")

    # Cenário 2: Mensagem Adulterada (Falha de Integridade)
    print("\n[Cenário 2] Verificando com mensagem adulterada...")
    mensagem_adulterada = b"Peixe, amanha o ataque sera as 08:00. Nao se atrase. - Chico"
    is_valid_tampered = verify_signature(mensagem_adulterada, assinatura, chico_pub_key)
    if not is_valid_tampered:
        print(" SUCESSO: Assinatura REJEITADA como esperado (mensagem adulterada).")
    else:
        print(" FALHA: A assinatura deveria ser inválida.")

    # Cenário 3: Chave Pública Errada (Falha de Autenticidade)
    print(f"\n[Cenário 3] Verificando com a chave pública errada ({USER_B})...")
    is_valid_wrong_key = verify_signature(minha_mensagem_secreta, assinatura, peixe_pub_key)
    if not is_valid_wrong_key:
        print(" SUCESSO: Assinatura REJEITADA como esperado (chave pública errada).")
    else:
        print(" FALHA: A assinatura deveria ser inválida.")

if __name__ == "__main__":
    # Limpa o terminal (opcional, 'clear' no Linux/macOS, 'cls' no Windows)
    os.system('cls' if os.name == 'nt' else 'clear')  ## EI BOY, TAS USANDO WINDOWS.
    run_signature_test()