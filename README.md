# 🦀 Secure Mangue Messenger


---

## 🎓 Contexto Acadêmico

Este projeto foi desenvolvido como trabalho prático para a disciplina de **Criptografia Aplicada**, como parte da **Pós-Graduação Lato Sensu em Segurança Ofensiva e Inteligência Cibernética (Hacker Ético)**.

---

## 📝 Descrição do Projeto

Este é um sistema de troca de mensagens seguras em Python, implementando criptografia de ponta a ponta (E2EE) com a temática visual do movimento Mangue Beat.

O objetivo é demonstrar a aplicação prática dos quatro pilares da segurança da informação em uma aplicação web moderna:

1.  **Confidencialidade:** As mensagens são ilegíveis para qualquer um, exceto o destinatário (nem o servidor pode ler).
2.  **Autenticidade:** O destinatário tem certeza de quem enviou a mensagem.
3.  **Integridade:** A mensagem não pode ser alterada no caminho sem ser detectada.
4.  **Não Repúdio:** O remetente não pode negar que enviou a mensagem.

---

## ⚙️ Tecnologias Utilizadas

* **Backend:** Python 3.10+, Flask
* **Criptografia:** Biblioteca `cryptography`
    * **Chaves Assimétricas:** RSA de 4096 bits (com padding OAEP para cifragem e PSS para assinatura)
    * **Chaves Simétricas:** AES de 256 bits (modo GCM - AEAD)
    * **Hashing:** BLAKE2b (para integridade do *plaintext*) e SHA-256 (para assinaturas)
* **Banco de Dados:** SQLite3

---

## 📂 Estrutura do Projeto



```bash
│
├── app.py                  \# Aplicação principal Flask
├── \_generate\_trust\_store.py \# [IMPORTANTE] Script de setup das chaves
├── \_verify\_audit\_log.py    \# Utilitário de verificação de logs
├── requirements.txt        \# Dependências do projeto
│
├── core/
│   ├── messaging.py        \# Orquestrador principal (enviar/receber)
│   └── trust.py            \# Módulo de Armazém de Confiança (CA)
│
├── crypto/
│   ├── encryption.py       \# Funções de Criptografia Híbrida (AES, RSA-OAEP)
│   ├── keys.py             \# Geração e carregamento de chaves
│   └── signature.py        \# Funções de Hashing (Blake2b) e Assinatura (RSA-PSS)
│
├── db/
│   ├── database.py         \# Gerenciamento do banco SQLite
│   └── messages.db         \# (Será criado aqui)
│
├── interface/
│   └── templates/
│       ├── base.html       \# Template mestre com o tema Mangue Beat
│       ├── index.html      \# Página de login/envio com terminal de log
│       ├── inbox.html      \# Caixa de entrada
│       ├── read.html       \# Leitura da mensagem decifrada
│       ├── sobre.html      \# Explicação técnica
│       └── audit.html      \# Página de visualização de logs
│
├── certs/
│   ├── trust\_store.json    \# (Será criado aqui) Armazém de Chaves Confiáveis
│   └── \*.pem               \# (Será criado aqui) Chaves dos usuários
│
└── logs/
├── audit.log           \# (Será criado aqui) Log de eventos
└── audit.log.sig       \# (Será criado aqui) Assinatura do log
└── logs/
├── * \# Arquivos de testes usados para validar o funcionamento de cada função durante o desenvolvimento
```



---

## 🚨 Instruções de Instalação e Execução

Para rodar este projeto, siga **exatamente** estes 6 passos. Os Passos 3 e 4 são **críticos** para a segurança e funcionalidade.

### Passo 1: Obter o Código

Clone ou baixe o repositório para sua máquina local.

```bash
git clone https://github.com/albuquerquealdry/secure-mangue-messager-UFPE.git
cd secure_mangue_messenger-UFPE
````

### Passo 2: Ambiente Virtual e Dependências

É altamente recomendado criar um ambiente virtual para isolar as dependências.

```bash
# 1. Crie o ambiente virtual
python -m venv venv

# 2. Ative o ambiente
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate
```

Crie um arquivo `requirements.txt` na raiz do projeto (veja o próximo bloco de código) e instale as dependências:

```bash
pip install -r requirements.txt
```

### Passo 3: 🔑 Gerar Chaves e Armazém de Confiança (Crítico)

Este é o passo mais importante. Vamos gerar as chaves RSA para todos os usuários (`chico`, `peixe`, `maia`) e para o sistema (`audit`).

Execute o script `_generate_trust_store.py`:

```bash
python _generate_trust_store.py
```

O script irá parar e **solicitar uma senha** para cada usuário.

**ATENÇÃO:** Você precisará criar e **memorizar (ou anotar) 4 senhas**:

1.  Senha para `chico` (ex: `123`)
2.  Senha para `peixe` (ex: `456`)
3.  Senha para `maia` (ex: `789`)
4.  Senha para `audit` (ex: `audit_secret_password`)

Ao final, ele criará a pasta `certs/` com todas as chaves `.pem` e o arquivo `trust_store.json`.

### Passo 4: 🔒 Definir Variável de Ambiente (Crítico)

A aplicação precisa da senha do `audit` para assinar os logs de forma segura, sem pedi-la a todo momento. Ela lê esta senha de uma variável de ambiente.

**Use a senha que você criou para o usuário `audit` no Passo 3.**

  * **No Windows (PowerShell):**
    ```powershell
    $env:AUDIT_KEY_PASSWORD="sua_senha_secreta_do_audit"
    ```
  * **No Windows (CMD):**
    ```cmd
    set AUDIT_KEY_PASSWORD="sua_senha_secreta_do_audit"
    ```
  * **No Linux / macOS:**
    ```bash
    export AUDIT_KEY_PASSWORD="sua_senha_secreta_do_audit"
    ```

### Passo 5: ▶️ Rodar a Aplicação

Com as chaves geradas e a variável de ambiente definida, rode o servidor Flask:

```bash
python app.py
```

O terminal deve exibir:

```
--- Servidor Flask Secure Mangue Messenger ---
Acesse: [http://127.0.0.1:5000](http://127.0.0.1:5000)
!!! Lembre-se de definir a variavel 'AUDIT_KEY_PASSWORD' !!!
---------------------------------------
🔑 Chave de Auditoria carregada com sucesso.
 * Running on [http://127.0.0.1:5000](http://127.0.0.1:5000)
```

### Passo 6: Usar a Aplicação (Fluxo de Teste)

Agora você pode testar o fluxo completo:

1.  **Acesse:** Abra `http://127.0.0.1:5000` no seu navegador.
2.  **Leia sobre:** Clique em **"Sobre"** para entender a criptografia.
3.  **Login (Chico):**
      * No formulário de login no topo, selecione `Chico`.
      * Digite a senha que você criou para `chico` (ex: `123`).
      * Clique em "Login".
4.  **Enviar (Chico -\> Peixe):**
      * Selecione `Peixe` como destinatário.
      * Escreva uma mensagem e clique em "Enviar".
      * Observe o terminal ao vivo na página: ele registrará o evento de envio.
5.  **Logout:** Clique em "(Logout)".
6.  **Login (Peixe):**
      * Faça login como `Peixe`, usando a senha dele (ex: `456`).
7.  **Ler (Peixe):**
      * Clique em **"Caixa (Peixe)"**.
      * Clique em "Ler Mensagem" ao lado da mensagem de "Chico".
      * A mensagem decifrada aparecerá.
8.  **Logout:** Clique em "(Logout)".
9.  **Verificar Auditoria (Audit):**
      * Faça login como `audit`, usando a senha dele (ex: `audit_secret_password`).
      * Clique no link **"Auditoria"**.

