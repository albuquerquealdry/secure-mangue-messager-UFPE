# secure_messenger/app.py
import os
import sqlite3
from flask import (
    Flask, render_template, request, redirect, url_for, 
    g, flash, abort, session, jsonify
)
from markupsafe import escape
from collections import deque 

import core.messaging as messaging
import db.database as database
from logs.audit import LOG_FILE_PATH, SIG_FILE_PATH, log_event
from crypto.keys import CERTS_DIR, load_private_key 
from core.trust import get_trusted_public_key
app = Flask(__name__, template_folder="interface/templates")
app.config['SECRET_KEY'] = os.urandom(32) 
USERS = ["chico", "peixe", "maia", "audit"] 

def init_app():
    """Inicializa o banco e os logs se não existirem."""
    print("Inicializando aplicação...")
    database.init_db()
    
    from crypto.keys import get_audit_private_key
    if not get_audit_private_key():
        print("Encerrando app: Falha ao carregar chave de auditoria.")
        print("Verifique se a variável de ambiente 'AUDIT_KEY_PASSWORD' está correta.")
        exit(1)
    
    if not os.path.exists(os.path.join(CERTS_DIR, "trust_store.json")):
        print("Armazém de confiança não encontrado. Gerando...")
        print("!!! ATENCAO: Voce precisara digitar as senhas de todos os usuarios (chico, peixe, maia, audit) AGORA para inicializar o app.")
        
        from _generate_trust_store import generate_trust_store
        generate_trust_store()
        print("Armazém de confiança gerado.")

init_app()

@app.context_processor
def inject_global_vars():
    """Injeta variáveis globais em todos os templates."""
    return dict(users=USERS)


@app.before_request
def load_logged_in_user():
    username = session.get('username')
    
    if username is None:
        g.user = None
    else:
        g.user = username
        g.user_password = session.get('user_password')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Nome de usuário e senha da chave são obrigatórios.", "error")
        return redirect(url_for('index'))

    private_key = load_private_key(username, password)
    
    if private_key:
        session.clear()
        session['username'] = username
        session['user_password'] = password
        flash(f"Logado como '{username}'. Chave privada carregada.", "success")
        log_event("CORE", f"Login bem-sucedido para o usuario '{username}'.", "SUCCESS")
    else:
        flash("Senha da chave privada incorreta ou usuário inválido.", "error")
        log_event("SECURITY", f"Tentativa de login FALHOU para o usuario '{username}'.", "FAILURE")
        
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    log_event("CORE", f"Logout para o usuario '{session.get('username')}'.", "INFO")
    session.clear()
    flash("Você foi deslogado.", "success")
    return redirect(url_for('index'))


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if not g.user:
            flash("Você precisa estar logado para enviar mensagens.", "error")
            return redirect(url_for('index'))
        
        if g.user == 'audit':
            flash("O usuário 'audit' é apenas para visualização de logs e não pode enviar mensagens.", "error")
            return redirect(url_for('index'))

        sender = g.user
        recipient = request.form.get('recipient')
        message = request.form.get('message')
        if not recipient or not message:
            flash("Destinatário e mensagem são obrigatórios.", "error")
            return redirect(url_for('index'))
        if sender == recipient:
            flash("Você não pode enviar uma mensagem para si mesmo.", "error")
            return redirect(url_for('index'))
        sender_key = load_private_key(sender, g.user_password)
        if not sender_key:
            flash("Sessão expirou ou senha inválida. Faça login novamente.", "error")
            session.clear()
            return redirect(url_for('index'))
        try:
            success = messaging.send_secure_message(sender, recipient, message, sender_key)
            if success:
                flash(f"Mensagem enviada de {sender} para {recipient} com sucesso!", "success")
            else:
                flash("Falha ao enviar mensagem. Verifique o console.", "error")
        except Exception as e:
            flash(f"Erro ao enviar: {e}. Verifique o console.", "error")
        return redirect(url_for('index'))

    recipients = [u for u in USERS if u != g.user and u != 'audit']
    return render_template('index.html', recipients=recipients)


@app.route('/inbox')
def inbox():
    if not g.user:
        flash("Você precisa estar logado para ver sua caixa de entrada.", "error")
        return redirect(url_for('index'))
    
    if g.user == 'audit':
        flash("O usuário 'audit' não possui caixa de entrada.", "error")
        return redirect(url_for('index'))
        
    try:
        messages = database.get_messages_for_user(g.user)
        return render_template('inbox.html', messages=messages, username=g.user)
    except Exception as e:
        flash(f"Erro ao buscar caixa de entrada: {e}", "error")
        return redirect(url_for('index'))


@app.route('/read/<int:message_id>')
def read_message(message_id):
    if not g.user:
        flash("Você precisa estar logado para ler mensagens.", "error")
        return redirect(url_for('index'))

    if g.user == 'audit':
        abort(403) 

    print(f"\n--- [WEB] {g.user} tentando ler a mensagem ID: {message_id} ---")
    
    try:
        recipient_key = load_private_key(g.user, g.user_password)
        if not recipient_key:
            flash("Sessão expirou ou senha inválida. Faça login novamente.", "error")
            session.clear()
            return redirect(url_for('index'))
        plaintext = messaging.receive_secure_message(message_id, g.user, recipient_key)
        if plaintext is None:
            flash(f"FALHA DE SEGURANÇA! Não foi possível verificar ou decifrar a mensagem ID: {message_id}. Veja os logs.", "error")
            return redirect(url_for('inbox'))
        message_details = database.get_message_by_id(message_id, g.user)
        
        return render_template('read.html', 
                               message=plaintext, 
                               details=message_details, 
                               username=g.user)
                               
    except Exception as e:
        flash(f"Erro ao ler mensagem: {e}.", "error")
        return redirect(url_for('inbox'))


@app.route('/sobre')
def sobre():
    """Renderiza a nova página de explicações técnicas."""
    return render_template('sobre.html')


@app.route('/audit')
def audit_log():
    if not g.user or g.user != 'audit':
        log_event("SECURITY", f"Tentativa de acesso NAO AUTORIZADA a /audit pelo usuario '{g.user}'.", "FAILURE")
        flash("Acesso negado. Esta página é restrita.", "error")
        return redirect(url_for('index'))

    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
            log_content = "".join(reversed(f.readlines()))
    except FileNotFoundError:
        log_content = "Arquivo de log ainda não foi criado."
    except Exception as e:
        log_content = f"Erro ao ler log: {e}"

    try:
        from _verify_audit_log import verify_log_integrity
        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            is_valid = verify_log_integrity()
        verification_output = f.getvalue()

    except Exception as e:
        is_valid = False
        verification_output = f"Erro ao verificar assinatura do log: {e}"

    log_event("CORE", f"Usuario 'audit' acessou a pagina de logs.", "SUCCESS")
    return render_template('audit.html', 
                           log_content=log_content, 
                           is_valid=is_valid,
                           verification_output=verification_output)


def get_latest_log_entries(n=10):
    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
            last_n_lines = deque(f, n)
            return "".join(last_n_lines)
    except FileNotFoundError:
        return "Aguardando primeiro evento de log..."
    except Exception as e:
        return f"Erro ao ler log: {e}"

@app.route('/log/latest')
def get_latest_logs():
    if not g.user or g.user != 'audit':
        return "", 403 # Proibido
        
    log_data = get_latest_log_entries(n=15)
    return log_data, 200, {'Content-Type': 'text/plain; charset=utf-8'}


if __name__ == '__main__':
    print("--- Servidor Flask Secure Mangue Messenger ---")
    print("Acesse: http://127.0.0.1:5000")
    print("!!! Lembre-se de definir a variavel 'AUDIT_KEY_PASSWORD' !!!")
    print("---------------------------------------")
    app.run(debug=True, host='0.0.0.0', port=5000)