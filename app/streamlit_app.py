import streamlit as st
import requests
import json
import os
import pandas as pd
from datetime import datetime
import copy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import configparser
from dotenv import load_dotenv
import tldextract
import pathlib

# Carregar variáveis de ambiente
load_dotenv()

# Carregar configurações do arquivo config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Configurações
CADDY_ADMIN_API = config['default']['CADDY_ADMIN_API']
DB_URI = config['database']['SQLALCHEMY_DATABASE_URI']

# Garantir que o diretório do banco de dados exista
if DB_URI.startswith('sqlite:///'):
    db_path = DB_URI.replace('sqlite:///', '')
    db_dir = os.path.dirname(db_path)
    pathlib.Path(db_dir).mkdir(parents=True, exist_ok=True)
    st.write(f"Usando SQLite: {db_path}")

# Configuração do banco de dados
Base = declarative_base()
engine = create_engine(DB_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Definindo modelos
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_admin = Column(Boolean, default=False)
    email = Column(String(120), unique=True, nullable=True)

class ConfigVersion(Base):
    __tablename__ = 'config_version'
    id = Column(Integer, primary_key=True)
    version = Column(String(50), nullable=False)
    name = Column(String(128))
    config_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship('User', backref='config_versions')

    @classmethod
    def save_version(cls, config_json, user_id):
        version_name = f"config-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
        
        version = cls(
            version=version_name,
            config_path=config_json,
            user_id=user_id
        )
        session.add(version)
        session.commit()
        return version

# Criar as tabelas se não existirem
Base.metadata.create_all(engine)

# Funções para interação com API do Caddy
def get_config():
    try:
        response = requests.get(
            f"{CADDY_ADMIN_API}/config/",
            timeout=5
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Erro na API do Caddy: {str(e)}")
        return None

def update_config(config, user_id=None):
    config_to_send = dict(config)
    config_to_send.pop("_meta", None)

    try:
        config_json = json.dumps(config_to_send)
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(
            f"{CADDY_ADMIN_API}/load",
            headers=headers,
            data=config_json,
            timeout=5
        )
        response.raise_for_status()
        
        if user_id:
            ConfigVersion.save_version(config_json, user_id)
            
        return True
    except requests.exceptions.RequestException as e:
        st.error(f"Erro ao atualizar configuração: {str(e)}")
        return False

def extract_reverse_proxies(route, current_host=None, proxies=None):
    """
    Extrai todos os proxies reversos de uma rota Caddy
    e mapeia {host → [upstreams]}.
    """
    if proxies is None:
        proxies = {}

    # ── herdar ou atualizar host match ───────────────────
    if isinstance(route.get("match"), list) and route["match"]:
        host_list = route["match"][0].get("host")
        if host_list:
            current_host = host_list[0]          # manter apenas o primeiro host

    # ── iterar pela lista de handlers ────────────────────────
    for h in route.get("handle", []):
        htype = h.get("handler")

        # (a) reverse_proxy direto
        if htype == "reverse_proxy":
            host_key = current_host or "unknown.local"
            entry = proxies.setdefault(
                host_key,
                {"host": host_key, "upstreams": []}
            )
            entry["upstreams"].extend(h.get("upstreams", []))

        # (b) subroute – recursão para suas rotas
        elif htype == "subroute":
            for sub in h.get("routes", []):
                extract_reverse_proxies(sub, current_host, proxies)

    # ── recursão para rotas aninhadas no nível superior (raro) ────
    for sub in route.get("routes", []):
        extract_reverse_proxies(sub, current_host, proxies)

    return proxies

def get_hosts():
    config = get_config()
    if not config:
        st.warning("Falha ao obter configuração da API do Caddy")
        return []

    all_proxies = {}

    try:
        servers = config.get('apps', {}).get('http', {}).get('servers', {})
        if not servers:
            st.warning("Nenhum servidor encontrado na configuração HTTP")
            return []
        all_proxies: dict = {}
        
        for server_name, server in servers.items():
            for route in server.get('routes', []):
                proxies_found = extract_reverse_proxies(route, server_name)
                for host, data in proxies_found.items():
                    entry = all_proxies.setdefault(host, {"host": host, "upstreams": []})
                    entry["upstreams"].extend(data["upstreams"])

    except Exception as e:
        st.error(f"Erro ao analisar configuração: {str(e)}")

    return [all_proxies[k] for k in sorted(all_proxies)]

def registrable_domain(fqdn: str) -> str:
    """Get the registrable domain (abc.example.com -> example.com)"""
    if tldextract:
        # Using tldextract (better)
        ext = tldextract.extract(fqdn)
        return f"{ext.domain}.{ext.suffix}"
    else:
        # Fallback to split (naive)
        parts = fqdn.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return fqdn

def group_hosts_by_domain(hosts):
    """Group hosts by their domain for a more organized UI"""
    grouped = {}
    
    for host in hosts:
        domain = registrable_domain(host['host'])
        if domain not in grouped:
            grouped[domain] = []
        grouped[domain].append(host)
    
    return grouped

def pre_modification_snapshot(action, user_id):
    # Antes da modificação
    before = get_config()
    if not before:
        st.error("Não foi possível obter a configuração")
        return None

    ConfigVersion.save_version(json.dumps(before), user_id)
    return before

def inject_metadata(config, action="edit", username="streamlit"):
    if "apps" not in config or "http" not in config["apps"]:
        raise Exception("Configuração inválida, faltando 'apps.http'")
    if isinstance(config, dict):
        config["_meta"] = {
            "updated_by": username,
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "action": action
        }

def validate_caddy_config(config):
    if not isinstance(config, dict):
        return False
    if "apps" not in config:
        return False
    if "http" not in config["apps"]:
        return False
    if "servers" not in config["apps"]["http"]:
        return False
    return True

# Funções de autenticação simplificadas
def check_password(username, password):
    from werkzeug.security import check_password_hash
    user = session.query(User).filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return user
    return None

# Interface de login
def login_page():
    st.title("Login - CaddyUI")
    
    username = st.text_input("Usuário")
    password = st.text_input("Senha", type="password")
    
    if st.button("Entrar"):
        user = check_password(username, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.user_id = user.id
            st.session_state.username = user.username
            st.session_state.is_admin = user.is_admin
            st.success("Login bem sucedido!")
            st.rerun()
        else:
            st.error("Usuário ou senha inválidos")

# Página principal
def main_page():
    st.title("CaddyUI - Gerenciador de Proxy Reverso")
    
    # Sidebar com opções
    with st.sidebar:
        st.write(f"Bem-vindo, {st.session_state.username}")
        page = st.radio("Navegação", ["Dashboard", "Criar Host", "Versões"])
        if st.button("Sair"):
            st.session_state.logged_in = False
            st.rerun()
    
    # Conteúdo principal baseado na página selecionada
    if page == "Dashboard":
        dashboard_page()
    elif page == "Criar Host":
        create_host_page()
    elif page == "Versões":
        versions_page()

def dashboard_page():
    st.header("Dashboard")
    
    hosts = get_hosts()
    grouped = group_hosts_by_domain(hosts)
    
    # Exibir hosts agrupados por domínio
    for domain, domain_hosts in grouped.items():
        with st.expander(f"Domínio: {domain} ({len(domain_hosts)} hosts)"):
            for host in domain_hosts:
                col1, col2, col3 = st.columns([3, 6, 1])
                with col1:
                    st.write(f"**{host['host']}**")
                with col2:
                    upstreams = []
                    for upstream in host['upstreams']:
                        if 'dial' in upstream:
                            upstreams.append(upstream['dial'])
                    st.write(", ".join(upstreams))
                with col3:
                    if st.button("Editar", key=f"edit_{host['host']}"):
                        st.session_state.edit_host = host
                        st.session_state.page = "Editar Host"
                        st.rerun()
                    if st.button("Excluir", key=f"delete_{host['host']}"):
                        if delete_host(host['host']):
                            st.success(f"Host {host['host']} excluído com sucesso!")
                            st.rerun()

def create_host_page():
    st.header("Criar Novo Host")
    
    new_host = st.text_input("Nome do Host (ex: example.com)")
    upstreams = st.text_area("Upstreams (um por linha)", "localhost:8080")
    
    if st.button("Criar"):
        if new_host and upstreams:
            upstream_list = [u.strip() for u in upstreams.split('\n') if u.strip()]
            
            # Pegar configuração atual
            before = pre_modification_snapshot("created", st.session_state.user_id)
            if before:
                config = copy.deepcopy(before)
                
                # Criar nova rota
                new_route = {
                    "match": [
                        {
                            "host": [new_host]
                        }
                    ],
                    "handle": [
                        {
                            "handler": "reverse_proxy",
                            "upstreams": [{"dial": u} for u in upstream_list]
                        }
                    ],
                    "terminal": True
                }
                
                # Adicionar a nova rota ao primeiro servidor encontrado
                for app in config.get('apps', {}).get('http', {}).get('servers', {}).values():
                    app['routes'].append(new_route)
                    break
                
                if validate_caddy_config(config):
                    inject_metadata(config, "create", st.session_state.username)
                    if update_config(config, st.session_state.user_id):
                        st.success(f"Host {new_host} criado com sucesso!")
                        st.session_state.page = "Dashboard"
                        st.rerun()
                    else:
                        st.error("Erro ao atualizar configuração")
            else:
                st.error("Não foi possível obter a configuração atual")
        else:
            st.error("Preencha todos os campos")

def edit_host(host, new_host, upstreams):
    # Pegar configuração atual
    before = pre_modification_snapshot("edited", st.session_state.user_id)
    if not before:
        return False
    
    after = copy.deepcopy(before)
    # Encontrar e atualizar a rota
    updated = False
    
    for app in after.get('apps', {}).get('http', {}).get('servers', {}).values():
        for route in app.get('routes', []):
            match = route.get('match', [{}])
            if match and 'host' in match[0] and host in match[0]['host']:
                match[0]['host'] = [new_host]
                for handle in route.get('handle', []):
                    if handle.get('handler') == 'reverse_proxy':
                        handle['upstreams'] = [{'dial': u.strip()} for u in upstreams]
                        updated = True
    
    if updated:
        if validate_caddy_config(after):
            inject_metadata(after, "edit", st.session_state.username)
            return update_config(after, st.session_state.user_id)
    
    return False

def delete_host(host):
    # Pegar configuração atual
    before = pre_modification_snapshot("deleted", st.session_state.user_id)
    if not before:
        return False
    
    config = copy.deepcopy(before)
    deleted = False
    
    for app in config.get('apps', {}).get('http', {}).get('servers', {}).values():
        for route in app.get('routes', []):
            match = route.get('match', [{}])
            if match and 'host' in match[0] and host in match[0]['host']:
                # Soft-delete substituindo o handler
                route['handle'] = [
                    {
                        "handler": "static_response",
                        "body": "Deleted",
                        "status_code": 410
                    }
                ]
                deleted = True
    
    if deleted:
        if validate_caddy_config(config):
            inject_metadata(config, "delete", st.session_state.username)
            return update_config(config, st.session_state.user_id)
    
    return False

def versions_page():
    st.header("Histórico de Versões")
    
    versions = session.query(ConfigVersion).order_by(ConfigVersion.created_at.desc()).all()
    
    for version in versions:
        col1, col2, col3 = st.columns([2, 6, 2])
        with col1:
            st.write(version.created_at.strftime('%Y-%m-%d %H:%M:%S'))
        with col2:
            st.write(version.name or f"Versão {version.version}")
        with col3:
            if st.button("Restaurar", key=f"restore_{version.id}"):
                try:
                    config = json.loads(version.config_path)
                    if validate_caddy_config(config):
                        inject_metadata(config, "rollback", st.session_state.username)
                        if update_config(config, st.session_state.user_id):
                            st.success("Configuração restaurada com sucesso!")
                            st.rerun()
                except Exception as e:
                    st.error(f"Erro ao restaurar versão: {str(e)}")
            
            if st.button("Excluir", key=f"delete_version_{version.id}"):
                session.delete(version)
                session.commit()
                st.success("Versão excluída com sucesso!")
                st.rerun()

# Inicialização da aplicação
def init_admin_user():
    from werkzeug.security import generate_password_hash
    
    # Verificar se existe usuário admin
    admin = session.query(User).filter_by(username="diegofornalha").first()
    if not admin:
        # Ler senha do arquivo
        try:
            with open('secrets/admin_password.txt', 'r') as f:
                password = f.readline().strip()
                if not password:
                    password = "ChangeMe"  # Senha padrão
        except:
            password = "ChangeMe"  # Senha padrão
        
        # Criar usuário admin
        admin = User(
            username="diegofornalha",
            password_hash=generate_password_hash(password),
            email="admin@example.com",
            is_admin=True
        )
        session.add(admin)
        session.commit()
        st.info("Usuário diegofornalha criado com senha personalizada.")

# Interface principal
def main():
    # Inicialização
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    # Verificar se existe usuário admin
    init_admin_user()
    
    # Verificar login
    if not st.session_state.logged_in:
        login_page()
    else:
        main_page()

if __name__ == "__main__":
    main() 