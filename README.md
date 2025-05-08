# OpenCaddyUI

Uma interface web simples para gerenciar configurações do servidor Caddy, agora com Streamlit!

## Sobre

OpenCaddyUI permite gerenciar facilmente configurações de proxy reverso do [Caddy Server](https://caddyserver.com/), mostrando todos os hosts de proxy configurados, permitindo adicionar novos, editar ou remover existentes, além de controle de versão das configurações.

## Características

- Interface moderna com Streamlit
- Visualização de todos os hosts de proxy configurados
- Adição, edição e remoção de hosts
- Controle de versão das configurações
- Autenticação de usuários
- Integração direta com a API do Caddy

## Requisitos

- Python 3.8+
- Caddy Server 2.x com API Admin ativada
- PostgreSQL 

## 

1. Crie um ambiente virtual e instale as dependências:
```bash
python -m venv .venv
source .venv/bin/activate 
pip install -r requirements.txt
```

2. Configure o banco de dados no arquivo `config.ini`:
```ini
[database]
SQLALCHEMY_DATABASE_URI = postgresql://usuario:senha@localhost:5432/caddyui
```

4. Execute o aplicativo:
```bash
python run.py
```

5. Acesse a interface web em `http://localhost:5000`

## Configuração

As principais configurações estão no arquivo `config.ini`, onde você pode definir:

- URL da API Admin do Caddy (CADDY_ADMIN_API)
- String de conexão do banco de dados (SQLALCHEMY_DATABASE_URI)
- Chave secreta para segurança (SECRET_KEY)

## Uso

1. Faça login com o usuário admin (senha padrão no arquivo secrets/admin_password.txt)
2. No dashboard, visualize todos os hosts configurados
3. Adicione novos hosts ou edite/remova existentes
4. Acesse o histórico de versões para reverter configurações anteriores
