#!/usr/bin/env python3
import os
import sys
import subprocess

# Adicionar o diretório atual ao PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

if __name__ == "__main__":
    # Configurar variáveis de ambiente
    os.environ["STREAMLIT_SERVER_PORT"] = "5000"
    os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"
    os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "true"
    os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    
    # Iniciar o Streamlit
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, "app", "streamlit_app.py")
    
    # Executar streamlit diretamente
    subprocess.run(["streamlit", "run", filename])