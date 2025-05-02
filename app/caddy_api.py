import requests
from typing import Optional
import copy
from flask import current_app
import json
from datetime import datetime
from app.models import ConfigVersion

class CaddyAPI:

    def __init__(self):
        pass

    @staticmethod
    def get_config():
        try:
            response = requests.get(
                f"{current_app.config['CADDY_ADMIN_API']}/config/",
                timeout=5
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Caddy API Error: {str(e)}")
            return None

    @staticmethod
    def update_config(config, user_id=None):
        config_to_send = dict(config)
        config_to_send.pop("_meta", None)

        try:
            config_json = json.dumps(config_to_send)
            headers = {'Content-Type': 'application/json'}
            
            response = requests.post(
                f"{current_app.config['CADDY_ADMIN_API']}/load",
                headers=headers,
                data=config_json,
                timeout=5
            )
            response.raise_for_status()
            
            if user_id:
                ConfigVersion.save_version(config_json, user_id)
                
            return True
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Config Update Error: {str(e)}")
            return False
    
    def get_hosts(self):
        config = self.get_config()
        if not config:
            print("⚠️ Failed to get config from Caddy API")
            return []

        all_proxies = {}

        try:
            servers = config.get('apps', {}).get('http', {}).get('servers', {})
            if not servers:
                print("⚠️ No 'servers' key found in http config")
                return []
            all_proxies: dict = {}
            
            for server_name, server in servers.items():
                print(f"🔍 Scanning server: {server_name}")
                for route in server.get('routes', []):
                    proxies_found = extract_reverse_proxies(route, server_name)
                    for host, data in proxies_found.items():
                        entry = all_proxies.setdefault(host, {"host": host, "upstreams": []})
                        entry["upstreams"].extend(data["upstreams"])

        except Exception as e:
            print(f"❌ Error parsing config: {str(e)}")

        return [all_proxies[k] for k in sorted(all_proxies)]

def extract_reverse_proxies(route, current_host=None, proxies=None):
    """
    Walk an arbitrary Caddy route tree and collect every
    {host → [upstreams]}  mapping.
    """
    if proxies is None:
        proxies = {}

    # ── inherit or update host match ───────────────────
    if isinstance(route.get("match"), list) and route["match"]:
        host_list = route["match"][0].get("host")
        if host_list:
            current_host = host_list[0]          # keep first host only

    # ── iterate the handle list ────────────────────────
    for h in route.get("handle", []):
        htype = h.get("handler")

        # (a) direct reverse_proxy
        if htype == "reverse_proxy":
            host_key = current_host or "unknown.local"
            entry = proxies.setdefault(
                host_key,
                {"host": host_key, "upstreams": []}
            )
            entry["upstreams"].extend(h.get("upstreams", []))

        # (b) subroute – recurse into its routes
        elif htype == "subroute":
            for sub in h.get("routes", []):
                extract_reverse_proxies(sub, current_host, proxies)

        # (c) any other handler – ignore but continue loop

    # ── recurse into top-level nested routes (rare) ────
    for sub in route.get("routes", []):
        extract_reverse_proxies(sub, current_host, proxies)

    return proxies
