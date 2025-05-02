import requests
import copy
import collections
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_required, current_user
from app.models import ConfigVersion, db
from app.caddy_api import CaddyAPI
import json
from datetime import datetime

try:
    import tldextract          # best way (handles abc.xyz, etc.)
except ImportError:
    tldextract = None          # fall back to simple split


main_bp = Blueprint('main', __name__)
caddy_api = CaddyAPI()

@main_bp.route('/')
@login_required
def dashboard():
    hosts = caddy_api.get_hosts()
    grouped = group_hosts_by_domain(hosts)
    return render_template('dashboard.html', grouped_hosts=grouped)

def pre_modification_snapshot(action):
    # Before modification
    before = caddy_api.get_config()
    if not before:
        flash("couldn't fetch config", "danger")
        return redirect(url_for('main.dashboard'))

    db.session.add(ConfigVersion(
        version=datetime.utcnow().isoformat(),
        name=f"Before {action} by {current_user.username}",
        config_path=json.dumps(before),
        user_id=current_user.id
    ))
    db.session.commit()

    return before


@main_bp.route('/edit/<path:host>', methods=['GET', 'POST'])
@login_required
def edit_host(host):
    action = "edited"
    if request.method == 'POST':
        # Process form data and update config
        new_host = request.form.get('host')
        upstreams = request.form.get('upstreams').split(',')
        before = pre_modification_snapshot(action) 
        after = copy.deepcopy(before)
        # Find and update the route
        updated = False
        for app in after.get('apps', {}).get('http', {}).get('servers', {}).values():
            for route in app.get('routes', []):
                match = route.get('match', [{}])
                if match and 'host' in match[0] and host in match[0]['host']:
                    match[0]['host'] = [new_host]
                    for handle in route.get('handle', []):
                        if 'reverse_proxy' in handle:
                            handle['reverse_proxy']['upstreams'] = [{'dial': u.strip()} for u in upstreams]
                            updated = True
        
        if updated:
            with open('/app/debug/debug_caddy.json', 'w') as f:
                json.dump(config, f, indent=2)
            if validate_caddy_config(after):
               check_then_post(after, "edit")
        else:
            flash('Route not found', 'danger')
        
        return redirect(url_for('main.dashboard'))
    
    # GET request - find the host to edit
    hosts = caddy_api.get_hosts()
    host_to_edit = next((h for h in hosts if h['host'] == host), None)
    
    if not host_to_edit:
        flash('Host not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    return render_template('edit_host.html', host=host_to_edit)

@main_bp.route('/versions')
@login_required
def versions():
    versions = ConfigVersion.query.order_by(ConfigVersion.created_at.desc()).all()
    return render_template('versions.html', versions=versions)

@main_bp.route('/rollback/<int:version_id>', methods=['POST'])
@login_required
def rollback(version_id):
    action = 'rollback'
    version = ConfigVersion.query.get_or_404(version_id)

    if not version:
        flash('Version not found.', 'danger')
        return redirect(url_for('main.versions'))
    before = pre_modification_snapshot(action) 
    full_config = json.loads(version.config_path)
    full_config.pop("_meta", None)

    try:
        if validate_caddy_config(full_config):
            check_then_post(full_config, "rollback")
            updated_config = caddy_api.get_config()
            with open("/app/debug/config_after_rollback.json", "w") as f:
                json.dump(updated_config, f, indent=2)

    except Exception as e:
        print(f"Rollback error: {e}")

    return redirect(url_for('main.dashboard'))


@main_bp.route('/versions/delete/<int:vid>', methods=["POST"])
@login_required
def delete_version(vid):
    v = ConfigVersion.query.get_or_404(vid)
    db.session.delete(v)
    db.session.commit()
    flash('Version deleted', 'Success')
    return redirect(url_for('main.versions'))


@main_bp.route('/delete/<path:host>', methods=['POST'])
@login_required
def delete_host(host):
    action = "deleted"
    before = pre_modification_snapshot(action)
    config = copy.deepcopy(before)

    deleted = False

    for app in config.get('apps', {}).get('http', {}).get('servers', {}).values():
        for route in app.get('routes', []):
            match = route.get('match', [{}])
            if match and 'host' in match[0] and host in match[0]['host']:
                # Soft-delete by clearing the handle
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
            check_then_post(config, "delete")
    else:
        flash('Host not found', 'danger')

    return redirect(url_for('main.dashboard'))


@main_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_host():
    action = "created"
    if request.method == 'POST':
        new_host = request.form.get('host')
        upstreams = request.form.get('upstreams').split(',')

        before = pre_modification_snapshot(action)
        config = copy.deepcopy(before)

        # Create a new route
        new_route = {
            "match": [
                {
                    "host": [new_host]
                }
            ],
            "handle": [
                {
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": u.strip()} for u in upstreams]
                }
            ],
            "terminal": True
        }

        for app in config.get('apps', {}).get('http', {}).get('servers', {}).values():
            app['routes'].append(new_route)

        if validate_caddy_config(config):

            check_then_post(config, "create")

        return redirect(url_for('main.dashboard'))

    return render_template('create_host.html')

def inject_metadata(config, action="edit"):
    if "apps" not in config or "http" not in config["apps"]:
        raise Exception("Invalid config, missing 'apps.http'")
    if isinstance(config, dict):
        config["_meta"] = {
            "updated_by": current_user.username,
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

def check_then_post(config, action):
    inject_metadata(config, action=action)

    payload_config = dict(config)
    
    payload_config.pop("_meta", None)
    
    with open('/app/debug/debug_caddy_config.json', 'w') as f:
        json.dump(config, f, indent=2)

    payload = json.dumps(payload_config, separators=(',', ':'))
    headers = {'Content-Type': 'application/json'}
    try:
        #Post minimized
        response = requests.post(
            f"{current_app.config['CADDY_ADMIN_API']}/load",
            headers=headers,
            data=payload,
            timeout=5
        )
        if response.status_code >= 400:
            print(f"Response body: {response.text}")
            print(f"Server returned {response.status_code}")
            response.raise_for_status()
        else:
            flash('Config rolled back: ', 'success')
    except requests.exceptions.RequestException as e:
        print(f"Request exception: {e}")
        if response is not None:
            print(f"Response after rais {response.text}")
        raise


def registrable_domain(fqdn: str) -> str:
    """
    Return the base/registrable domain of a host:
      ▸ xyz.abc.com   →  abc.com
      ▸ abc.com       →  abc.com
    Uses tldextract if available, otherwise last two labels.
    """
    if tldextract:
        ext = tldextract.extract(fqdn)
        return f"{ext.domain}.{ext.suffix}"
    parts = fqdn.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


def group_hosts_by_domain(hosts):
    """
    hosts: list of {'host': 'xyz.abc.com', 'upstreams':[...]}
    returns OrderedDict{ 'abc.com': [host_dict, …], ... }  sorted.
    """
    grouped = collections.defaultdict(list)
    for h in hosts:
        base = registrable_domain(h["host"])
        grouped[base].append(h)

    # sort groups and hosts alphabetically
    grouped_sorted = collections.OrderedDict()
    for domain in sorted(grouped.keys()):
        grouped_sorted[domain] = sorted(grouped[domain],
                                        key=lambda x: x["host"])
    return grouped_sorted