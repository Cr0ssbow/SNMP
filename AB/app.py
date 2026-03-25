from flask import Flask, render_template, request, jsonify
import serial.tools.list_ports
import threading
import time
import socket
import struct
import asyncio
from modbus import create_modbus_client, calculate_values_from_registers
from flask_socketio import SocketIO
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Импорты для SNMP
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c
from pysnmp.smi import builder, view, compiler
from pysnmp.smi.error import SmiError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_here'
app.config['SNMP_PORT'] = 1161

auth = HTTPBasicAuth()
socketio = SocketIO(app, cors_allowed_origins="*")

users = {
    "admin": generate_password_hash("admin123"),
    "client": generate_password_hash("client123")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None


# ---------------- DEVICE STATE ---------------- #

devices_lock = threading.Lock()
device = {
    "client": None,
    "connected": False,
    "polling": False,
    "interval": 1,
    "values": ["—"] * 7,
    "port": None,
    "snmp_port": 1161
}


# ---------------- UTILS ---------------- #

def get_unit(parameter):
    units = {
        'freq_set': 'Гц', 'freq_out': 'Гц', 'volt_out': 'В',
        'curr_out': 'А', 'pow_out': 'Вт', 'torque_out': '%', 'volt_pt': 'В'
    }
    return units.get(parameter, '')


# ---------------- SNMP АГЕНТ (pysnmp) ---------------- #

class SNMPAgent:
    def __init__(self):
        self.snmp_engine = None
        self.running = False
        self.thread = None
        self.port = 1161
        self.community = "mypublic"
        
        # Сопоставление OID с индексами значений устройства
        # Используем поддерево 1.3.6.1.4.1.9999.1.x для организации walk
        # Каждый параметр - отдельный узел в поддереве
        self.oid_mapping = {
            (1, 3, 6, 1, 4, 1, 9999, 1, 1, 0): 0,  # Частота заданная
            (1, 3, 6, 1, 4, 1, 9999, 1, 2, 0): 1,  # Частота выходная
            (1, 3, 6, 1, 4, 1, 9999, 1, 3, 0): 2,  # Напряжение
            (1, 3, 6, 1, 4, 1, 9999, 1, 4, 0): 3,  # Ток
            (1, 3, 6, 1, 4, 1, 9999, 1, 5, 0): 4,  # Мощность
            (1, 3, 6, 1, 4, 1, 9999, 1, 6, 0): 5,  # Момент
            (1, 3, 6, 1, 4, 1, 9999, 1, 7, 0): 6,  # Напряжение ПТ
        }
        
        # Создаем список всех OID для сортировки (для walk)
        self.sorted_oids = sorted(self.oid_mapping.keys())
        
    def get_value_for_oid(self, oid_tuple):
        """Получает значение для указанного OID из данных устройства"""
        if oid_tuple in self.oid_mapping:
            idx = self.oid_mapping[oid_tuple]
            with devices_lock:
                if device["connected"] and device["values"][idx] != "—":
                    value_str = str(device["values"][idx])
                    return v2c.OctetString(value_str)
        return None
    
    def find_next_oid(self, oid_tuple):
        """Находит следующий OID в дереве для walk/next операций"""
        # Если oid_tuple пустой или None, возвращаем первый OID
        if not oid_tuple:
            return self.sorted_oids[0] if self.sorted_oids else None
        
        # Проверяем, находится ли запрошенный OID в нашем поддереве
        # Если oid меньше первого нашего OID, возвращаем первый
        if oid_tuple < self.sorted_oids[0]:
            return self.sorted_oids[0]
        
        # Ищем следующий OID
        for oid in self.sorted_oids:
            if oid > oid_tuple:
                return oid
        
        # Если следующего нет, возвращаем конец дерева
        return None
    
    def find_previous_oid(self, oid_tuple):
        """Находит предыдущий OID (для обратного обхода)"""
        prev_oid = None
        for oid in self.sorted_oids:
            if oid >= oid_tuple:
                break
            prev_oid = oid
        return prev_oid


# Создаем глобальный экземпляр SNMP агента
snmp_agent = SNMPAgent()


# ---------------- ПОЛЬЗОВАТЕЛЬСКИЙ ОБРАБОТЧИК SNMP ---------------- #

class CustomMibScalarInstance:
    """Базовый класс для MIB скалярных экземпляров"""
    def __init__(self, oid, instance_id, syntax, idx):
        self.oid = oid
        self.instance_id = instance_id
        self.syntax = syntax
        self.idx = idx
    
    def getValue(self, name, **context):
        with devices_lock:
            if device["connected"] and device["values"][self.idx] != "—":
                value_str = str(device["values"][self.idx])
                return self.syntax.clone(value_str)
        return self.syntax.clone("—")
    
    def setValue(self, value, **context):
        raise Exception("Read-only variable")


def run_snmp_agent():
    """Запускает SNMP агент с использованием pysnmp"""
    try:
        # Создаем event loop для asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Создаем SNMP движок
        snmp_engine = engine.SnmpEngine()
        
        # Настраиваем UDP транспорт
        config.add_transport(
            snmp_engine,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode(('0.0.0.0', snmp_agent.port))
        )
        
        # Настраиваем community string
        config.add_v1_system(snmp_engine, 'my-area', snmp_agent.community)
        
        # Настраиваем VACM доступ для всего нашего поддерева
        config.add_vacm_user(
            snmp_engine, 2, 'my-area', 'noAuthNoPriv',
            readSubTree=(1, 3, 6, 1, 4, 1, 9999),
            writeSubTree=(),
            notifySubTree=()
        )
        
        # Создаем SNMP контекст
        snmp_context = context.SnmpContext(snmp_engine)
        
        # Регистрируем наши OID напрямую через MIB builder
        mib_builder = snmp_context.getMibInstrum().getMibBuilder()
        
        # Создаем новый MIB модуль
        mib_builder.loadModule('SNMPv2-SMI')
        MibScalar, MibScalarInstance = mib_builder.importSymbols(
            'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
        )
        
        # Регистрируем каждую переменную
        for oid_tuple, idx in snmp_agent.oid_mapping.items():
            parent_oid = oid_tuple[:-1]  # OID без последнего 0
            instance_id = (oid_tuple[-1],)  # Индекс экземпляра
            
            # Создаем класс для этого OID
            class DynamicMibScalarInstance(CustomMibScalarInstance):
                pass
            
            # Создаем экземпляр
            instance = DynamicMibScalarInstance(
                parent_oid, 
                instance_id, 
                v2c.OctetString(""),
                idx
            )
            
            # Регистрируем в MIB
            mib_builder.exportSymbols(
                '__MY_MIB',
                MibScalar(parent_oid, v2c.OctetString()),
                instance
            )
        
        # Регистрируем стандартные обработчики
        cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
        cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
        cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
        
        app.logger.info(f"SNMP Agent started on port {snmp_agent.port}")
        
        # Запускаем диспетчер
        snmp_engine.transport_dispatcher.job_started(1)
        snmp_engine.transport_dispatcher.run_dispatcher()
        
    except Exception as e:
        app.logger.error(f"SNMP Agent error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if snmp_engine:
            snmp_engine.transport_dispatcher.close_dispatcher()


# ---------------- POLLING ---------------- #

def polling_thread():
    """Поток опроса Modbus устройства"""
    while True:
        with devices_lock:
            if not device["polling"]:
                break
            client = device["client"]
            interval = device["interval"]
        
        try:
            if client:
                result = client.read_holding_registers(291, count=12, slave=1)
                regs = result.registers
                values = calculate_values_from_registers(regs)
                
                with devices_lock:
                    device["values"] = values
                    device["connected"] = True
                
                app.logger.debug(f"Polling successful: {values}")
            else:
                with devices_lock:
                    device["connected"] = False
                    device["values"] = ["—"] * 7
                
        except Exception as e:
            with devices_lock:
                device["connected"] = False
                device["values"] = ["—"] * 7
            app.logger.error(f"Polling error: {e}")
        
        broadcast_device_state()
        time.sleep(interval)


def broadcast_device_state():
    """Отправляет состояние устройства через WebSocket"""
    with devices_lock:
        socketio.emit('device_update', device)


# ---------------- AUTO CONNECT ---------------- #

def auto_connect():
    """Автоматическое подключение к Modbus устройству"""
    ports = [p.device for p in serial.tools.list_ports.comports()]
    for port in ports:
        try:
            app.logger.info(f"Trying to connect to {port}")
            client = create_modbus_client(port)
            if client.connect():
                with devices_lock:
                    device["client"] = client
                    device["connected"] = True
                    device["port"] = port
                    device["polling"] = True
                
                # Запускаем SNMP агент в отдельном потоке
                snmp_agent.thread = threading.Thread(target=run_snmp_agent, daemon=True)
                snmp_agent.thread.start()
                snmp_agent.running = True
                
                # Запускаем поток опроса
                threading.Thread(target=polling_thread, daemon=True).start()
                
                app.logger.info(f"Connected to device on {port}")
                return
        except Exception as e:
            app.logger.error(f"Failed to connect to {port}: {e}")
            continue


# ---------------- ROUTES ---------------- #

@app.route('/')
def home():
    return "OK"


@app.route('/start_polling', methods=['POST'])
def start_polling():
    """Запускает опрос Modbus устройства"""
    with devices_lock:
        if device["polling"]:
            return jsonify({"status": "already"})
        device["polling"] = True
    
    threading.Thread(target=polling_thread, daemon=True).start()
    return jsonify({"status": "started"})


@app.route('/stop_polling', methods=['POST'])
def stop_polling():
    """Останавливает опрос Modbus устройства"""
    with devices_lock:
        device["polling"] = False
    return jsonify({"status": "stopped"})


@app.route('/snmp/status', methods=['GET'])
def snmp_status():
    """Проверяет статус SNMP агента"""
    return jsonify({
        "running": snmp_agent.running,
        "port": snmp_agent.port,
        "community": snmp_agent.community,
        "registered_oids": list(snmp_agent.oid_mapping.keys())
    })


@app.route('/device/values', methods=['GET'])
def device_values():
    """Возвращает текущие значения устройства"""
    with devices_lock:
        return jsonify({
            "connected": device["connected"],
            "values": device["values"],
            "polling": device["polling"]
        })


# ---------------- MAIN ---------------- #

def main():
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Запускаем авто-подключение в отдельном потоке
    threading.Thread(target=auto_connect, daemon=True).start()
    
    # Запускаем Flask приложение с SocketIO
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )


if __name__ == "__main__":
    main()