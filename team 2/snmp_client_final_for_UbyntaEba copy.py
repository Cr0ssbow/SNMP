#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
SNMP АГЕНТ с поддержкой WALK - чистый Python
================================================================================
Описание:
    SNMP Агент (сервер), который поддерживает:
    - SNMP GET (получение одного значения по OID)
    - SNMP GETNEXT (получение следующего OID - для WALK)
    - SNMP WALK (обход всех OID в ветке)

    Хранит 7 переменных в ветке 1.3.6.1.4.1.9999.1.X.0

Совместимость:
    - snmpget / snmpwalk (Net-SNMP)
    - iReasoning MIB Browser
    - Любые SNMP менеджеры

Версия: 2.0 (с поддержкой WALK)
================================================================================
"""

import socket
import struct
import datetime
import time
import random
import threading

# ==============================================================================
# КОНФИГУРАЦИЯ СЕРВЕРА
# ==============================================================================

HOST = '0.0.0.0'      # Слушаем на всех интерфейсах
PORT = 1161           # UDP порт (161 требует root)
COMMUNITY = 'public'  # Community string для авторизации

# ==============================================================================
# ХРАНИЛИЩЕ ДАННЫХ - 7 ПЕРЕМЕННЫХ
# ==============================================================================
# Эти данные будут отдаваться по SNMP запросам.
# В реальном приложении здесь могут быть данные с датчиков, Modbus и т.д.
# ==============================================================================

data = {
    'freq_set': 50.0,      # Частота заданная (Гц)
    'freq_out': 49.8,      # Частота выходная (Гц)
    'volt_out': 220.5,     # Напряжение выходное (В)
    'curr_out': 15.3,      # Ток выходной (А)
    'pow_out': 3200.0,     # Мощность выходная (Вт)
    'torque_out': 75.5,    # Момент (%)
    'volt_pt': 24.1        # Напряжение ПТ (В)
}

# ==============================================================================
# ТАБЛИЦА OID - СОПОСТАВЛЕНИЕ OID С ДАННЫМИ
# ==============================================================================
#
# Структура OID:
#   1.3.6.1.4.1.9999.1.X.0
#   │ │ │ │ │ │    │ │ └─ Экземпляр (0 = скалярное значение)
#   │ │ │ │ │ │    │ └─── Номер переменной (1-7)
#   │ │ │ │ │ │    └───── Группа переменных (1)
#   │ │ │ │ │ └────────── Enterprise ID (9999 - наш)
#   │ │ │ │ └──────────── enterprises (1)
#   │ │ │ └────────────── private (4)
#   │ │ └──────────────── internet (1)
#   │ └────────────────── dod (6)
#   └──────────────────── org (3)
#
# Для WALK важно, чтобы OID были ОТСОРТИРОВАНЫ по возрастанию!
# ==============================================================================

# Список OID в порядке возрастания (критично для WALK!)
OID_TABLE = [
    # (OID в байтах, ключ в data, описание, тип: 'string' или 'integer')
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x01\x00', 'freq_set',   'Частота заданная (Гц)',   'string'),
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x02\x00', 'freq_out',   'Частота выходная (Гц)',   'string'),
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x03\x00', 'volt_out',   'Напряжение (В)',          'string'),
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x04\x00', 'curr_out',   'Ток (А)',                 'string'),
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x05\x00', 'pow_out',    'Мощность (Вт)',           'string'),
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x06\x00', 'torque_out', 'Момент (%)',              'string'),
    (b'\x2b\x06\x01\x04\x01\xce\x0f\x01\x07\x00', 'volt_pt',    'Напряжение ПТ (В)',       'string'),
]

# Префикс нашего поддерева (для проверки принадлежности OID)
# 1.3.6.1.4.1.9999.1 = 2b 06 01 04 01 ce 0f 01
OID_PREFIX = b'\x2b\x06\x01\x04\x01\xce\x0f\x01'

# BER кодирование 9999:
# 9999 = 0x270F
# В BER: (9999 >> 7) | 0x80 = 0xCE, 9999 & 0x7F = 0x0F
# Итого: CE 0F

# ==============================================================================
# ВЫВОД ЗАГОЛОВКА
# ==============================================================================

print("=" * 70)
print("  SNMP АГЕНТ с поддержкой WALK")
print(f"  Слушаю на {HOST}:{PORT}")
print(f"  Community: {COMMUNITY}")
print("=" * 70)


# ==============================================================================
# ФУНКЦИИ КОДИРОВАНИЯ BER/ASN.1
# ==============================================================================

def encode_length(length):
    """
    Кодирует длину в BER формате.

    BER длина:
    - Если < 128: один байт со значением длины
    - Если >= 128: первый байт = 0x80 + кол-во байт длины, затем сама длина
    """
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def encode_string(s):
    """Кодирует строку в SNMP OCTET STRING."""
    text = str(s)
    encoded = text.encode('utf-8')
    return b'\x04' + encode_length(len(encoded)) + encoded


def encode_integer(i):
    """Кодирует число в SNMP INTEGER."""
    if i == 0:
        return b'\x02\x01\x00'
    elif 0 < i < 128:
        return b'\x02\x01' + bytes([i])
    elif 128 <= i < 256:
        return b'\x02\x02\x00' + bytes([i])   # добавляем 0x00 для положительного числа
    else:
        # Для больших чисел
        result = []
        temp = i
        while temp > 0:
            result.insert(0, temp & 0xFF)
            temp >>= 8
        # Если старший бит = 1, добавляем 0x00 (иначе будет отрицательное)
        if result[0] & 0x80:
            result.insert(0, 0)
        return b'\x02' + bytes([len(result)]) + bytes(result)


def encode_oid(oid_bytes):
    """Оборачивает OID байты в ASN.1 тег."""
    return b'\x06' + encode_length(len(oid_bytes)) + oid_bytes


def encode_sequence(content):
    """Оборачивает содержимое в SEQUENCE."""
    return b'\x30' + encode_length(len(content)) + content


def encode_null():
    """Кодирует NULL значение."""
    return b'\x05\x00'


# ==============================================================================
# ФУНКЦИИ РАБОТЫ С OID
# ==============================================================================

def get_value_by_oid(oid_bytes):
    """Получает значение по точному совпадению OID (для GET)."""
    for oid, key, desc, vtype in OID_TABLE:
        if oid == oid_bytes:
            value = data.get(key, '—')
            return (oid, value, vtype)
    return None


def get_next_oid(oid_bytes):
    """
    Находит СЛЕДУЮЩИЙ OID в дереве (для GETNEXT/WALK).
    """
    # Если запрос на префикс без конкретного OID
    if len(oid_bytes) <= len(OID_PREFIX):
        oid, key, desc, vtype = OID_TABLE[0]
        return (oid, data.get(key, '—'), vtype)

    # Если OID меньше нашего первого - возвращаем первый
    if oid_bytes < OID_TABLE[0][0]:
        oid, key, desc, vtype = OID_TABLE[0]
        return (oid, data.get(key, '—'), vtype)

    # Ищем следующий OID, который БОЛЬШЕ запрошенного
    for oid, key, desc, vtype in OID_TABLE:
        if oid > oid_bytes:
            return (oid, data.get(key, '—'), vtype)

    # Конец дерева
    return None


# ==============================================================================
# ФУНКЦИИ СОЗДАНИЯ SNMP ОТВЕТОВ
# ==============================================================================

def create_get_response(request_id, oid_bytes, value, value_type):
    """Создаёт SNMP GET-RESPONSE пакет."""
    # Кодируем значение
    if value_type == 'integer':
        value_encoded = encode_integer(int(value))
    else:
        value_encoded = encode_string(value)

    # VarBind: SEQUENCE { OID, Value }
    oid_encoded = encode_oid(oid_bytes)
    varbind = encode_sequence(oid_encoded + value_encoded)

    # VarBindList: SEQUENCE { VarBind }
    varbindlist = encode_sequence(varbind)

    # PDU: [0xA2 = GET-RESPONSE] + длина + (request-id, error-status, error-index, varbinds)
    error_status = b'\x02\x01\x00'   # noError
    error_index = b'\x02\x01\x00'    # 0

    pdu_content = request_id + error_status + error_index + varbindlist
    pdu = b'\xa2' + encode_length(len(pdu_content)) + pdu_content

    # SNMP Message: SEQUENCE { version, community, PDU }
    version = b'\x02\x01\x01'  # SNMPv2c (для лучшей совместимости)
    community = b'\x04' + encode_length(len(COMMUNITY)) + COMMUNITY.encode('utf-8')

    message_content = version + community + pdu
    return encode_sequence(message_content)


def create_error_response(request_id, oid_bytes, error_status, error_index=1):
    """
    Создаёт SNMP ответ с ошибкой.
    Error Status коды:
    - 0 = noError
    - 1 = tooBig
    - 2 = noSuchName (OID не найден)
    - 3 = badValue
    - 4 = readOnly
    - 5 = genErr
    """
    # Возвращаем OID с NULL значением
    oid_encoded = encode_oid(oid_bytes)
    varbind = encode_sequence(oid_encoded + encode_null())
    varbindlist = encode_sequence(varbind)

    error_st = b'\x02\x01' + bytes([error_status])
    error_idx = b'\x02\x01' + bytes([error_index])

    pdu_content = request_id + error_st + error_idx + varbindlist
    pdu = b'\xa2' + encode_length(len(pdu_content)) + pdu_content

    version = b'\x02\x01\x01'
    community = b'\x04' + encode_length(len(COMMUNITY)) + COMMUNITY.encode('utf-8')

    message_content = version + community + pdu
    return encode_sequence(message_content)


def create_end_of_mib_response(request_id, oid_bytes):
    """
    Создаёт ответ "End of MIB" для GETNEXT когда достигнут конец дерева.
    В SNMPv2c это endOfMibView (тег 0x82).
    """
    oid_encoded = encode_oid(oid_bytes)
    end_of_mib = b'\x82\x00'  # endOfMibView (implicit, primitive, tag 2 in context class)

    varbind = encode_sequence(oid_encoded + end_of_mib)
    varbindlist = encode_sequence(varbind)

    error_status = b'\x02\x01\x00'
    error_index = b'\x02\x01\x00'

    pdu_content = request_id + error_status + error_index + varbindlist
    pdu = b'\xa2' + encode_length(len(pdu_content)) + pdu_content

    version = b'\x02\x01\x01'
    community = b'\x04' + encode_length(len(COMMUNITY)) + COMMUNITY.encode('utf-8')

    message_content = version + community + pdu
    return encode_sequence(message_content)


# ==============================================================================
# ПАРСИНГ SNMP ЗАПРОСОВ
# ==============================================================================

def parse_snmp_request(packet):
    """
    Парсит входящий SNMP пакет и извлекает информацию.
    Определяет тип запроса:
    - 0xA0 = GET-REQUEST
    - 0xA1 = GETNEXT-REQUEST (используется для WALK)
    - 0xA5 = GETBULK-REQUEST (SNMPv2)
    """
    try:
        # Определяем тип PDU
        pdu_type = None
        if b'\xa0' in packet:
            pdu_type = 'GET'
            pdu_idx = packet.find(b'\xa0')
        elif b'\xa1' in packet:
            pdu_type = 'GETNEXT'
            pdu_idx = packet.find(b'\xa1')
        elif b'\xa5' in packet:
            pdu_type = 'BULK'
            pdu_idx = packet.find(b'\xa5')
        else:
            return None

        # Извлекаем Request ID (ищем 0x02 0x04 после PDU тега)
        req_id_idx = packet.find(b'\x02\x04', pdu_idx)
        if req_id_idx == -1:
            # Пробуем искать короткий request ID (0x02 0x01, 0x02 0x02, 0x02 0x03)
            for length in [1, 2, 3]:
                pattern = b'\x02' + bytes([length])
                idx = packet.find(pattern, pdu_idx)
                if idx != -1:
                    req_id_idx = idx
                    request_id = packet[idx:idx + 2 + length]
                    break
            else:
                return None
        else:
            request_id = packet[req_id_idx:req_id_idx + 6]

        # Извлекаем OID (ищем 0x06)
        oid_idx = packet.find(b'\x06', req_id_idx)
        if oid_idx == -1:
            return None

        oid_len = packet[oid_idx + 1]
        oid_bytes = packet[oid_idx + 2:oid_idx + 2 + oid_len]

        # Извлекаем community (ищем 0x04 в начале пакета)
        comm_idx = packet.find(b'\x04')
        if comm_idx != -1 and comm_idx < pdu_idx:
            comm_len = packet[comm_idx + 1]
            community = packet[comm_idx + 2:comm_idx + 2 + comm_len].decode('utf-8', errors='ignore')
        else:
            community = 'public'

        return {
            'type': pdu_type,
            'request_id': request_id,
            'oid': oid_bytes,
            'community': community
        }

    except Exception as e:
        print(f"[!] Ошибка парсинга: {e}")
        return None


# ==============================================================================
# ФОНОВОЕ ОБНОВЛЕНИЕ ДАННЫХ
# ==============================================================================

def update_data():
    """
    Фоновый поток для обновления данных каждые 5 секунд.
    Имитирует изменение показаний датчиков.
    """
    while True:
        time.sleep(5)

        # Имитируем изменение показаний
        data['freq_set'] = round(50.0 + random.uniform(-0.5, 0.5), 2)
        data['freq_out'] = round(data['freq_set'] + random.uniform(-0.3, 0.3), 2)
        data['volt_out'] = round(220.0 + random.uniform(-5, 5), 1)
        data['curr_out'] = round(15.0 + random.uniform(-2, 2), 2)
        data['pow_out'] = round(data['volt_out'] * data['curr_out'], 1)
        data['torque_out'] = round(75.0 + random.uniform(-5, 5), 1)
        data['volt_pt'] = round(24.0 + random.uniform(-0.5, 0.5), 2)

        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"[~] {timestamp} | freq={data['freq_out']:.1f}Hz, U={data['volt_out']:.0f}V, "
              f"I={data['curr_out']:.1f}A, P={data['pow_out']:.0f}W")


# Запускаем поток обновления данных
threading.Thread(target=update_data, daemon=True).start()

# ==============================================================================
# СОЗДАНИЕ UDP СОКЕТА
# ==============================================================================

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

# ==============================================================================
# ВЫВОД ИНФОРМАЦИИ О ДОСТУПНЫХ OID
# ==============================================================================

print("\n[✓] Доступные OID (7 переменных):")
for i, (oid, key, desc, vtype) in enumerate(OID_TABLE, 1):
    print(f"  {i}. 1.3.6.1.4.1.9999.1.{i}.0 - {desc}")

print(f"\n[✓] Команды для тестирования:")
print(f"    snmpget -v2c -c {COMMUNITY} {HOST}:{PORT} 1.3.6.1.4.1.9999.1.1.0")
print(f"    snmpwalk -v2c -c {COMMUNITY} {HOST}:{PORT} 1.3.6.1.4.1.9999.1")
print(f"\n[✓] ГОТОВ! Ctrl+C для остановки\n")

# ==============================================================================
# ГЛАВНЫЙ ЦИКЛ ОБРАБОТКИ ЗАПРОСОВ
# ==============================================================================

try:
    while True:
        # Ожидаем UDP пакет
        packet, addr = sock.recvfrom(1024)

        # Парсим запрос
        request = parse_snmp_request(packet)

        if not request:
            print(f"[!] Некорректный пакет от {addr[0]}:{addr[1]}")
            continue

        request_type = request['type']
        request_id = request['request_id']
        oid_bytes = request['oid']

        print(f"[←] {request_type} от {addr[0]}:{addr[1]} | OID: {oid_bytes.hex()}")

        # ======================================================================
        # ОБРАБОТКА GET ЗАПРОСА
        # ======================================================================
        if request_type == 'GET':
            result = get_value_by_oid(oid_bytes)
            if result:
                oid, value, vtype = result
                response = create_get_response(request_id, oid, value, vtype)
                print(f"[→] Отправляю: {value}")
            else:
                response = create_error_response(request_id, oid_bytes, 2)  # noSuchName
                print(f"[!] OID не найден")

        # ======================================================================
        # ОБРАБОТКА GETNEXT ЗАПРОСА (ДЛЯ WALK)
        # ======================================================================
        elif request_type == 'GETNEXT' or request_type == 'BULK':
            result = get_next_oid(oid_bytes)
            if result:
                oid, value, vtype = result
                response = create_get_response(request_id, oid, value, vtype)
                print(f"[→] Следующий OID: {oid.hex()} = {value}")
            else:
                response = create_end_of_mib_response(request_id, oid_bytes)
                print(f"[→] Конец дерева (endOfMibView)")

        else:
            print(f"[!] Неизвестный тип запроса")
            continue

        # Отправляем ответ
        sock.sendto(response, addr)

except KeyboardInterrupt:
    print("\n[!] Агент остановлен")
finally:
    sock.close()