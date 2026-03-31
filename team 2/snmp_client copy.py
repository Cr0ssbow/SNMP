#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP клиент для Windows.
Поддерживает:
- GET запросы к конкретным OID
- WALK (обход) ветки OID
Использует UDP, community 'public'.
"""

import socket
import struct
import time
import random

# ====== Конфигурация ======
AGENT_IP = '192.168.0.203'   # IP-адрес SNMP агента
AGENT_PORT = 1161            # Порт агента
COMMUNITY = 'public'         # Community string
TIMEOUT = 3.0                # Таймаут ответа (сек)

# Глобальный идентификатор запроса (увеличивается при каждом запросе)
rid = random.randint(1, 50000)


# ====== Функции кодирования BER/ASN.1 ======
def enc_len(n: int) -> bytes:
    """Кодирует длину в BER формате."""
    if n < 128:
        return bytes([n])
    return bytes([0x81, n])


def enc_oid_str(s: str) -> bytes:
    """
    Преобразует строковый OID (например "1.3.6.1.4.1.9999.1.1.0")
    в BER-кодированную последовательность байтов.
    """
    s = s.strip().lstrip('.')
    if not s:
        raise ValueError("OID пустой")
    parts = [int(x) for x in s.split('.') if x]
    # Первые два числа кодируются как first*40 + second
    r = bytes([parts[0]*40 + parts[1]])
    # Остальные числа кодируются с разделением на 7-битные группы
    for n in parts[2:]:
        if n < 128:
            r += bytes([n])
        else:
            t = []
            while n > 0:
                t.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(t)-1):
                t[i] |= 0x80
            r += bytes(t)
    return r


def dec_oid(b: bytes) -> str:
    """Декодирует BER-последовательность OID в строку."""
    if not b:
        return ''
    p = [b[0] // 40, b[0] % 40]
    i = 1
    while i < len(b):
        n = 0
        while i < len(b):
            n = (n << 7) | (b[i] & 0x7F)
            i += 1
            if not (b[i-1] & 0x80):
                break
        p.append(n)
    return '.'.join(map(str, p))


def make_pkt(oid_bytes: bytes, pdu_tag: int) -> bytes:
    """
    Формирует SNMP пакет (GET или GETNEXT) для заданного OID.
    pdu_tag: 0xA0 для GET, 0xA1 для GETNEXT
    """
    global rid
    rid += 1
    # Request ID
    reqid = b'\x02\x04' + struct.pack('>I', rid)

    # OID с тегом 0x06
    oid_e = b'\x06' + enc_len(len(oid_bytes)) + oid_bytes

    # VarBind: SEQUENCE { OID, NULL }
    vb = b'\x30' + enc_len(len(oid_e) + 2) + oid_e + b'\x05\x00'

    # VarBindList: SEQUENCE { VarBind }
    vbl = b'\x30' + enc_len(len(vb)) + vb

    # PDU: (tag) + длина + (request-id, error-status, error-index, varbindlist)
    pdu_c = reqid + b'\x02\x01\x00\x02\x01\x00' + vbl
    pdu = bytes([pdu_tag]) + enc_len(len(pdu_c)) + pdu_c

    # SNMP версия (v2c) и community
    ver = b'\x02\x01\x01'
    com = b'\x04\x06public'

    # Сообщение: SEQUENCE { version, community, pdu }
    msg = ver + com + pdu
    return b'\x30' + enc_len(len(msg)) + msg


# ====== Функции разбора ответа ======
def parse(data: bytes):
    """
    Разбирает ответ SNMP агента.
    Возвращает (oid, value, end_of_mib_flag)
    """
    # Проверка признака endOfMibView
    if b'\x82\x00' in data:
        return None, None, True

    # Ищем PDU GET-RESPONSE (тег 0xA2)
    pdu_pos = data.find(b'\xa2')
    if pdu_pos == -1:
        return None, None, False

    # Ищем OID (тег 0x06) после PDU
    oid_pos = -1
    for i in range(pdu_pos + 1, len(data) - 2):
        if data[i] == 0x06:
            oid_len = data[i + 1]
            if 0 < oid_len < 50 and i + 2 + oid_len <= len(data):
                oid_pos = i
                break

    if oid_pos == -1:
        return None, None, False

    oid_len = data[oid_pos + 1]
    oid_bytes = data[oid_pos + 2:oid_pos + 2 + oid_len]
    oid_str = dec_oid(oid_bytes)

    # Значение идёт сразу после OID
    val_pos = oid_pos + 2 + oid_len
    if val_pos >= len(data):
        return oid_str, '', False

    val_tag = data[val_pos]
    val_len = data[val_pos + 1]
    val_data = data[val_pos + 2:val_pos + 2 + val_len]

    if val_tag == 0x04:      # OCTET STRING
        value = val_data.decode('utf-8', errors='replace')
    elif val_tag == 0x02:    # INTEGER
        value = str(int.from_bytes(val_data, 'big')) if val_data else '0'
    elif val_tag == 0x82:    # endOfMibView
        return None, None, True
    else:
        value = val_data.decode('utf-8', errors='replace')

    return oid_str, value, False


# ====== Выполнение GET запроса ======
def snmp_get(oid_string: str):
    """Отправляет GET-запрос к агенту и выводит результат."""
    if not oid_string or not oid_string.strip():
        print("[!] OID пустой")
        return None
    print(f"\n[GET] {oid_string}")
    try:
        pkt = make_pkt(enc_oid_str(oid_string), 0xA0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.sendto(pkt, (AGENT_IP, AGENT_PORT))
        data, _ = s.recvfrom(4096)
        s.close()
        oid, val, eom = parse(data)
        if oid and val:
            print(f"[✓] {oid} = {val}")
            return val
        print("[✗] Нет значения")
        return None
    except socket.timeout:
        print("[✗] Таймаут!")
        return None
    except Exception as e:
        print(f"[✗] Ошибка: {e}")
        return None


# ====== Выполнение WALK (обход) ======
def snmp_walk(base_oid: str):
    """
    Выполняет WALK: последовательно запрашивает GETNEXT,
    начиная с base_oid, пока не выйдет за пределы ветки.
    """
    if not base_oid or not base_oid.strip():
        print("[!] OID пустой")
        return
    base_oid = base_oid.strip().lstrip('.')
    print(f"\n[WALK] {base_oid}")
    print("=" * 60)

    cur = enc_oid_str(base_oid)
    results = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)

    try:
        for i in range(100):   # ограничение на 100 итераций
            pkt = make_pkt(cur, 0xA1)   # GETNEXT
            s.sendto(pkt, (AGENT_IP, AGENT_PORT))
            data, _ = s.recvfrom(4096)

            oid_str, val, eom = parse(data)

            if eom:
                print(f"\n[✓] Конец. Получено {len(results)} значений.")
                break

            if not oid_str:
                print("[!] Ошибка парсинга")
                break

            # Проверяем, остались ли мы в нужной ветке
            if not oid_str.startswith(base_oid + ".") and oid_str != base_oid:
                print(f"\n[✓] Конец ветки. Получено {len(results)} значений.")
                break

            results.append((oid_str, val))
            print(f"  [{len(results)}] {oid_str} = {val}")

            cur = enc_oid_str(oid_str)

    except socket.timeout:
        print(f"[✗] Таймаут после {len(results)} значений")
    except Exception as e:
        print(f"[✗] Ошибка: {e}")
        import traceback
        traceback.print_exc()
    finally:
        s.close()


# ====== Меню ======
oids = [
    "1.3.6.1.4.1.9999.1.1.0",
    "1.3.6.1.4.1.9999.1.2.0",
    "1.3.6.1.4.1.9999.1.3.0",
    "1.3.6.1.4.1.9999.1.4.0",
    "1.3.6.1.4.1.9999.1.5.0",
    "1.3.6.1.4.1.9999.1.6.0",
    "1.3.6.1.4.1.9999.1.7.0",
]
names = ["Частота задан.", "Частота вых.", "Напряжение",
         "Ток", "Мощность", "Момент", "Напряжение ПТ"]

print("=" * 60)
print(f"  SNMP КЛИЕНТ | {AGENT_IP}:{AGENT_PORT}")
print("=" * 60)

while True:
    print("\n" + "-" * 60)
    for i in range(7):
        print(f"  {i+1}. GET  {names[i]}")
    print("  8. WALK все переменные")
    print("  9. GET  свой OID")
    print(" 10. WALK свой OID")
    print("  0. Выход")
    print("-" * 60)

    c = input("➤ ").strip()

    if c in ['1', '2', '3', '4', '5', '6', '7']:
        snmp_get(oids[int(c)-1])
    elif c == '8':
        snmp_walk("1.3.6.1.4.1.9999.1")
    elif c == '9':
        o = input("OID: ").strip()
        if o:
            snmp_get(o)
    elif c == '10':
        o = input("Base OID: ").strip()
        if o:
            snmp_walk(o)
    elif c == '0':
        print("Выход!")
        break