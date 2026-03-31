"""
SNMP менеджер на базе pysnmp 7.x.

Отправляет SET и GET запросы к агенту по OID 1.3.6.1.4.1.99999.1.0.
Использует SNMPv2c с community 'public'.
"""

import asyncio
from pysnmp.hlapi.v3arch.asyncio import (
    set_cmd, get_cmd, next_cmd, bulk_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity, OctetString
)

AGENT_HOST = '192.168.0.110'  # IP адрес агента
COMMUNITY  = 'public'         # SNMP community string
OID        = (1, 3, 6, 1, 4, 1, 99999, 1, 0)  # OID целевой переменной для GET/SET
WALK_ROOT  = (1, 3, 6, 1, 4, 1, 99999)         # Корень поддерева для WALK
VALUE      = "Hello from Windows!"             # Значение для SET запроса


async def snmp_set():
    """Отправляет SET запрос агенту, устанавливая значение VALUE."""
    errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        await UdpTransportTarget.create((AGENT_HOST, 1161)),
        ContextData(),
        ObjectType(ObjectIdentity(OID), OctetString(VALUE))
    )
    if errorIndication:
        print(f"[SET] Ошибка: {errorIndication}")
    elif errorStatus:
        print(f"[SET] Ошибка статуса: {errorStatus.prettyPrint()}")
    else:
        print(f"[SET] Отправлено: {VALUE}")


async def snmp_get():
    """Отправляет GET запрос агенту и выводит полученное значение."""
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        await UdpTransportTarget.create((AGENT_HOST, 1161)),
        ContextData(),
        ObjectType(ObjectIdentity(OID))
    )
    if errorIndication:
        print(f"[GET] Ошибка: {errorIndication}")
    elif errorStatus:
        print(f"[GET] Ошибка статуса: {errorStatus.prettyPrint()}")
    else:
        for oid, value in varBinds:
            print(f"[GET] {oid} = {value.prettyPrint()}")


async def snmp_walk():
    """Обходит поддерево OID с помощью GETNEXT запросов."""
    current_oid = WALK_ROOT
    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((AGENT_HOST, 1161))
    while True:
        errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
            engine,
            CommunityData(COMMUNITY, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(current_oid))
        )
        if errorIndication or errorStatus:
            break
        for oid, value in varBinds:
            oid_tuple = tuple(oid)
            if oid_tuple[:len(WALK_ROOT)] != WALK_ROOT:
                return
            pretty = value.prettyPrint()
            if 'No more variables' in pretty:
                return
            print(f"[WALK] {oid} = {pretty}")
            current_oid = oid_tuple


async def main():
    commands = {
        '1': ('GET',  snmp_get),
        '2': ('SET',  snmp_set),
        '3': ('WALK', snmp_walk),
    }
    while True:
        print("\nВыберите команду:")
        for key, (name, _) in commands.items():
            print(f"  {key}. {name}")
        print("  0. Выход")
        choice = input("Ввод: ").strip()
        if choice == '0':
            break
        elif choice in commands:
            await commands[choice][1]()
        else:
            print("Неверный выбор")

asyncio.run(main())
