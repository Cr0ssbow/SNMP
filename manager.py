"""
SNMP менеджер на базе pysnmp 7.x.

Отправляет SET и GET запросы к агенту по OID 1.3.6.1.4.1.99999.1.0.
Использует SNMPv2c с community 'public'.
"""

import asyncio
from pysnmp.hlapi.v3arch.asyncio import (
    set_cmd, get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity, OctetString
)

AGENT_HOST = '192.168.0.110'  # IP адрес агента
COMMUNITY  = 'public'         # SNMP community string
OID        = (1, 3, 6, 1, 4, 1, 99999, 1, 0)  # OID целевой переменной
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


async def main():
    """Последовательно выполняет SET и GET запросы."""
    await snmp_set()
    await snmp_get()

asyncio.run(main())
