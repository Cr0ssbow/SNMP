# =============================================================================
# SNMP Клиент (snmpget)
# Протокол: SNMP v2c поверх UDP
# Библиотека: pysnmp (pip install pysnmp)
#
# Запуск: python snmpwork.py
#
# Подсказка: можно передать другой хост/порт/OID через аргументы:
#   result = asyncio.run(snmpget(host='192.168.1.10', port=1161))
#
# Полезные OID для запросов:
#   1.3.6.1.2.1.1.1.0 — sysDescr    (описание системы)
#   1.3.6.1.2.1.1.3.0 — sysUpTime   (время работы)
#   1.3.6.1.2.1.1.5.0 — sysName     (имя хоста)
# =============================================================================

import asyncio
from pysnmp.hlapi.asyncio import (
    get_cmd, SnmpEngine, CommunityData,
    UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
)

# --- Настройки подключения к агенту ---
# IP адрес Windows машины где запущен agent.py
# Подсказка: узнать IP на Windows — команда ipconfig
AGENT_HOST = '192.168.100.7'
AGENT_PORT = 1161

# Community string — должен совпадать с тем, что задан в agent.py
COMMUNITY = 'public'

# OID переменной, значение которой хотим получить
OID = '1.3.6.1.2.1.1.1.0'


async def snmpget(host=AGENT_HOST, port=AGENT_PORT, oid=OID):
    """
    Выполняет SNMP GET запрос к агенту по UDP.

    Параметры:
        host — IP адрес или hostname агента
        port — UDP порт агента
        oid  — OID переменной для чтения

    Возвращает строковое значение переменной или None при ошибке.
    """

    # get_cmd — асинхронная функция SNMP GET запроса
    # mpModel=1 — использовать SNMPv2c (0=v1, 1=v2c)
    # UdpTransportTarget.create — создаёт UDP транспорт (обязательно через .create())
    #   timeout — секунд ждать ответа от агента
    #   retries — количество повторных попыток при отсутствии ответа
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        await UdpTransportTarget.create((host, port), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    # errorIndication — ошибка транспортного уровня (нет связи, timeout)
    if errorIndication:
        print(f'Ошибка соединения: {errorIndication}')
        # Подсказка: если timeout — проверьте:
        #   1. Запущен ли agent.py
        #   2. Правильный ли IP/порт
        #   3. Открыт ли порт в firewall (UDP 1161)
        return None

    # errorStatus — ошибка SNMP протокола (неверный OID, нет доступа и т.д.)
    elif errorStatus:
        print(f'SNMP ошибка: {errorStatus.prettyPrint()} at index {errorIndex}')
        # Подсказка: noSuchName означает что OID не найден в MIB агента
        return None

    # varBinds — список пар (OID, значение) из ответа агента
    for varBind in varBinds:
        name, value = varBind
        print(f'{name} = {value}')
        return str(value)


if __name__ == '__main__':
    # asyncio.run() — запускает асинхронную функцию в синхронном контексте
    result = asyncio.run(snmpget())
    print(f'Получено значение: {result}')
