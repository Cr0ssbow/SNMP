# =============================================================================
# SNMP Агент (сервер)
# Протокол: SNMP v2c поверх UDP
# Библиотека: pysnmp (pip install pysnmp)
#
# Запуск: python agent.py
# Проверка с другой машины:
#   snmpget -v2c -c public <IP>:1161 1.3.6.1.4.1.99999.1.0
#   snmpwalk -v2c -c public <IP>:1161 1.3.6.1.4.1.99999
#
# Если агент недоступен с другой машины — откройте порт в firewall:
#   Windows (PowerShell от администратора):
#     New-NetFirewallRule -DisplayName "SNMP 1161" -Direction Inbound -Protocol UDP -LocalPort 1161 -Action Allow
#   Linux:
#     sudo ufw allow 1161/udp
# =============================================================================

import asyncio
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c

# --- Настройки агента ---
# '0.0.0.0' — слушать на всех сетевых интерфейсах (доступен извне)
# '127.0.0.1' — только локально (недоступен с других машин)
AGENT_HOST = '0.0.0.0'

# Порт 161 — стандартный SNMP, требует прав администратора
# Порт 1161 — пользовательский, не требует прав администратора
AGENT_PORT = 1161

# Несколько OID с произвольными значениями для демонстрации snmpwalk
# Формат: (OID_tuple, значение)
# OID 1.3.6.1.2.1.1.X.0 — поддерево system в mib-2 (содержит стандартные объекты Timeticks)
# OID_VALUES = [
#     ((1, 3, 6, 1, 2, 1, 1, 1, 0), 'Hello from SNMP Agent'),   # sysDescr
#     ((1, 3, 6, 1, 2, 1, 1, 2, 0), 'Moscow'),                   # sysObjectID
#     ((1, 3, 6, 1, 2, 1, 1, 4, 0), 'admin@example.com'),        # sysContact
#     ((1, 3, 6, 1, 2, 1, 1, 5, 0), 'MyDevice-01'),              # sysName
#     ((1, 3, 6, 1, 2, 1, 1, 6, 0), 'Server Room 42'),           # sysLocation
# ]

# 1.3.6.1.4.1.99999 — пользовательское поддерево (enterprises), без стандартных объектов
# Формат: (OID_tuple, значение)
# OID[:-1] = (1,3,6,1,4,1,99999,1) — общий родительский узел
# OID[-1]  = 1,2,3,4,5 — индекс экземпляра
OID_VALUES = [
    ((1, 3, 6, 1, 4, 1, 99999, 1, 1), 'Hello from SNMP Agent'),
    ((1, 3, 6, 1, 4, 1, 99999, 1, 2), 'Moscow'),
    ((1, 3, 6, 1, 4, 1, 99999, 1, 3), 'admin@example.com'),
    ((1, 3, 6, 1, 4, 1, 99999, 1, 4), 'MyDevice-01'),
    ((1, 3, 6, 1, 4, 1, 99999, 1, 5), 'Server Room 42'),
]

# Python 3.10+ не создаёт event loop автоматически — создаём вручную
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# Создаём SNMP движок — центральный объект, управляющий всем агентом
snmpEngine = engine.SnmpEngine()

# Регистрируем UDP транспорт — агент будет принимать пакеты по UDP
# udp.DOMAIN_NAME — идентификатор UDP/IPv4 транспорта
config.add_transport(
    snmpEngine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().open_server_mode((AGENT_HOST, AGENT_PORT))
)

# Настраиваем community string для SNMPv1/v2c аутентификации
# 'my-area' — внутреннее имя (securityName)
# 'public'  — community string, который указывает клиент в запросе
# Подсказка: для безопасности замените 'public' на уникальную строку
config.add_v1_system(snmpEngine, 'my-area', 'public')

# VACM (View-based Access Control Model) — контроль доступа
# readSubTree  — OID поддерева, доступного для чтения (snmpget/snmpwalk)
# writeSubTree — OID поддерева, доступного для записи (snmpset)
# notifySubTree — OID поддерева для уведомлений (trap)
config.add_vacm_user(
    snmpEngine, 2, 'my-area', 'noAuthNoPriv',
    readSubTree=(1, 3, 6, 1, 4, 1, 99999),
    writeSubTree=(1, 3, 6, 1, 4, 1, 99999),
    notifySubTree=(1, 3, 6, 1, 4, 1, 99999)
)


# Создаём SNMP контекст и получаем MIB builder для регистрации OID
snmpContext = context.SnmpContext(snmpEngine)
mibBuilder = snmpContext.get_mib_instrum().get_mib_builder()

# Импортируем базовые классы MIB для создания собственных переменных
MibScalar, MibScalarInstance = mibBuilder.import_symbols(
    'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
)

# Динамически создаём класс для каждого OID со своим значением
def make_mib_instance(oid, value):
    class DynamicValue(MibScalarInstance):
        _value = value
        def getValue(self, name, **context):
            return self.syntax.clone(self._value)
    return DynamicValue

# Регистрируем все OID в MIB дереве агента
# MibScalar — родительский узел, регистрируется один раз для всего поддерева
# MibScalarInstance — каждый экземпляр со своим индексом и значением
PARENT_OID = (1, 3, 6, 1, 4, 1, 99999, 1)

export_list = [MibScalar(PARENT_OID, v2c.OctetString())]
for oid, value in OID_VALUES:
    cls = make_mib_instance(oid, value)
    export_list.append(cls(PARENT_OID, (oid[-1],), v2c.OctetString(value)))

mibBuilder.export_symbols('__MY_MIB', *export_list)

# Регистрируем обработчики SNMP команд:
# GetCommandResponder  — отвечает на snmpget  (запрос конкретного OID)
# NextCommandResponder — отвечает на snmpgetnext (следующий OID)
# BulkCommandResponder — отвечает на snmpbulkget (массовый запрос)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

print(f'SNMP Agent запущен на {AGENT_HOST}:{AGENT_PORT}')

# Сообщаем диспетчеру что есть активная задача (иначе он сразу завершится)
snmpEngine.transport_dispatcher.job_started(1)

try:
    # Запускаем основной цикл обработки входящих SNMP пакетов (блокирующий)
    snmpEngine.transport_dispatcher.run_dispatcher()
except KeyboardInterrupt:
    print('Агент остановлен')
    snmpEngine.transport_dispatcher.close_dispatcher()
