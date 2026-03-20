"""
SNMP агент на базе pysnmp 7.x.

Регистрирует кастомный OID 1.3.6.1.4.1.99999.1.0 с доступом read-write.
Поддерживает GET и SET запросы по SNMPv1 и SNMPv2c с community 'public'.
Слушает UDP порт 1161.
"""

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.rfc1902 import OctetString

# Инициализация SNMP движка
snmpEngine = engine.SnmpEngine()

# Настройка транспорта: UDP, все интерфейсы, порт 1161
config.add_transport(
    snmpEngine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().open_server_mode(('0.0.0.0', 1161))
)

# Регистрация community 'public' с именем безопасности 'my-area'
config.add_v1_system(snmpEngine, 'my-area', 'public')

# Настройка VACM: разрешить чтение и запись поддерева 1.3.6.1.4.1.99999
# для SNMPv1 (securityModel=1) и SNMPv2c (securityModel=2)
config.add_vacm_user(snmpEngine, 1, 'my-area', 'noAuthNoPriv',
                     readSubTree=(1, 3, 6, 1, 4, 1, 99999),
                     writeSubTree=(1, 3, 6, 1, 4, 1, 99999))
config.add_vacm_user(snmpEngine, 2, 'my-area', 'noAuthNoPriv',
                     readSubTree=(1, 3, 6, 1, 4, 1, 99999),
                     writeSubTree=(1, 3, 6, 1, 4, 1, 99999))

# Создание SNMP контекста и получение MIB builder'а
snmpContext = context.SnmpContext(snmpEngine)
mibBuilder = snmpContext.get_mib_instrum('').get_mib_builder()

# Импорт базовых классов MIB из SNMPv2-SMI
MibScalar, MibScalarInstance = mibBuilder.import_symbols(
    'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
)

# OID кастомной переменной (без суффикса .0)
CUSTOM_OID = (1, 3, 6, 1, 4, 1, 99999, 1)

# Хранилище текущего значения переменной
stored_value = [OctetString("Hello from Device A!")]


class WritableMibScalarInstance(MibScalarInstance):
    """Экземпляр MIB переменной с поддержкой чтения и записи."""

    def getValue(self, name, **context):
        """Возвращает текущее значение переменной."""
        return stored_value[0].clone()

    def setValue(self, value, name, **context):
        """Сохраняет новое значение переменной при SET запросе."""
        stored_value[0] = value
        print(f"[SET] Получено: {value.prettyPrint()}")
        return value


# Создание объекта MibScalar с доступом read-write
customScalar = MibScalar(CUSTOM_OID, OctetString()).setMaxAccess('read-write')

# Создание экземпляра переменной (суффикс (0,) соответствует .0 в OID)
customInstance = WritableMibScalarInstance(CUSTOM_OID, (0,), OctetString("Hello from Device A!"))

# Регистрация объектов в MIB дереве:
# customInstance -> customScalar -> mibTree (iso)
(mibTree,) = mibBuilder.import_symbols('SNMPv2-SMI', 'iso')
customScalar.registerSubtrees(customInstance)
mibTree.registerSubtrees(customScalar)

# Регистрация обработчиков GET и SET команд
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)

print("SNMP агент запущен на UDP:1161")
print(f"OID: {'.'.join(map(str, CUSTOM_OID))}.0")

# Запуск диспетчера транспорта (блокирующий цикл)
snmpEngine.transport_dispatcher.job_started(1)
try:
    snmpEngine.transport_dispatcher.run_dispatcher()
except KeyboardInterrupt:
    pass
finally:
    snmpEngine.transport_dispatcher.close_dispatcher()
