"""
SNMP агент на базе pysnmp 7.x.

Регистрирует кастомные OID в поддереве 1.3.6.1.4.1.99999 с доступом read-write.
Поддерживает GET, SET и WALK запросы по SNMPv1 и SNMPv2c с community 'public'.
Слушает UDP порт 1161.
"""

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.rfc1902 import OctetString

snmpEngine = engine.SnmpEngine()

config.add_transport(
    snmpEngine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().open_server_mode(('0.0.0.0', 1161))
)

config.add_v1_system(snmpEngine, 'my-area', 'public')

for security_model in (1, 2):
    config.add_vacm_user(
        snmpEngine, security_model, 'my-area', 'noAuthNoPriv',
        readSubTree=(1, 3, 6, 1, 4, 1, 99999),
        writeSubTree=(1, 3, 6, 1, 4, 1, 99999)
    )

snmpContext = context.SnmpContext(snmpEngine)
mibBuilder = snmpContext.get_mib_instrum('').get_mib_builder()

MibScalar, MibScalarInstance = mibBuilder.import_symbols(
    'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
)

VARIABLES = [
    ((1, 3, 6, 1, 4, 1, 99999, 1), "Hello from Device A!"),
    ((1, 3, 6, 1, 4, 1, 99999, 2), "50"),    # CPU Load
    ((1, 3, 6, 1, 4, 1, 99999, 3), "36.6"),  # Temperature
]

stored_values = {oid: OctetString(val) for oid, val in VARIABLES}


def make_instance_class(oid):
    class _Instance(MibScalarInstance):
        _oid = oid

        def getValue(self, name, **ctx):
            return stored_values[self._oid].clone()

        def setValue(self, value, name, **ctx):
            stored_values[self._oid] = value
            print(f"[SET] {'.'.join(map(str, self._oid))}.0 = {value.prettyPrint()}")
            return value

    return _Instance


export_kwargs = {}
for i, (oid, _) in enumerate(VARIABLES, start=1):
    InstanceClass = make_instance_class(oid)
    scalar   = MibScalar(oid, OctetString()).setMaxAccess('read-write')
    instance = InstanceClass(oid, (0,), OctetString())
    # Имена должны быть уникальными и сортироваться в порядке OID
    export_kwargs[f'scalar_{i:03d}']      = scalar
    export_kwargs[f'scalar_{i:03d}_inst'] = instance

mibBuilder.export_symbols('__MY_MIB', **export_kwargs)

cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

print("SNMP агент запущен на UDP:1161")
for oid, val in VARIABLES:
    print(f"  OID: {'.'.join(map(str, oid))}.0 = {val!r}")

snmpEngine.transport_dispatcher.job_started(1)
try:
    snmpEngine.transport_dispatcher.run_dispatcher()
except KeyboardInterrupt:
    pass
finally:
    snmpEngine.transport_dispatcher.close_dispatcher()
