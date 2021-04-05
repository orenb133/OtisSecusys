import otis_dds.communicator
import otis_dds.security_system_adapter
import secusys_acl.client

# Config
config = otis_dds.communicator.DdsCommunicator.Configuration()
config.heartbeatReceiveMcGroup = '234.46.30.7'
config.heartbeatReceivePort = 47307
config.heartbeatReceiveTimeout = 3.0

config.localIp = '192.168.1.242'

config.interactiveReceivePortDes = 45303
config.interactiveReceivePortDec = 46308
config.interactiveSendPortDes = 46303
config.interactiveSendPortDec = 45308
config.interactiveDuplicatesCacheSize = 5
config.interactiveSendRetryIntreval = 1.0
config.interactiveSendMaxRetries = 5

config.heartbeatSendMcGroup = '234.46.30.7'
config.heartbeatSendPort = 48307
config.heartbeatSendInterval = 1

config.decOperationMode = 3

# Logger
logger = logging.getLogger('DDS DdsCommunicator')
logger.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(ch)

# Security system integration
class SecuritySystemAdapterSecusys(otis_dds.security_system_adapter.SecuritySystemAdapterInterface):

    class AccessInfo(typing.NamedTuple):
       
        class DoorType(enum.IntEnum):
            Front = 0
            Rear = 1
     
        isValid : bool
        defaultFloor : int
        defaultDoorType : DoorType
        allowedFloorsFront: []
        allowedFloorsRear: []

    @property
    def allowedFloorsFront:
        return [-3,10]

    @property
    def allowedFloorsRear:
        return [-2,11]

    def getAccessInfo(credentialData, credentialSizeBits):
        return AccessInfo(True, 0, AccessInfo.DoorType.Front, [12,13], [14,15])

secusysAdapter = SecuritySystemAdapterSecusys()


ssDdsCommunicator = DdsCommunicator(logger, config, secusysAdapter)
ssDdsCommunicator.start()
