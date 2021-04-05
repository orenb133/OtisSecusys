import otis_dds.communicator
import otis_dds.security_system_adapter
import secusys_acl.client
import logging

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
logger = logging.getLogger('Test Logger')
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

    def __init__(self, logger, secusysClient):
        self.__logger = logger
        self.__secusysClient = secusysClient

    @property
    def allowedFloorsFront(self):
        return [-3,10]

    @property
    def allowedFloorsRear(self):
        return [-2,11]

    def getAccessInfo(self,credentialData, credentialSizeBits):
        return otis_dds.security_system_adapter.SecuritySystemAdapterInterface.AccessInfo(
            True, 
            0, 
            otis_dds.security_system_adapter.SecuritySystemAdapterInterface.AccessInfo.DoorType.Front, 
            [12,13], 
            [14,15])

secusysClient = secusys_acl.client.SecusysClient(logger, 'administrator', 'secusys', 'http://192.168.201.3:7070/SecusysWeb/WebService/AccessWS.asmx?WSDL')
secusysClient.connect()
secusysAdapter = SecuritySystemAdapterSecusys(logger, secusysClient)
ssDdsCommunicator = otis_dds.communicator.DdsCommunicator(logger, config, secusysAdapter)
ssDdsCommunicator.start()
