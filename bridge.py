import otis_dds.communicator
import otis_dds.security_system_adapter
import secusys_acs.client
import logging
import configparser

#======================================================================================================================
class Bridge:

    __CONFIG_SECTION_DDS = 'DDS'
    __CONFIG_SECTION_ACS = 'ACS'

#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, logger, configFilePath):
        self.__logger = logger
        self.__configParser = configparser.ConfigParser()
        self.__ddsCommunicatorConfig = otis_dds.communicator.DdsCommunicator.Configuration()
        self.__secusysAcsConfig = secusys_acl.client.SecusysClient.Configuration()

        try:
            self.__configParser.read(configFilePath)
            self.__ddsCommunicatorConfig.heartbeatReceiveMcGroup = 
                self.__configParser.get(self.__CONFIG_SECTION_DDS, "heartbeatReceiveMcGroup")
            self.__ddsCommunicatorConfig.heartbeatReceivePort = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "heartbeatReceivePort")
            self.__ddsCommunicatorConfig.heartbeatReceiveTimeout = 
                self.__configParser.getfloat(self.__CONFIG_SECTION_DDS, "heartbeatReceiveTimeout")
            self.__ddsCommunicatorConfig.heartbeatSendMcGroup = 
                self.__configParser.get(self.__CONFIG_SECTION_DDS, "heartbeatSendMcGroup")
            self.__ddsCommunicatorConfig.heartbeatSendPort = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "heartbeatSendPort")
            self.__ddsCommunicatorConfig.heartbeatSendInterval = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "heartbeatSendInterval")

            self.__ddsCommunicatorConfig.interactiveReceivePortDes = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "interactiveReceivePortDes")
            self.__ddsCommunicatorConfig.interactiveReceivePortDec = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "interactiveReceivePortDec")
            self.__ddsCommunicatorConfig.interactiveSendPortDes = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "interactiveSendPortDes")
            self.__ddsCommunicatorConfig.interactiveSendPortDec = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "interactiveSendPortDec")
            self.__ddsCommunicatorConfig.interactiveDuplicatesCacheSize = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "interactiveDuplicatesCacheSize")
            self.__ddsCommunicatorConfig.interactiveSendRetryIntreval = 
                self.__configParser.getfloat(self.__CONFIG_SECTION_DDS, "heartbeatReceiveTimeout")
            self.__ddsCommunicatorConfig.interactiveSendMaxRetries = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "interactiveSendMaxRetries")

            self.__ddsCommunicatorConfig.localIp = 
                self.__configParser.get(self.__CONFIG_SECTION_DDS, "localIp")
            self.__ddsCommunicatorConfig.decOperationMode = 
                self.__configParser.getint(self.__CONFIG_SECTION_DDS, "decOperationMode")
        
        except Exception as e:
            self.__logger.exception("Failed parsing configuration file: configFilePath=%s", configFilePath)
            raise





# Config
config = otis_dds.communicator.DdsCommunicator.Configuration()


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

secusysClient = secusys_acl.client.SecusysClient(logger, 'administrator', 'secusys', 'http://10.0.0.88:7070/SecusysWeb/WebService/AccessWS.asmx?WSDL')
secusysClient.connect()
print (secusysClient.getPersonnalIdByCardNo("000012"))
print (secusysClient.getPersonnalIdByCardNo("00001234"))
secusysAdapter = SecuritySystemAdapterSecusys(logger, secusysClient)
ssDdsCommunicator = otis_dds.communicator.DdsCommunicator(logger, config, secusysAdapter)
ssDdsCommunicator.start()
