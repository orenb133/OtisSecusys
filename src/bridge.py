import otis_dds.communicator
import otis_dds.security_system_adapter
import secusys_acs.client 
import logging
import configparser
import ipaddress

#======================================================================================================================
class Bridge:

    __CONFIG_SECTION_DDS = 'DDS'
    __CONFIG_SECTION_ACS = 'ACS'
    __CONFIG_SECTION_LOGGER = 'Logger'

#-----------------------------------------------------------------------------------------------------------------------
    class _SecuritySystemAdapterSecusys(otis_dds.security_system_adapter.SecuritySystemAdapterInterface):

        __CONFIG_SECTION_ALLOWED = 'ALLOWED'
        __CONFIG_KEY_FLOORS = 'floors'
        __SECURITY_GROUP_PREFIX = "DDS."

        def __init__(self, logger, secusysClient, groupsFilePath):
            """ C'tor
            Params:
                logger: Python logging interface
                secusysClient: Secusys client to addapt to
                groupsFilePath: Groups mapping file path
            """

            self.__logger = logger
            self.__secusysClient = secusysClient
            self.__groups = {}
            
            configParser = configparser.ConfigParser()

            try:
                configParser.read(groupsFilePath)

                # Get allowed floors and remove this section
                allowedPath = (self.__CONFIG_SECTION_ALLOWED, self.__CONFIG_KEY_FLOORS)
                self.__allowedFloors = self.__parseFloorList(configParser.get(*allowedPath), "%s.%s" % allowedPath)
                configParser.remove_section(self.__CONFIG_SECTION_ALLOWED)

                # Get the rest of the groups
                for section in configParser.sections():
                    for key, val in configParser.items(section):
                        if key == self.__CONFIG_KEY_FLOORS:
                            floorsList = self.__parseFloorList(val, "%s.%s" % (section, key))

                            # Verify there is no overlap between allowed and other groups floors
                            for i in self.__allowedFloors:
                             
                                if i in floorsList:
                                    raise ValueError("%s.%s list must not overlap with %s.%s. Found %s" % 
                                                     (section, key, *allowedPath, i))
                           
                            self.__groups[section] = floorsList

            except Exception as e:
                self.__logger.exception("Failed parsing groups file: groupsFilePath=%s", groupsFilePath)
                raise
           
#----------------------------------------------------------------------------------------------------------------------- 
        @property
        def allowedFloorsFront(self):
            return self.__allowedFloors 

#----------------------------------------------------------------------------------------------------------------------- 
        @property
        def allowedFloorsRear(self):
            # Note we don't support rear 
            return []

#----------------------------------------------------------------------------------------------------------------------- 
        def getAccessInfo(self,credentialData, credentialSizeBits):

            isValid = False
            personalId = self.__secusysClient.getPersonalIdByCardNo(int.from_bytes(credentialData, 'big'))
            floors = []
            
            if personalId:
                isValid = True
                securityGroups = self.__secusysClient.getPersonSecurityGroupsByPersonalId(personalId)

                for group in securityGroups:
                    if group.startswith(self.__SECURITY_GROUP_PREFIX):
                        floors.extend(self.__groups.get(group, []))

            return otis_dds.security_system_adapter.SecuritySystemAdapterInterface.AccessInfo(
                isValid, 
                0, 
                otis_dds.security_system_adapter.SecuritySystemAdapterInterface.AccessInfo.DoorType.Front, 
                floors, 
                []) # Not supporting rear

#-----------------------------------------------------------------------------------------------------------------------  
        def __parseFloorList(self, rawFloorList, fieldName):
            res = []
           
            if rawFloorList:

                for item in rawFloorList.replace(' ','').split(','):
                    
                    if ':' in item:
                        splitRange = [int(x) for x in item.split(':')]

                        if len(splitRange) == 2:
                            res.extend(range(splitRange[0], splitRange[1]+1))
                    
                        else:
                            raise ValueError("%s ranges must be in a form of Start:End. Got '%s'" % (fieldName, item))
                    
                    else:
                        res.append(int(item))

            for i in res:
                if i < self.FLOOR_NUMBER_MIN or i > self.FLOOR_NUMBER_MAX:
                  raise ValueError("%s numbers must be between %s to %s. Got '%s'" % 
                                    (fieldName, self.FLOOR_NUMBER_MIN, self.FLOOR_NUMBER_MAX, i))
                    
            return res

#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, logger, configFilePath):
        self.__logger = logger
        self.__isRunning = False

        configParser = configparser.ConfigParser()
        ddsCommunicatorConfig = otis_dds.communicator.DdsCommunicator.Configuration()
        secusysAcsConfig = secusys_acs.client.SecusysClient.Configuration()

        try:
            configParser.read(configFilePath)

            # Logger Config section
            configSection = self.__CONFIG_SECTION_LOGGER

            val = rawLogLevel = configParser.get(configSection, "level")

            if val not in ['E,W,I,D']:
                raise ValueError("%s.level must be one of E, W, I, D. Got '%s'" % (configSection, val))

            # DDS Config section
            configSection = self.__CONFIG_SECTION_DDS

            val = ddsCommunicatorConfig.heartbeatReceiveMcGroup = configParser.get(configSection, "heartbeatReceiveMcGroup")

            try:
                ipaddress.ip_address(val)
            except:
                raise ValueError("%s.heartbeatReceiveMcGroup must be a valid IP address. Got '%s'" % (configSection, val))

            val = ddsCommunicatorConfig.heartbeatReceivePort = configParser.getint(configSection, "heartbeatReceivePort")

            if val < 1 or val > 65535:
                raise ValueError("%s.heartbeatReceivePort must be a valid UDP port. Got '%s'" % (configSection, val))

            val = ddsCommunicatorConfig.heartbeatReceiveTimeout = configParser.getfloat(configSection, "heartbeatReceiveTimeout")

            if val < 1.0:
                raise ValueError("%s.heartbeatReceiveTimeout must be a at least 1.0. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.heartbeatSendMcGroup = configParser.get(configSection, "heartbeatSendMcGroup")

            try:
                ipaddress.ip_address(val)
            except:
                raise ValueError("%s.heartbeatSendMcGroup must be a valid IP address. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.heartbeatSendPort = configParser.getint(configSection, "heartbeatSendPort")

            if val < 1 or val > 65535:
                raise ValueError("%s.heartbeatSendPort must be a valid UDP port. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.heartbeatSendInterval = configParser.getfloat(configSection, "heartbeatSendInterval")

            if val < 1.0:
                raise ValueError("%s.heartbeatSendInterval must be a at least 1.0. Got '%s'" % (configSection, val))

            val = ddsCommunicatorConfig.interactiveReceivePortDes = configParser.getint(configSection, "interactiveReceivePortDes")

            if val < 1 or val > 65535:
                raise ValueError("%s.interactiveReceivePortDes must be a valid UDP port. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.interactiveReceivePortDec = configParser.getint(configSection, "interactiveReceivePortDec")

            if val < 1 or val > 65535:
                raise ValueError("%s.interactiveReceivePortDec must be a valid UDP port. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.interactiveSendPortDes = configParser.getint(configSection, "interactiveSendPortDes")

            if val < 1 or val > 65535:
                raise ValueError("%s.interactiveSendPortDes must be a valid UDP port. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.interactiveSendPortDec = configParser.getint(configSection, "interactiveSendPortDec")

            if val < 1 or val > 65535:
                raise ValueError("%s.interactiveSendPortDec must be a valid UDP port. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.interactiveDuplicatesCacheSize = configParser.getint(configSection, "interactiveDuplicatesCacheSize")

            if val < 1 or val > 100:
                raise ValueError("%s.interactiveDuplicatesCacheSize must be between 1 and 100. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.interactiveSendRetryIntreval = configParser.getfloat(configSection, "interactiveSendRetryIntreval")

            if val < 1.0:
                raise ValueError("%s.interactiveSendRetryIntreval must be a at least 1.0. Got '%s'" % (configSection, val))
            
            val = ddsCommunicatorConfig.interactiveSendMaxRetries = configParser.getint(configSection, "interactiveSendMaxRetries")

            if val < 1:
                raise ValueError("%s.interactiveSendMaxRetries must be a at least 1. Got '%s'" % (configSection, val))

            val = ddsCommunicatorConfig.localIp = configParser.get(configSection, "localIp")

            try:
                ipaddress.ip_address(val)
            except:
                raise ValueError("%s.localIp must be a valid IP address. Got '%s'" % (configSection, val))

            val = ddsCommunicatorConfig.decOperationMode = configParser.getint(configSection, "decOperationMode")

            if val < 1 or val > 4:
                raise ValueError("%s.decOperationMode must be between 1 to 4. Got '%s'" % (configSection, val))

            # ACS Config section
            configSection = self.__CONFIG_SECTION_ACS

            val = secusysAcsConfig.userName = configParser.get(configSection, "userName")

            if not val:
                raise ValueError("%s.userName must be provided. Got '%s'" % (configSection, val))

            val = secusysAcsConfig.password = configParser.get(configSection, "password")

            if not val:
                raise ValueError("%s.password must be provided. Got '%s'" % (configSection, val))

            val = secusysAcsConfig.wsdl = configParser.get(configSection, "wsdl")

            if not val:
                raise ValueError("%s.wsdl must be provided. Got '%s'" % (configSection, val))

            val = groupsFilePath = configParser.get(configSection, "groupsFilePath")

            if not val:
                raise ValueError("%s.groupsFilePath must be provided. Got '%s'" % (configSection, val))
        
        except Exception as e:
            self.__logger.exception("Failed parsing configuration file: configFilePath=%s", configFilePath)
            raise

        self.__configureLogLevel(rawLogLevel)
        self.__secusysAcsClient = secusys_acs.client.SecusysClient(logger, secusysAcsConfig)
        ssAdapter = self._SecuritySystemAdapterSecusys(logger, self.__secusysAcsClient, groupsFilePath)
        self.__ddsCommunicator = otis_dds.communicator.DdsCommunicator(logger, ddsCommunicatorConfig, ssAdapter)

#-----------------------------------------------------------------------------------------------------------------------
    def start(self):
        """ Start the bridge
        """
        if not self.__isRunning :
            self.__logger.info("Starting Bridge")
            self.__secusysAcsClient.connect()
            self.__ddsCommunicator.start()
            self.__isRunning = True

        else:
            self.__logger.warning("Trying to start an already running Bridge")

#-----------------------------------------------------------------------------------------------------------------------    
    def stop(self):
        """ Stop the bridge
        """
        if self.__isRunning :
            self.__logger.info("Stopping Bridge")
            self.__ddsCommunicator.stop()
            self.__secusysAcsClient.disconnect()
            self.__isRunning = False

        else:
            self.__logger.warning("Trying to start an already running Bridge")

#-----------------------------------------------------------------------------------------------------------------------    
    def __configureLogLevel(self, rawLogLevel):
        level = None
        
        if rawLogLevel == 'E':
            level = logging.ERROR
        elif rawLogLevel == 'W':
            level = logging.WARNING
        elif rawLogLevel == 'I':
            level = logging.INFO
        elif rawLogLevel == 'D':
            level = logging.DEBUG
        else:
            raise ValueError("Unknown log level received: rawLogLevel=%s" % rawLogLevel)

        self.__logger.setLevel(level)