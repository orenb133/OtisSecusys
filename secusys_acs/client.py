import datetime
import zeep
import xmltodict
import collections
import hashlib
import typing
import dataclasses

#======================================================================================================================
class SecusysClient:

#-----------------------------------------------------------------------------------------------------------------------
    @dataclasses.dataclass
    class Configuration():

        userName       : str = ''
        password       : str = ''
        wsdl           : str = ''

#-----------------------------------------------------------------------------------------------------------------------
    class _SecusysClientValidCode(typing.NamedTuple):
        timeStamp   : int
        md5Hash     : int

#-----------------------------------------------------------------------------------------------------------------------
    class _SecusysClientParsedResponseHead(typing.NamedTuple):
        errorCode    : int
        errorMessage : str

#-----------------------------------------------------------------------------------------------------------------------
    class _SecusysClientParsedResponse(typing.NamedTuple):
        head  : object
        body  : object

#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, logger, configuration):
        """ C'tor
        Params:
            logger: Python logging interface
            configuration: DdsCommunicator configuration
            password: Secusys password
            wsdl: URL for Secusys WSDL
        """
        self.__logger = logger
        self.__configuration = configuration
        self.__client = None

#-----------------------------------------------------------------------------------------------------------------------
    def connect(self):
        """ Connect to Secusys API
        """
        self.__logger.info("Connecting to Secusys API: wsdl=%s", self.__configuration.wsdl)
        self.__client = zeep.Client(self.__configuration.wsdl)

#-----------------------------------------------------------------------------------------------------------------------
    def disconnect(self):
        """ Disconnect from Secusys API
        """
        self.__logger.info("Disconnecting from Secusys API")
        self.__client = None

#-----------------------------------------------------------------------------------------------------------------------
    def getPersonalIdByCardNo(self, cardNo):
        """ Get a personal ID by its card number
        Params:
            cardNo: Card number as string
        Return: Personal ID on success | None
        """
        validCode = self.__createValidCode()
        res = None

        try:
            self.__logger.debug("Requesting info for card: cardNo=%s", cardNo)

            rawResponse = self.__client.service.GetCardInfos(AppKey = self.__configuration.userName, 
                                                             TimeStamp = validCode.timeStamp, 
                                                             PersonnalID = 0,
                                                             CardNo = cardNo, 
                                                             ValidCode = validCode.md5Hash)

            response = self.__parseResponse('GetCardInfos', rawResponse)

            self.__logger.debug("Received response for card: cardNo=%s response=%s", cardNo, response)

            if response.head.errorCode == 0:
                items = response.body['Item']
            
                if not isinstance(items, list):
                    # Not a list and has a value otherwise we would have received an error from the server
                    res = int(items['PersonnalID'])
                else:
                    self.__logger.error("Ambiguity, expecting a single personnal ID: cardNo=%s response=%s", 
                                        cardNo, response)

            else:
                self.__logger.error("Received an error from API: cardNo=%s response=%s", cardNo, response)
        except:
            self.__logger.exception("Failed requesting info for card: cardNo=%s", cardNo)

        return res

#-----------------------------------------------------------------------------------------------------------------------
    def getPersonSecurityGroupsByPersonalId(self, personalId):
        """ Get a list of a person security groups by its personal ID
        Params:
            personalId: Personal ID
        Return: A list of security groups names on success | None
        """
        validCode = self.__createValidCode()
        res = None

        try:
            self.__logger.debug("Requesting info for card: cardNo=%s", cardNo)

            rawResponse = self.__client.service.GetPersonAccessSecurityGroups(AppKey = self.__configuration.userName, 
                                                             TimeStamp = validCode.timeStamp, 
                                                             PersonnalID = personalId,
                                                             ValidCode = validCode.md5Hash)

            response = self.__parseResponse('GetPersonAccessSecurityGroups', rawResponse)

            self.__logger.debug("Received response for personal ID: personalId=%s response=%s", personalId, response)

            if response.head.errorCode == 0:
                print (response)

            else:
                self.__logger.error("Received an error from API: personalId=%s response=%s", personalId, response)
        except:
            self.__logger.exception("Failed requesting security groups for personal ID: personalId=%s", personalId)

        return res

#-----------------------------------------------------------------------------------------------------------------------
    def __createValidCode(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

        return self._SecusysClientValidCode(timestamp, 
                                            hashlib.md5((timestamp+self.__configuration.password).encode('utf-8')).hexdigest())

#-----------------------------------------------------------------------------------------------------------------------
    def __parseResponse(self, methodName, rawResponse):
        response = xmltodict.parse(rawResponse)
        head = response['Integration'][methodName]['Head']
        body = response['Integration'][methodName]['Body']
        
        return self._SecusysClientParsedResponse(self._SecusysClientParsedResponseHead(int(head['ErrCode']), 
                                                head['ErrMsg']), body)
