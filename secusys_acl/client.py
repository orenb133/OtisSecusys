import datetime
import zeep
import xmltodict
import collections
import hashlib
import typing

class SecusysClient:

    class _SecusysClientValidCode(typing.NamedTuple):
        timeStamp   : int
        md5Hash     : int

    class _SecusysClientParsedResponseHead(typing.NamedTuple):
        errorCode : int
        errorMessage : str

    class _SecusysClientParsedResponse(typing.NamedTuple):
        head  : object
        body  : object

    def __init__(self, logger, userName, password, wsdl):
        self.__userName = userName
        self.__password = password
        self.__wsdl = wsdl
        self.__logger = logge
        self.__client = None

    def connect(self):
        self.__logger.info("Connecting to Secusys API: wsdl=%s", self.__wsdl)
        self.__client = zeep.Client(self.__wsdl)

    def disconnect(self):
        self.__logger.info("Disconnecting from Secusys API")
        self.__client = None

    def getPersonnalIdByCardNo(self, cardNo):
        validCode = self.__createValidCode()
        res = None

        try:
            self.__logger.debug("Requesting info for card: cardNo=%s", cardNo)

            rawResponse = self.__client.service.GetCardInfos(AppKey = self.__userName, 
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
                    self.__logger.error("Ambiguity, expecting a single personnal ID: cardNo=%s response=%s", cardNo, response)

            else:
                self.__logger.error("Received an error from API: cardNo=%s response=%s", cardNo, response)
        except:
            self.__logger.exception("Failed requesting info for card: cardNo=%s", cardNo)

        return res

    def __createValidCode(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

        return _SecusysClientValidCode(timestamp, hashlib.md5((timestamp+self.__password).encode('utf-8')).hexdigest())

    def __parseResponse(self, methodName, rawResponse):
        res = None

        try:
            response = xmltodict.parse(rawResponse)
            head = response['Integration'][methodName]['Head']
            body = response['Integration'][methodName]['Body']
            res = _SecusysClientParsedResponse(_SecusysClientParsedResponseHead(int(head['ErrCode']), head['ErrMsg']), body)

        except:
            self.__logger.exception("Failed to parse response")
            res = None
            raise

        return res

if __name__ == "__main__":
    # Some testing around
    secureSysClient = SecusysClient('administrator', 'secusys', 'http://10.0.0.88:7070/SecusysWeb/WebService/AccessWS.asmx?WSDL')
    secureSysClient.connect()
    print (secureSysClient.getPersonnalIdByCardNo("000012"))
    print (secureSysClient.getPersonnalIdByCardNo("00001234"))
    secureSysClient.disconnect()