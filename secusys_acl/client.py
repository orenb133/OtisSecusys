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

    def __init__(self, userName, password, wsdl):
        self._userName = userName
        self._password = password
        self._wsdl = wsdl
        self._client = None

    def connect(self):
        self._client = zeep.Client(self._wsdl)

    def disconnect(self):
        self._client = None

    def getPersonnalIdByCardNo(self, cardNo):
        validCode = self._createValidCode()
        res = None

        try:
            rawResponse = self._client.service.GetCardInfos(AppKey = self._userName, 
                                                             TimeStamp = validCode.timeStamp, 
                                                             PersonnalID = 0,
                                                             CardNo = cardNo, 
                                                             ValidCode = validCode.md5Hash)

            response = self._parseResponse('GetCardInfos', rawResponse)

            if response.head.errorCode == 0:
                items = response.body['Item']
            
                if not isinstance(items, list):
                    # Not a list and has a value otherwise we would have received an error from the server
                    res = int(items['PersonnalID'])
                else:
                    # Ambiguity, expecting a single personnal ID
                    print ("Ambiguity")
                    print (items)
                    #TODO Log
            else:
                print (response.head)
                #TODO Log
        except:
            #TODO: Log
            raise

        return res

    def _createValidCode(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

        return _SecusysClientValidCode(timestamp, hashlib.md5((timestamp+self._password).encode('utf-8')).hexdigest())

    def _parseResponse(self, methodName, rawResponse):
        res = None

        try:
            response = xmltodict.parse(rawResponse)
            head = response['Integration'][methodName]['Head']
            body = response['Integration'][methodName]['Body']
            res = _SecusysClientParsedResponse(_SecusysClientParsedResponseHead(int(head['ErrCode']), head['ErrMsg']), body)

        except:
            #TODO Log
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