import typing
import enum

#======================================================================================================================
class SecuritySystemAdapterInterface:

    FLOOR_NUMBER_MIN = -127
    FLOOR_NUMBER_MAX = 127

    class AccessInfo(typing.NamedTuple):
       
        class DoorType(enum.IntEnum):
            Front = 0
            Rear = 1
     
        isValid : bool
        defaultFloor : int
        defaultDoorType : DoorType
        allowedFloorsFront: list
        allowedFloorsRear: list

    @property
    def allowedFloorsFront(self):
        """ List of allowed floors from the front door
        """
        raise NotImplementedError 

    @property
    def allowedFloorsRear(self):
        """ List of allowed floors from the rear door
        """
        raise NotImplementedError 

    def getAccessInfo(self, credentialData, credentialSizeBits):
        """ Get access info for given credentials data
        Params:
            credentialData: Credential data buffer
            credentialSizeBits Credential data size in bits
        """
        raise NotImplementedError # Return a list of floors

    