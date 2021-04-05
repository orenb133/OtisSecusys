import typing
import enum

#======================================================================================================================
class SecuritySystemAdapterInterface:

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

    def getAccessInfo(self, credentialData, credentialSizeBits):
        """ Get access info for given credentials data
        Params:
            credentialData: 
        raise NotImplementedError # Return a list of floors

    