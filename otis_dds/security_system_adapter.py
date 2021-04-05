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
        allowedFloorsFront: []
        allowedFloorsRear: []

    @property
    def allowedFloorsFront(self):
        raise NotImplementedError # Returns a list of floors

    @property
    def allowedFloorsRear(self):
        raise NotImplementedError # Return a list of floors

    def getAccessInfo(self, credentialData, credentialSizeBits):
        raise NotImplementedError # Return a list of floors

    