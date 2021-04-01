import struct
import time
import enum
import typing

#======================================================================================================================
class _InteractiveReactor:

        class DenChannelType(enum.IntEnum):
            Des = 0
            Dec = 1

        @dataclasses.dataclass
        class _UnAackedSentPacket():

            packet        : object
            peerTuple     : ()
            lastSendTime  : int
            denChannel    : _InteractiveReactor.DenChannelType
            retryCout     : int = 0

#----------------------------------------------------------------------------------------------------------------------
        def __init__(self, logger, desIp, configuration, desSocket, decsocket, packetClasses):
            self.__logger = logger
            self.__lastHeartbeatTime = 0
            self.__isDesOnline  = False
            self.__sequenceNumber = 0
            self.__onlineDecIds = []
            self.__duplicatesCache = collections.OrderedDict()
            self.__unAckedBacklog = collections.OrderedDict()
            self.__configuration = configuration
            self.__denSockets = [None] * 2
            self.__denSockets[self.DenChannelType.Des] = desSocket
            self.__denSockets[self.DenChannelType.Dec] = decSocket
            self.__packetClasses = packetClasses

#----------------------------------------------------------------------------------------------------------------------
        @property
        def isDesOnline(self):
            return self.__isDesOnline

#----------------------------------------------------------------------------------------------------------------------
        @property
        def sequenceNumber(self):
            return self.__sequenceNumber

#----------------------------------------------------------------------------------------------------------------------
        @property
        def desIp(self):
            return self.__desIp

#----------------------------------------------------------------------------------------------------------------------
        @property
        def onlineDecIds(self):
            return self.__onlineDecIds

#----------------------------------------------------------------------------------------------------------------------
        @onlineDecIds.setter
        def onlineDecIds(self, onlineDecIds):
            self.__onlineDecIds = onlineDecIds

#----------------------------------------------------------------------------------------------------------------------
        @property
        def _lastHeartbeatTime(self):
            return self.__lastHeartbeatTime

#----------------------------------------------------------------------------------------------------------------------
        @_lastHeartbeatTime.setter
        def _lastHeartbeatTime(self, heartbeatTime):
            self.__lastHeartbeatTime = heartbeatTime

#----------------------------------------------------------------------------------------------------------------------
        def _setDesOnline(self, isDesOnline):
            self.__isDesOnline = isDesOnline 

#----------------------------------------------------------------------------------------------------------------------
        def sendPacket(self, packet, peerTuple, denChannel):
            """ Send a packet
            Params:
                packet: Packet to send
                peerTuple: (Peer IP, Peer Port)
                denChannel: Den channel to send packet through
            """
            
            self.__denSockets[denChannel].sendto(packet.packed(), peerTuple)
            self.__unAckedBacklog[packet[0]] = self.unAckedSentPacket(packet, peerTuple, time.monotonic(), denChannel)
            self.__sequenceNumber = self.__sequenceNumber + 1

#----------------------------------------------------------------------------------------------------------------------
        def ackPacket(self, packetId):
            """ Ack a packet sent to the DEN
            Params:
                packetId: Packet ID to ack
            """
            if packetId in self.__unAckedBacklog:
                del self.__unAckedBacklog[packetId]

#----------------------------------------------------------------------------------------------------------------------
        def _handlePacket(self, rawPacket, packetId, peerTuple, denSocket):

            # Filter duplicates
            if packetId in self.__duplicatesCache:

                print ("Received duplicate interactive packet: packetId=%s peerTuple=%s" % (packetId, peerTuple))
                ackType = packets._PacketInteractiveAck.AckType.Duplicate
                
            else:
                # Cache packet id
                self.__duplicatesCache[packetId] = None

                # Maintain cache size
                if len(self.__duplicatesCache) > self.__configuration.interactiveDuplicatesCacheSize:
                    self.__duplicatesCache.popitem(False)

                # Get the appropriate packet class if supported
                packetClass = self.__packetClasses.get(packetType, None)

                if packetClass is None:
                    print ("Received unsupported interactive packet: packetRaw=%s peerTuple=%s" % 
                          (packetRaw, peerTuple))
                       
                    ackType = packets._PacketInteractiveAck.AckType.Unsupported

                else:
                    # We have a packet, let's create and react with it
                    packet = packetClass.s_createFromRaw(packetRaw, packetId)
                    print ("Received interactive packet: packet=%s peerTuple=%s" % (packet, peerTuple))
                    
                    wasReactionSuccesful = False

                    try:
                        wasReactionSuccesful = packet.react(self, 
                                                            self.__configuration, 
                                                            self.__securitySystemInterface)

                    except Exception as e:
                        print ("Failed reacting to packet: packet=%s peerIp=%s exception=%s" % (packet, peerIp, e))
                  
                    if wasReactionSuccesful:
                        ackType = packets._PacketInteractiveAck.AckType.Acceptable
                     
                    else:
                        ackType = packets._PacketInteractiveAck.AckType.Unacceptable

            ackPacket = packets._PacketInteractiveAck(packetId, ackType)

            try:
                print ("Sending ack packet to peer: packet=%s peerTuple=%s" % (ackPacket, peerTuple))
               
                denSocket.sendto(ackPacket.packed(), peerTuple)
          
            except Exception as e:
                print ("Failed sending ack packet to peer: packet=%s peerIp=%s exception=%s" % (ackPacket, peerIp, e))

#----------------------------------------------------------------------------------------------------------------------
        def _handleUnAckedPackets(self):
            now = time.monotonic()

            # Iterate maximum to backlog size
            for _ in range(len(self.__unAckedBacklog)):

                # Get backlog item
                packetId, unAckedSentPacket = self.__unAckedBacklog.popitem(False)

                # Time to resend the packet
                if now - unAckedSentPacket.lastSendTime > self.__configuration.interactiveSendRetryIntreval:
                
                    try:
                        print ("Sending un-acked sent packet: packet=%s peerTuple=%s" % 
                        (unAckedSentPacket.packet, unAckedSentPacket.peerTuple))

                        self.__denSockets[unAckedSentPacket.denChannel].sendto(unAckedSentPacket.packet.packed(), 
                                                                               unAckedSentPacket.peerTuple)
                    except Exception as e:
                        print ("Failed sending unacked backloged packet: unAckedSentPacket=%s exception=%s" % 
                        (unAckedSentPacket, e))

                    # Update backlog item
                    unAckedSentPacket.lastSendTime = now
                    unAckedSentPacket.retryCout = unAckedSentPacket.retryCout + 1

                    # If we haven't reached the limit for packet resend push it back to the backlog
                    if unAckedSentPacket.retryCout < self.__configuration.interactiveSendMaxRetries:
                        self.__unAckedBacklog[packetId] = unAckedSentPacket
                else:
                    # Pusing back to front and breaking as items are sorted by time within the backlog
                    self.__unAckedBacklog[packetId] = unackBacklogItem
                    self.__unAckedBacklog.move_to_end(packetId, last = False)
                    break

#======================================================================================================================
class _PacketBase(object):

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        """ Pack this packet to a raw binary represintation of the packet (bytes)  
        Returns: 
            Bytes buffer which conrains the binary representation of the packet
        """
        raise NotImplementedError

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket):
        """ Static method which create an instance of the derived class from a raw packet
        Params:
            rawPacket: bytes buffer containing the binay representation of the packet   
        Returns: 
            Instance of the appropriate implementing class
        """
        raise NotImplementedError

#----------------------------------------------------------------------------------------------------------------------
    def _s_unpackBitList(bytesBuffer):
        """ Unpack bytes containing per bit data to a list of 0s and 1s
        Params:
            bytesBuffer: buffer of bytes
        Returns:
            A list of 0s and 1s according to the input per bit data
        """
        return [bytesBuffer[y] >> i & 1 for y in range(0, len(bytesBuffer)) for i in range(8)]

#----------------------------------------------------------------------------------------------------------------------
    def _s_packBitList(bitList):
        """ Pack a list of bits (0s and 1s) to a buffer of bytes 
        Params:
            bitList: List of 0s and 1s
        Returns:
            A bytes buffer containing the list in the bits packet into bytes
        """
        return bytes([int("".join(map(str, reversed(bitList[i:i+8]))), 2) for i in range(0, len(bitList), 8)])


#======================================================================================================================
class _PacketHeartbeat(typing.NamedTuple, _PacketBase):    
    TYPE = 0x01

    class SourceType(enum.IntEnum):
        DES = 0x01
        DER = 0x02
        SS  = 0x03

    source : SourceType
    icdMajorSupported  : int # B (uint8)
    icdMinorSupported  : int # B (uint8)
    icdMajorNegotiable : int # B (uint8)
    icdMinorNegotiable : int # B (uint8)

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket):
        unpacked = struct.unpack_from('BBBBB', rawPacket, 2)

        return _PacketHeartbeat(_PacketHeartbeat.SourceType(unpacked[0]), *unpacked[1:])

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('HBBBBB', self.TYPE, *self)


#======================================================================================================================
class _PacketInteractiveBase(_PacketBase):

#----------------------------------------------------------------------------------------------------------------------
    def react(self, ddsContext, configuration, securitySystemInterface):
        """ React upon receiving this packet
        Params:
            desContext - Context of the relevant DDS
            configuration - System configuration structure
            securitySystemInterface - Security system interface for interacting with security system
        Returns: 
            True iff reaction was succesfull 
        """
        raise NotImplementedError

#======================================================================================================================
class _PacketInteractiveAck(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x01

    class AckType(enum.IntEnum):
        Unacceptable = 0x0
        Acceptable   = 0x1
        Duplicate    = 0x2
        Unsupported  = 0x3

    packetId   : int     #I (uint32)
    ackType    : AckType #I (uint32)

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        unpacked = struct.unpack_from('I', rawPacket, 6)

        return _PacketInteractiveAck(packetId, *unpacked)

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('IHI', self.packetId, self.TYPE, int(self.ackType))

#----------------------------------------------------------------------------------------------------------------------
    def react(self, ddsContext, configuration, securitySystemInterface):
        print ("Received ACK: packet=%s decIp=%s" % (self))
        ddsContext.ackPacket(self.packetId)

#======================================================================================================================
class _PacketInteractiveDecOnlineStatus(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x17

    packetId          : int  # I   (uint32)
    decSubnetId       : int  # B   (uint8)
    onlineDecMap      : list # 32s (32 * uint8)

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        decSubnetId, onlineDecMap = struct.unpack_from('B32s', rawPacket, 6)

        return _PacketInteractiveDecOnlineStatus(packetId, decSubnetId, _PacketBase._s_unpackBitList(onlineDecMap))

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('IHB32s', self.packetId, self.TYPE, self.decSubnetId, _PacketBase._s_packBitList(self.onlineDecMap))

#----------------------------------------------------------------------------------------------------------------------
    def react(self, ddsContext, configuration, securitySystemInterface):

        for i in range(len(self.onlineDecMap)):
            if self.onlineDecMap[i] == 1:
                decIp = "%s.%s.%s" % ('.'.join(ddsContext.desIp.split('.')[0:2]), self.decSubnetId, i)
                packet = _PacketInteractiveDecSecurityOperationModeV2(ddsContext.sequenceNumber, 
                                                                    [0] * 7, # Not using features
                                                                    configuration.decOperationMode, 
                                                                    [0] * 256, # No allowed floors
                                                                    [0] * 256,
                                                                    0)
                print ("Sending Packet to DEC: packet=%s decIp=%s" % (packet, decIp))
                ddsContext.sendPacket(packet, decIp, configuration.interactiveSendPortDec)

        return True

#======================================================================================================================
class _PacketInteractiveDecSecurityOperationModeV2(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x33

    packetId              : int                                       # I   (uint32)
    featuresMap           : list                                      # 1s  (uint8)
    mode                  : int                                       # B   (uint8)
    allowedFloorsFrontMap : list                                      # 32s (32 * uint8)
    allowedFloorsRearMap  : list                                      # 32s (32 * uint8)
    reserved              : int                                       # B   (uint8)

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        featuresMap, mode, allowedFloorsFrontMap, allowedFloorsRearMap, reserved = struct.unpack_from('1sB32s32sB', 
                                                                                                        rawPacket, 
                                                                                                        6)
        return _PacketInteractiveDecSecurityOperationModeV2(packetId,
                                                    _PacketBase._s_unpackBitList(featuresMap), 
                                                    mode, 
                                                    _PacketBase._s_unpackBitList(allowedFloorsFrontMap), 
                                                    _PacketBase._s_unpackBitList(allowedFloorsRearMap), 
                                                    reserved)

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('IH1sB32s32sB', 
                        self.packetId, 
                        self.TYPE, 
                        _PacketBase._s_packBitList(self.featuresMap), 
                        int(self.mode),
                        _PacketBase._s_packBitList(self.allowedFloorsFrontMap), 
                        _PacketBase._s_packBitList(self.allowedFloorsRearMap), 
                        self.reserved)


#======================================================================================================================
class _PacketInteractiveDecSecurityAutorizedDefaultFloorV2(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x34

    valid                    : bool                                                   # B   (uint8)
    credentialNumber         : bytes                                                  # 16s (16 * uint8)
    mode                     : int                                                    # B   (uint8)
    featuresMap              : list                                                   # 1s  (uint8)
    reserved1                : int                                                    # B   (uint8)
    authorizedFloorsFrontMap : list                                                   # 32s (32 * uint8)
    authorizedFloorsRearMap  : list                                                   # 32s (32 * uint8)
    defaultFloor             : int                                                    # B   (int8)
    defaultDoor              : int                                                    # B   (uint8)
    dateTime                 : int                                                    # I   (uint32)
    localTimezone            : int                                                    # I   (uint32)
    readerLocation           : int                                                    # I   (uint32)
    reserved2                : bytes                                                  # 3s  (3 * uint8)

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        (valid, credentialNumber, mode, featuresMap, reserved1, authorizedFloorsFrontMap, authorizedFloorsRearMap, 
        defaultFloor, defaultDoor, dateTime, localTimezone, readerLocation, 
        reserved2) = struct.unpack_from('B16sB1sB32s32sBBIII3s', rawPacket, 6)

        return _PacketInteractiveDecSecurityAutorizedDefaultFloorV2(packetId, 
                                                            self.TYPE,
                                                            bool(valid),
                                                            credentialNumber,
                                                            mode,
                                                            _PacketBase._s_unpackBitList(featuresMap),
                                                            reserved1,
                                                            _PacketBase._s_unpackBitList(authorizedFloorsFrontMap),
                                                            authorizedFloorsFrontMap(authorizedFloorsRearMap),
                                                            defaultFloor,
                                                            defaultDoor,
                                                            dateTime,
                                                            localTimezone,
                                                            readerLocation,
                                                            reserved2)            

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        self.__cache = struct.pack('IHB16sB1sB32s32sBBIII3s', 
                        self.packetId, 
                        self.TYPE, 
                        int(self.valid),
                        self.credentialNumber,
                        int(self.mode),
                        _PacketBase._s_packBitList(self.featuresMap),
                        self.reserved1,
                        _PacketBase._s_packBitList(self.authorizedFloorsFrontMap),
                        _PacketBase._s_packBitList(self.authorizedFloorsRearMap),
                        self.defaultFloor,
                        self.defaultDoor,
                        self.dateTime,
                        self.localTimezone,
                        self.readerLocation,
                        self.reserved2)

#======================================================================================================================
class _PacketInteractiveDecSecurityCredentialData(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x40

    packetId          : int   # I   (uint32)
    decSubnetId       : int   # B   (uint8)
    decId             : int   # B   (uint8)
    credentialData    : bytes # Variable sized string

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        decSubnetId, decId, credentialDataSize = struct.unpack_from('BBB', rawPacket, 6)
        credentialData = struct.unpack_from('%ss' % credentialDataSize, rawPacket, 9)

        return _PacketInteractiveDecSecurityCredentialData(packetId, decSubnetId, decId, credentialData)

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('IHBBBB%ss' % len(self.credentialData), self.packetId, self.TYPE, self.decSubnetId, self.decId, 
                        len(self.credentialData), credentialData)