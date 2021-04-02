import struct
import time
import enum
import typing
import dataclasses
import collections
import math

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
            denChannel    : int
            retryCount     : int = 0

#----------------------------------------------------------------------------------------------------------------------
        def __init__(self, logger, desIp, configuration, desSocket, decSocket, packetClasses, securitySystemInterface):
            self.__logger = logger
            self.__desIp = desIp
            self.__lastHeartbeatTime = 0
            self.__isDesOnline  = False
            self.__sequenceNumber = 0
            self.__onlineDecMap = [0] * 256
            self.__duplicatesCache = collections.OrderedDict()
            self.__unAckedBacklog = collections.OrderedDict()
            self.__configuration = configuration

            self.__denSocketsByChannel = [None] * 2
            self.__denSocketsByChannel[self.DenChannelType.Des] = desSocket
            self.__denSocketsByChannel[self.DenChannelType.Dec] = decSocket

            self.__denSendPortByChannel = [0] * 2
            self.__denSendPortByChannel[self.DenChannelType.Des] = self.__configuration.interactiveSendPortDes
            self.__denSendPortByChannel[self.DenChannelType.Dec] = self.__configuration.interactiveSendPortDec

            self.__denChannelByPeerPort = {self.__configuration.interactiveReceivePortDes : self.DenChannelType.Des,
                                           self.__configuration.interactiveReceivePortDec : self.DenChannelType.Dec}
            self.__packetClasses = packetClasses
            self.__securitySystemInterface = securitySystemInterface

#----------------------------------------------------------------------------------------------------------------------
        @property
        def logger(self):
            return self.__logger

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
        def onlineDecMap(self):
            return self.__onlineDecMap

#----------------------------------------------------------------------------------------------------------------------
        @onlineDecMap.setter
        def onlineDecMap(self, onlineDecMap):
            self.__onlineDecMap = onlineDecMap

#----------------------------------------------------------------------------------------------------------------------
        def sendPacket(self, packet, peerIp, denChannel):
            """ Send a packet
            Params:
                packet: Packet to send
                peerIp: Peer IP address
                denChannel: Den channel to send packet through
            """
            

            peerTuple = (peerIp, self.__denSendPortByChannel[denChannel])
            self.__denSocketsByChannel[denChannel].sendto(packet.packed(), peerTuple)
            self.__unAckedBacklog[packet[0]] = self._UnAackedSentPacket(packet, peerTuple, time.monotonic(), denChannel)
            self.__sequenceNumber = self.__sequenceNumber + 1
            self.__logger.debug("Sending interactie packet: packet=%s peerTuple=%s", packet, peerIp)

#----------------------------------------------------------------------------------------------------------------------
        def _ackPacket(self, packetId):
            if packetId in self.__unAckedBacklog:
                self.__logger.debug("Packet was acked: packetId=%s", packetId)
                del self.__unAckedBacklog[packetId]

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
        def _handlePacket(self, packetRaw, packetId, packetType, peerTuple):
            try:
                ackType = _PacketInteractiveAck.AckType.Unacceptable

                # Filter duplicates
                if packetId in self.__duplicatesCache:
                    ackType = _PacketInteractiveAck.AckType.Duplicate
                    self.__logger.warning("Received duplicate interactive packet: packetId=%s peerTuple=%s", 
                                        packetId, peerTuple)
                    
                else:
                    # Cache packet id
                    self.__duplicatesCache[packetId] = None

                    # Maintain cache size
                    if len(self.__duplicatesCache) > self.__configuration.interactiveDuplicatesCacheSize:
                        self.__duplicatesCache.popitem(False)

                    # Get the appropriate packet class if supported
                    packetClass = self.__packetClasses.get(packetType, None)

                    if packetClass is None:
                        ackType = _PacketInteractiveAck.AckType.Unsupported
                        self.__logger.warning("Received unsupported interactive packet: packetRaw=%s peerTuple=%s", 
                                            packetRaw, peerTuple)

                    else:
                        # We have a packet, let's create and react with it
                        packet = packetClass.s_createFromRaw(packetRaw, packetId)
                        self.__logger.debug("Received interactive packet: packet=%s peerTuple=%s", packet, peerTuple)

                        try:
                            packet.react(self, self.__configuration, self.__securitySystemInterface)
                            ackType = _PacketInteractiveAck.AckType.Acceptable

                        except Exception as e:
                            self.__logger.exception("Failed reacting to interactive packet: packet=%s peerTuple=%s", 
                            packet, peerTuple)
                    
                    ackPacket = _PacketInteractiveAck(packetId, ackType)
                    denChannel = self.__denChannelByPeerPort[peerTuple[1]]
                    peerTuple = (peerTuple[0], self.__denSendPortByChannel[denChannel])
                    self.__logger.debug("Sending ack packet to peer: packet=%s peerTuple=%s", ackPacket, peerTuple)
                    self.__denSocketsByChannel[denChannel].sendto(ackPacket.packed(), peerTuple)
          
            except Exception as e:
                self.__logger.exception("Failed reacting to interactive packet: packet=%s peerTuple=%s", packetRaw, 
                                       peerTuple)

#----------------------------------------------------------------------------------------------------------------------
        def _handleUnAckedPackets(self):
            try:
                now = time.monotonic()

                # Iterate maximum to backlog size
                for _ in range(len(self.__unAckedBacklog)):

                    # Get backlog item
                    packetId, unAckedSentPacket = self.__unAckedBacklog.popitem(False)

                    # Time to resend the packet
                    if now - unAckedSentPacket.lastSendTime > self.__configuration.interactiveSendRetryIntreval:
                    
                        try:
                            self.__logger.debug("Sending un-acked sent packet: packet=%s peerTuple=%s retryCount=%s", 
                                                unAckedSentPacket.packet, 
                                                unAckedSentPacket.peerTuple, 
                                                unAckedSentPacket.retryCount)

                            self.__denSocketsByChannel[unAckedSentPacket.denChannel].sendto(unAckedSentPacket.packet.packed(), 
                                                                                            unAckedSentPacket.peerTuple)
                        except Exception as e:
                            self.__logger.exception("Failed sending unacked backloged packet: unAckedSentPacket=%s", 
                                                    unAckedSentPacket)

                        # Update backlog item
                        unAckedSentPacket.lastSendTime = now
                        unAckedSentPacket.retryCount = unAckedSentPacket.retryCount + 1

                        # If we haven't reached the limit for packet resend push it back to the backlog
                        if unAckedSentPacket.retryCount < self.__configuration.interactiveSendMaxRetries:
                            self.__unAckedBacklog[packetId] = unAckedSentPacket
                    
                        else:
                            self.__logger.warning("Reached retry limit for un-acked sent packet:" + 
                                                "packet=%s peerTuple=%s retryCount=%s", 
                                                unAckedSentPacket.packet, 
                                                unAckedSentPacket.peerTuple, 
                                                unAckedSentPacket.retryCount)
                    else:
                        # Pusing back to front and breaking as items are sorted by time within the backlog
                        self.__unAckedBacklog[packetId] = unAckedSentPacket
                        self.__unAckedBacklog.move_to_end(packetId, last = False)
                        break
        
            except Exception:
                self.__logger.exception("Failed handling un-acked sent packets")

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
    def react(self, reactor, configuration, securitySystemInterface):
        """ React upon receiving this packet
        Params:
            Reactor - Interactive packet reactor handling packets from
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
    def react(self, reactor, configuration, securitySystemInterface):
        reactor._ackPacket(self.packetId)

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
    def react(self, reactor, configuration, securitySystemInterface):

        for i in range(len(self.onlineDecMap)):
         
            # Compare online dec maps and act on change
            if reactor.onlineDecMap[i] != self.onlineDecMap[i]:
                decIp = "%s.%s.%s" % ('.'.join(reactor.desIp.split('.')[0:2]), self.decSubnetId, i)
              
                if self.onlineDecMap[i] == 1:
                    reactor.logger.info("DEC changed state to Online, configuring operation mode: decIp=%s mode=%s", 
                                        decIp, configuration.decOperationMode)
                 
                    packet = _PacketInteractiveDecSecurityOperationModeV2(reactor.sequenceNumber, 
                                                                        [0] * 8, # Not using features (TODO)
                                                                        configuration.decOperationMode, 
                                                                        [0] * 256, # No allowed floors
                                                                        [0] * 256, # No allowed floors (TODO)
                                                                        0)

                    reactor.sendPacket(packet, decIp, _InteractiveReactor.DenChannelType.Dec)

                else:
                    reactor.logger.info("DEC changed state to Offline: decIp=%s", decIp)

        # Save new online DEC map
        reactor.onlineDecMap = self.onlineDecMap

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
                        self.mode,
                        _PacketBase._s_packBitList(self.allowedFloorsFrontMap), 
                        _PacketBase._s_packBitList(self.allowedFloorsRearMap), 
                        self.reserved)


#======================================================================================================================
class _PacketInteractiveDecSecurityAutorizedDefaultFloorV2(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x34

    class DoorType(enum.IntEnum):
        Front = 0
        Rear  = 1

    packetId                 : int                                                    # I   (uint32)
    valid                    : bool                                                   # B   (uint8)
    credentialNumber         : bytes                                                  # 16s (16 * uint8)
    mode                     : int                                                    # B   (uint8)
    featuresMap              : list                                                   # 1s  (uint8)
    reserved1                : int                                                    # B   (uint8)
    authorizedFloorsFrontMap : list                                                   # 32s (32 * uint8)
    authorizedFloorsRearMap  : list                                                   # 32s (32 * uint8)
    defaultFloor             : int                                                    # b   (int8)
    defaultDoor              : DoorType                                               # B   (uint8)
    dateTime                 : int                                                    # I   (uint32)
    localTimezone            : int                                                    # i   (int32)
    readerLocation           : int                                                    # I   (uint32)
    reserved2                : bytes                                                  # 3s  (3 * uint8)

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        (valid, credentialNumber, mode, featuresMap, reserved1, authorizedFloorsFrontMap, authorizedFloorsRearMap, 
        defaultFloor, defaultDoor, dateTime, localTimezone, readerLocation, 
        reserved2) = struct.unpack_from('B16sB1sB32s32sbBIiI3s', rawPacket, 6)

        return _PacketInteractiveDecSecurityAutorizedDefaultFloorV2(packetId, 
                                                            self.TYPE,
                                                            bool(valid),
                                                            credentialNumber,
                                                            mode,
                                                            _PacketBase._s_unpackBitList(featuresMap),
                                                            reserved1,
                                                            _PacketBase._s_unpackBitList(authorizedFloorsFrontMap),
                                                            _PacketBase._s_unpackBitList(authorizedFloorsRearMap),
                                                            defaultFloor,
                                                            defaultDoor,
                                                            dateTime,
                                                            localTimezone,
                                                            readerLocation,
                                                            reserved2)            

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('IHB16sB1sB32s32sbBIiI3s', 
                            self.packetId, 
                            self.TYPE, 
                            int(self.valid),
                            self.credentialNumber,
                            self.mode,
                            _PacketBase._s_packBitList(self.featuresMap),
                            self.reserved1,
                            _PacketBase._s_packBitList(self.authorizedFloorsFrontMap),
                            _PacketBase._s_packBitList(self.authorizedFloorsRearMap),
                            self.defaultFloor,
                            int(self.defaultDoor),
                            self.dateTime,
                            self.localTimezone,
                            self.readerLocation,
                            self.reserved2)

#======================================================================================================================
class _PacketInteractiveDecSecurityCredentialData(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x40

    packetId                      : int   # I   (uint32)
    decSubnetId                   : int   # B   (uint8)
    decId                         : int   # B   (uint8)
    credentialDataBitsSize        : int   # B   (uint8)
    credentialDataBytes           : bytes # Variable sized string

#----------------------------------------------------------------------------------------------------------------------
    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        decSubnetId, decId, credentialDataSizeBits = struct.unpack_from('BBB', rawPacket, 6)
        credentialDataSizeBytes =  math.ceil(credentialDataSizeBits/8.0)
        credentialData = struct.unpack_from('%ss' % credentialDataSizeBytes, rawPacket, 9)[0]

        return _PacketInteractiveDecSecurityCredentialData(packetId, decSubnetId, decId, credentialDataSizeBits, 
                                                           credentialData)

#----------------------------------------------------------------------------------------------------------------------
    def packed(self):
        return struct.pack('IHBBBB%ss' % len(self.credentialDataBytes), self.packetId, self.TYPE, self.decSubnetId, 
                          self.decId,  self.credentialDataBitsSize, self.credentialDataBytes)

#----------------------------------------------------------------------------------------------------------------------
    def react(self, reactor, configuration, securitySystemInterface):

        packet = _PacketInteractiveDecSecurityAutorizedDefaultFloorV2(reactor.sequenceNumber,
                                                True,
                                                self.credentialDataBytes,
                                                configuration.decOperationMode,
                                                [0] * 8, # Not using features (TODO),
                                                0,
                                                [1] * 256, # Authorise all front doors (TODO)
                                                [0] * 256, # Block all rear doors (TODO)
                                                10,        # Default floor 10
                                                _PacketInteractiveDecSecurityAutorizedDefaultFloorV2.DoorType.Rear,
                                                time.mktime(time.localtime()),
                                                time.timezone,
                                                0,
                                                bytes([0] * 3))
        
        reactor.sendPacket(packet, reactor.desIp, _InteractiveReactor.DenChannelType.Des)

