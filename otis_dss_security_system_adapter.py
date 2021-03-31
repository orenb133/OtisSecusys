import socket
import struct
import sys
import time
import collections
import enum
import typing
import functools
import dataclasses

#======================================================================================================================
class _PacketBase(object):

    def packed(self):
        """ Pack this packet to a raw binary represintation of the packet (bytes)  
        Returns: 
            Bytes buffer which conrains the binary representation of the packet
        """
        raise NotImplementedError

    @classmethod
    def s_createFromRaw(self, rawPacket):
        """ Static method which create an instance of the derived class from a raw packet
        Params:
            rawPacket: bytes buffer containing the binay representation of the packet   
        Returns: 
            Instance of the appropriate implementing class
        """
        raise NotImplementedError

    def _s_unpackBitList(bytesBuffer):
        """ Unpack bytes containing per bit data to a list of 0s and 1s
        Params:
            bytesBuffer: buffer of bytes
        Returns:
            A list of 0s and 1s according to the input per bit data
        """
        return [bytesBuffer[y] >> i & 1 for y in range(0, len(bytesBuffer)) for i in range(8)]

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

    @classmethod
    def s_createFromRaw(self, rawPacket):
        unpacked = struct.unpack_from('BBBBB', rawPacket, 2)

        return _PacketHeartbeat(_PacketHeartbeat.SourceType(unpacked[0]), *unpacked[1:])

    def packed(self):
        return struct.pack('HBBBBB', self.TYPE, *self)

#======================================================================================================================
class _PacketInteractiveBase(_PacketBase):

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

    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        unpacked = struct.unpack_from('I', rawPacket, 6)

        return _PacketInteractiveAck(packetId, *unpacked)

    def packed(self):
        return struct.pack('IHI', self.packetId, self.TYPE, int(self.ackType))

    def react(self, ddsContext, configuration, securitySystemInterface):
        ddsContext.ackPacket(self.packetId)

#======================================================================================================================
class _PacketInteractiveDecOnlineStatus(typing.NamedTuple, _PacketInteractiveBase):    
    TYPE = 0x17

    packetId          : int  # I   (uint32)
    decSubnetId       : int  # B   (uint8)
    onlineDecMap      : list # 32s (32 * uint8)

    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        decSubnetId, onlineDecMap = struct.unpack_from('B32s', rawPacket, 6)

        return _PacketInteractiveDecOnlineStatus(packetId, decSubnetId, _PacketBase._s_unpackBitList(onlineDecMap))

    def packed(self):
        return struct.pack('IHB32s', self.packetId, self.TYPE, self.decSubnetId, _PacketBase._s_packBitList(self.onlineDecMap))

    def react(self, ddsContext, configuration, securitySystemInterface):

        for i in range self.onlineDecMap:
            decIp = "%s.%s.%s" % ('.'.join(ddsContext.des.split('.')[0:2]), self.decSubnetId, i)
            packet = _PacketInteractiveDecSecurityOperationModeV2(ddsContext.sequenceNumber, 
                                                                  [0] * 7 # Not using features
                                                                  configuration.decOperationMode, 
                                                                  [0] * 256, # No allowed floors
                                                                  [0] * 256,
                                                                  0)

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
    reserved              : int                                       # 32s (32 * uint8)

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

    def packed(self):
        return struct.pack('IH1s32s32sB', 
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


    @classmethod
    def s_createFromRaw(self, rawPacket, packetId):
        decSubnetId, decId, credentialDataSize = struct.unpack_from('BBB', rawPacket, 6)
        credentialData = struct.unpack_from('%ss' % credentialDataSize, rawPacket, 9)

        return _PacketInteractiveDecSecurityCredentialData(packetId, decSubnetId, decId, credentialData)

    def packed(self):
        return struct.pack('IHBBBB%ss' % len(self.credentialData), self.packetId, self.TYPE, self.decSubnetId, self.decId, 
                        len(self.credentialData), credentialData)


#======================================================================================================================
class OtisDdsSecuritySystemAdapter:

    ICD_MAJOR = 0x3
    ICD_MINOR = 0x0

    __PACKET_RECV_BUFFER_SIZE = 4096
    __PACKET_RECV_SOCKET_TIMEOUT = 0.001
    
#-----------------------------------------------------------------------------------------------------------------------
    @dataclasses.dataclass
    class Configuration():

        heartbeatSendMcGroup  : str = ''
        heartbeatSendPort     : int = 0
        heartbeatSendInterval : float = 0.0

        heartbeatReceiveMcGroup        : str = ''
        heartbeatReceivePort           : int = 0
        heartbeatReceiveTimeout        : float = 0

        localIp : str = ''

        interactiveSendMaxRetries        : int = 0
        interactiveReceivePort           : int = 0
        interactiveSendPortDes           : int = 0
        interactiveSendPortDec           : int = 0
        interactiveDuplicatesCacheSize   : int = 0
        interactiveSendRetryIntreval     : int = 0

        decOperationMode                 : int = 0

#-----------------------------------------------------------------------------------------------------------------------
    class _DdsContext:

        @dataclasses.dataclass
        class _UnackBacklogItem():

            packet        : object
            ipAddress     : str
            port          : int 
            lastSendTime  : int
            retryCout     : int = 0

        def __init__(self, desIp, socket):
            self.__lastHeartbeatTime = 0
            self.__isDesOnline  = False
            self.__sequenceNumber = 0
            self.__onlineDecMap = [0] * 256
            self.__duplicatesCache = collections.OrderedDict()
            self.__desIp = desIp
            self.__unackBacklog = collections.OrderedDict()
            self.__socket = None

        @property
        def isDesOnline(self):
            return self.__isDesOnline

        @property
        def sequenceNumber(self):
            return self.__sequenceNumber

        @property
        def desIp(self):
            return self.__desIp

        @property
        def onlineDecMap(self):
            return self.__onlineDecMap

        @onlineDecMap.setter
        def onlineDecMap(self, onlineDecMap):
            self.__onlineDecMap = onlineDecMap

        def sendPacket(self, packet, ipAddress, port):
            """ Send a packet
            Params:
                packet: Packet to send
                ipAddress: Peer address
                port: Peer port
            """
            self.__socket.sendto(packet.packed(), (ipAddress, port))
            self.__unackBacklog[packet[0]] = self._UnackBacklogItem(packet, ipAddress, port, time.monotonic())
            self.__sequenceNumber = self.__sequenceNumber + 1

        def ackPacket(self, packetId):
            """ Ack a packet sent to the DEN
            Params:
                packetId: Packet ID to ack
            """
            if packetId in self.__unackBacklog:
                del self.__unackBacklog[packetId]

        @property
        def _lastHeartbeatTime(self):
            return self.__lastHeartbeatTime

        @_lastHeartbeatTime.setter
        def _lastHeartbeatTime(self, heartbeatTime):
            self.__lastHeartbeatTime = heartbeatTime

        @property
        def _unackBacklog(self):
            return self.__unackBacklog

        @property
        def _duplicatesCache(self):
            return self.__duplicatesCache

        def _setDesOnline(self, isDesOnline):
            self.__isDesOnline = isDesOnline    

#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, configuration, securitySystemInterface):
        self.__configuration = configuration
        self.__interactivePacketClasses = {}
        self.__ddsContexts = {}
        self.__heartbeatSendNextTime = time.monotonic() + self.__configuration.heartbeatSendInterval
        self.__heartbeatSendPacket = _PacketHeartbeat(_PacketHeartbeat.SourceType.SS, self.ICD_MAJOR, self.ICD_MINOR, 
                                                   self.ICD_MAJOR, self.ICD_MINOR)
        self.__heartbeatSendPacketPacked = self.__heartbeatSendPacket.packed()
        self.__securitySystemInterface = securitySystemInterface

        # Initialize receive MCast socket
        self.__heartbeatReceiveSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__heartbeatReceiveSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mcGroup = struct.pack('4sL', socket.inet_aton(configuration.heartbeatReceiveMcGroup), socket.INADDR_ANY)
        self.__heartbeatReceiveSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mcGroup)
        self.__heartbeatReceiveSocket.bind((configuration.localIp, configuration.heartbeatReceivePort))
        self.__heartbeatReceiveSocket.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
        
        # Initialize send MCast socket
        self.__heartbeatSendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.__heartbeatSendSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
        self.__heartbeatSendSocket.bind((configuration.localIp, 0))
        
        # Initializing Interactive socket
        self.__interactiveSocketDes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__interactiveSocketDes.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__interactiveSocketDes.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
        self.__interactiveSocketDes.bind((configuration.localIp, configuration.interactiveReceivePort))

        # Registering Packets
        self.__registerPacketClass(_PacketInteractiveAck)
        self.__registerPacketClass(_PacketInteractiveDecOnlineStatus)
        self.__registerPacketClass(_PacketInteractiveDecSecurityCredentialData)
        self.__registerPacketClass(_PacketInteractiveDecSecurityOperationModeV2)
        self.__registerPacketClass(_PacketInteractiveDecSecurityAutorizedDefaultFloorV2)


#-----------------------------------------------------------------------------------------------------------------------  
    def start(self):
        while True:
            self.__handleHeartbeatSend()
            self.__handleHeartbeatReceive()
            self.__handleInteractive(self.__interactiveSocketDes)

            time.sleep(0.5)

#-----------------------------------------------------------------------------------------------------------------------        
    def __registerPacketClass(self, packetClass):
        print ("Registering packet class: %s" % packetClass)
        self.__interactivePacketClasses[packetClass.TYPE] = packetClass

#-----------------------------------------------------------------------------------------------------------------------  
    def __removeLastIpOctet(self, ipAddress):
        return '.'.join(ipAddress.split('.')[0:3])

#-----------------------------------------------------------------------------------------------------------------------
    def __handleHeartbeatSend(self):
        now = time.monotonic()
        #print ("Heandling heartbeat send: heartbeatSendNextTime=%s, now=%s" % (self.__heartbeatSendNextTime, now))
       
        if self.__heartbeatSendNextTime <= now:
            self.__heartbeatSendNextTime = self.__heartbeatSendNextTime + self.__configuration.heartbeatSendInterval
         
            #print ("Heartbeat send time had elapsed, updating and sending: heartbeatSendNextTime=%s, packet=%s" % 
            #      (self.__heartbeatSendNextTime, self.__heartbeatSendPacket))

            try:
              self.__heartbeatReceiveSocket.sendto(self.__heartbeatSendPacketPacked, 
                                                  (self.__configuration.heartbeatSendMcGroup, 
                                                  self.__configuration.heartbeatSendPort))
            
            except Exception as e:
                print ("Failed sending heartbeat: exception=%s" % e)

#-----------------------------------------------------------------------------------------------------------------------
    def __handleInteractive(self, sock):
        try:
            # Receive an interactive packet and get its type and ID and DDS context
            packetRaw, peerTuple  = self.__interactiveSocketDes.recvfrom(4096)
            packetId, packetType = struct.unpack_from('IH', packetRaw)
            ddsKey = self.__removeLastIpOctet(peerTuple[0])
            ddsContext = self.__ddsContexts.get(ddsKey, None)
            ackPacketType = None

            # We have a context
            if ddsContext is not None:
            
                # Check for duplicates
                if packetId in ddsContext._duplicatesCache.keys():
                    print ("Received duplicate interactive packet: packetId=%s peerTuple=%s" % (packetId, peerTuple))
                    ackPacketType = _PacketInteractiveAck.AckType.Duplicate
                
                else:
                    # No duplicates, cache the packet ID
                    ddsContext._duplicatesCache[packetId] = None

                    # And pop the oldest one from duplicates cache
                    if len(ddsContext._duplicatesCache) > self.__configuration.interactiveDuplicatesCacheSize:
                        ddsContext._duplicatesCache.popitem(False)

                    # Get the appropriate packet class if supported
                    packetClass = self.__interactivePacketClasses.get(packetType, None)

                    if(packetClass is None):
                        print ("Received unsupported interactive packet: packetRaw=%s peerTuple=%s" % 
                              (packetRaw, peerTuple))
                       
                        ackPacketType = _PacketInteractiveAck.AckType.Unsupported

                    else:
                        # We have a packet, let's process it
                        packet = packetClass.s_createFromRaw(packetRaw, packetId)
                        print ("Received interactive packet: packet=%s peerTuple=%s" % (packet, peerTuple))

                        wasPacketProcessed = packet.react(ddsContext, self.__configuration, self.__securitySystemInterface)

                        if wasPacketProcessed:
                            ackPacketType = _PacketInteractiveAck.AckType.Acceptable

                        else:
                            ackPacketType = _PacketInteractiveAck.AckType.Unacceptable
            else:
                print ("Received interactive packet before having a DDS context, ignoring: " + 
                        "packetId=%s packetType=%s peerTuple=%s" % (packetId, packetType, peerTuple))

            peerIp = peerTuple[0]
            ackPacket = _PacketInteractiveAck(packetId, ackPacketType)
            print ("Sending ack packet to peer: packet=%s peerIp=%s" % (ackPacket, peerIp))

            try:
                self.__interactiveSocketDes.sendto(ackPacket.packed(), 
                                                  (peerIp, self.__configuration.interactiveSendPortDes))
            except:
                print ("Failed sending ack packet to peer: packet=%s peerIp=%s" % (ackPacket, peerIp))
       
        except socket.timeout:
            # Retry sending unacked backlogs  
            now = time.monotonic()

            # Go over all contexts
            for ddsContext in self.__ddsContexts.values():
                unackBacklog = ddsContext._unackBacklog

                # Iterate maximum to backlog size
                for _ in range(len(unackBacklog)):

                    # Get backlog item
                    packetId, unackBacklogItem = ddsContext._unackBacklog.popitem(False)

                    # Time to resend the packet
                    if now - unackBacklogItem.lastSendTime > self.__configuration.interactiveSendRetryIntreval:
                       
                        try:
                            print ("Sending unacked backloged packet: packet=%s peerIp=%s" % 
                            (unackBacklogItem.packet, unackBacklogItem.ipAddress))

                            self.__interactiveSocketDes.sendto(unackBacklogItem.packet.packed(), 
                                                              (unackBacklogItem.ipAddress, unackBacklogItem.port))
                        except Exception as e:
                            print ("Failed sending unacked backloged packet: unackBacklogItem=%s exception=%s" % 
                            (unackBacklogItem, e))

                        # Update backlog item
                        unackBacklogItem.lastSendTime = now
                        unackBacklogItem.retryCout = unackBacklogItem.retryCout + 1

                        # If we haven't reached the limit for packet resend push it back to the backlog
                        if unackBacklogItem.retryCout < self.__configuration.interactiveSendRetryIntreval:
                            ddsContext._unackBacklog[packetId] = unackBacklogItem
                    else:
                        # Breaking as items are sorted by time within the backlog
                        break

#-----------------------------------------------------------------------------------------------------------------------
    def __handleHeartbeatReceive(self):        
        now = time.monotonic()
        
        try:
            # Receive a heartbeat packet
            packetRaw, desTuple  = self.__heartbeatReceiveSocket.recvfrom(4096)
            desIp = desTuple[0]
            heartbeatPacket = _PacketHeartbeat.s_createFromRaw(packetRaw)
            #print ("Received heartbeat packet: packet=%s desTuple=%s" % (heartbeatPacket, desTuple))

            # Get context or create and add if needed
            ddsContext = None
            ddsContextKey = self.__removeLastIpOctet(desIp)

            if not self.__ddsContexts.get(ddsContextKey, None):
                print ("New DES discovered: desIp=%s" % desIp)
                ddsContext = OtisDdsSecuritySystemAdapter._DdsContext(desIp, self.__interactiveSocketDes)
                
                self.__ddsContexts[ddsContextKey] = ddsContext

            else:
                ddsContext = self.__ddsContexts[ddsContextKey]

            # Update context
            ddsContext._lastHeartbeatTime = now
           
            if not ddsContext.isDesOnline:
                print ("DES became online: desIp=%s" % desIp)
                ddsContext._setDesOnline(True)
       
        except socket.timeout:
            # Check if a DES had timed out
            for ddsContext in self.__ddsContexts.values():
                
                if ddsContext.isDesOnline and (now - ddsContext._lastHeartbeatTime) > self.__configuration.heartbeatReceiveTimeout:
                    print ("DES became offline: desIp=%s" % ddsContext.desIp)
                    ddsContext._setDesOnline(False)


config = OtisDdsSecuritySystemAdapter.Configuration()
config.heartbeatReceiveMcGroup = '234.46.30.7'
config.heartbeatReceivePort = 47307
config.heartbeatReceiveTimeout = 3.0

config.localIp = '192.168.1.50'

config.interactiveReceivePort = 45303
config.interactiveSendPortDes = 46303
config.interactiveSendPortDec = 45308
config.interactiveDuplicatesCacheSize = 5
config.interactiveSendRetryIntreval = 1.0
config.interactiveSendMaxRetries = 5

config.heartbeatSendMcGroup = '234.46.30.7'
config.heartbeatSendPort = 48307
config.heartbeatSendInterval = 1

config.decOperationMode = 1

ssAdapter = OtisDdsSecuritySystemAdapter(config, None)
ssAdapter.start()

