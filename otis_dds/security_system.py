import packets
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
class Adapter:

    ICD_MAJOR = 0x3
    ICD_MINOR = 0x0

    __PACKET_RECV_BUFFER_SIZE = 4096
    __PACKET_RECV_SOCKET_TIMEOUT = 0.001
    
#-----------------------------------------------------------------------------------------------------------------------
    @dataclasses.dataclass
    class Configuration():

        heartbeatSendMcGroup            : str = ''
        heartbeatSendPort               : int = 0
        heartbeatSendInterval           : float = 0.0

        heartbeatReceiveMcGroup         : str = ''
        heartbeatReceivePort            : int = 0
        heartbeatReceiveTimeout         : float = 0

        localIp                          : str = ''

        interactiveSendMaxRetries        : int = 0
        interactiveReceivePort           : int = 0
        interactiveSendPortDes           : int = 0
        interactiveSendPortDec           : int = 0
        interactiveDuplicatesCacheSize   : int = 0
        interactiveSendRetryIntreval     : int = 0

        decOperationMode                 : int = 0      

#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, configuration, securitySystemInterface):
        self.__configuration = configuration
        self.__interactivePacketClasses = {}
        self.__interactivePacketsRectors = {}
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
        
        # Initializing Interactive DES socket
        self.__interactiveSocketDes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__interactiveSocketDes.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__interactiveSocketDes.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
        self.__interactiveSocketDes.bind((configuration.localIp, configuration.interactiveReceivePortDes))

        # Initializing Interactive DES socket
        self.__interactiveSocketDec = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__interactiveSocketDec.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__interactiveSocketDec.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
        self.__interactiveSocketDec.bind((configuration.localIp, configuration.interactiveReceivePortDec))

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
            self.__handleInteractive(self.__interactiveSocketDec)

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
    def __handleInteractive(self, denSocket):
        try:
            # Receive an interactive packet and get its type, ID and the appropriate interactive reactor
            packetRaw, peerTuple  = self.__interactiveSocketDes.recvfrom(4096)
            packetId, packetType = struct.unpack_from('IH', packetRaw)
            reactor = self.__interactivePacketsRectors.get(self.__removeLastIpOctet(peerTuple[0]), None)

            if reactor is not None:
                reactor._handleInteractivePacket(packetRaw, packetId, peerTuple, denSocket)
      
        except socket.timeout:

            for reactor in self.__interactivePacketsRectors.values():
                reactor._handleUnAckedPackets()
       
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
                ddsContext = self._DdsContext(desIp, self.__interactiveSocketDes)
                
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


config = Adapter.Configuration()
config.heartbeatReceiveMcGroup = '234.46.30.7'
config.heartbeatReceivePort = 47307
config.heartbeatReceiveTimeout = 3.0

config.localIp = '192.168.1.50'

config.interactiveReceivePortDes = 45303
config.interactiveReceivePortDec = 46308
config.interactiveSendPortDes = 46303
config.interactiveSendPortDec = 45308
config.interactiveDuplicatesCacheSize = 5
config.interactiveSendRetryIntreval = 1.0
config.interactiveSendMaxRetries = 5

config.heartbeatSendMcGroup = '234.46.30.7'
config.heartbeatSendPort = 48307
config.heartbeatSendInterval = 1

config.decOperationMode = 1

ssAdapter = Adapter(config, None)
ssAdapter.start()

