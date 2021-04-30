import socket
import struct
import sys
import time
import collections
import enum
import typing
import functools
import dataclasses
import logging
import threading

from . import packets

#======================================================================================================================
class DdsCommunicator:

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
        interactiveSendRetryIntreval     : int = 0

        interactiveReceivePortDes        : int = 0
        interactiveReceivePortDec        : int = 0
       
        interactiveSendPortDes           : int = 0
        interactiveSendPortDec           : int = 0

        interactiveDuplicatesCacheSize   : int = 0

        decOperationMode                 : int = 0      

#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, logger, configuration, securitySystemAdapter):
        """ C'tor
        Params:
            logger: Python logging interface
            configuration: DdsCommunicator configuration
            securitySystemAdapter: Adapter twards the security system
        """

        self.__shouldRun = False
        self.__daemon = None
        self.__logger = logger
        self.__configuration = configuration
        self.__securitySystemAdapter = securitySystemAdapter
        self.__heartbeatReceiveSocket = None
        self.__heartbeatSendSocket = None
        self.__interactiveSocketDes = None
        self.__interactiveSocketDec = None

        self.__interactivePacketClasses = {}
        self.__interactivePacketsRectors = {}

        self.__heartbeatSendNextTime = time.monotonic() + self.__configuration.heartbeatSendInterval
        self.__heartbeatSendPacket = packets._PacketHeartbeat(packets._PacketHeartbeat.SourceType.SS, 
                                                             self.ICD_MAJOR, 
                                                             self.ICD_MINOR, 
                                                             self.ICD_MAJOR, 
                                                             self.ICD_MINOR)
      
        self.__heartbeatSendPacketPacked = self.__heartbeatSendPacket.packed()

        # Registering Packets
        self.__registerPacketClass(packets._PacketInteractiveAck)
        self.__registerPacketClass(packets._PacketInteractiveDecOnlineStatus)
        self.__registerPacketClass(packets._PacketInteractiveDecSecurityCredentialData)
        self.__registerPacketClass(packets._PacketInteractiveDecSecurityOperationModeV2)
        self.__registerPacketClass(packets._PacketInteractiveDecSecurityAutorizedDefaultFloorV2)


#-----------------------------------------------------------------------------------------------------------------------  
    def start(self):
        """ Start the DdsCommunicator
        """
        if not self.__shouldRun and self.__daemon is None:
            self.__logger.info("Starting DDS Communicator...")

            # Initialize receive MCast socket
            listenTuple = (self.__configuration.localIp, self.__configuration.heartbeatReceivePort)
            self.__logger.info("Initializing receive MCast socket: tuple=%s", listenTuple)
            self.__heartbeatReceiveSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.__heartbeatReceiveSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            mreq = struct.pack('4s4s', socket.inet_aton(self.__configuration.heartbeatReceiveMcGroup), 
                               socket.inet_aton(self.__configuration.localIp))
            
            self.__heartbeatReceiveSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.__heartbeatReceiveSocket.bind(listenTuple)
            self.__heartbeatReceiveSocket.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
            
            # Initialize send MCast socket
            self.__logger.info("Initializing send MCast socket: ip=%s", self.__configuration.localIp)
            self.__heartbeatSendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.__heartbeatSendSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('B', 255))
            self.__heartbeatSendSocket.bind((self.__configuration.localIp, 0))
            
            # Initializing Interactive DES socket
            listenTuple = (self.__configuration.localIp, self.__configuration.interactiveReceivePortDes)
            self.__logger.info("Initializing interactive DES socket: tuple=%s", listenTuple)
            self.__interactiveSocketDes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.__interactiveSocketDes.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.__interactiveSocketDes.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
            self.__interactiveSocketDes.bind(listenTuple)

            # Initializing Interactive DEC socket
            listenTuple = (self.__configuration.localIp, self.__configuration.interactiveReceivePortDec)
            self.__logger.info("Initializing interactive DEC socket: tuple=%s", listenTuple)
            self.__interactiveSocketDec = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.__interactiveSocketDec.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.__interactiveSocketDec.settimeout(self.__PACKET_RECV_SOCKET_TIMEOUT)
            self.__interactiveSocketDec.bind(listenTuple)

            self.__shouldRun = True

            try:
                self.__daemon = threading.Thread(target = self.__mainLoop, daemon = True)
                self.__daemon.start()

            except Exception as e:
                self.__logger.exception("Failed spawning daemon thread")
                self.__shouldRun = False
                self.__daemon = None
                raise
        
        else:
            self.__logger.warning("DDS Communicator is already started")

#-----------------------------------------------------------------------------------------------------------------------  
    def stop(self):
        """ Stop the DdsCommunicator
        """
        if self.__shouldRun:
            self.__logger.info("Stopping DDS Communicator...")
            self.__shouldRun = False
            self.__daemon.join()
            self.__daemon = None

            self.__heartbeatReceiveSocket.close()
            self.__heartbeatSendSocket.close()
            self.__interactiveSocketDes.close()
            self.__interactiveSocketDec.close()

            self.__logger.info("DDS Communicator stopped!")
        else:
           self.__logger.warning("DDS Communicator is already stopped") 

 #-----------------------------------------------------------------------------------------------------------------------        
    def __mainLoop(self):
        self.__logger.info("DDS Communicator started!")

        while self.__shouldRun:
            self.__handleHeartbeatSend()
            self.__handleHeartbeatReceive()
            self.__handleInteractive(self.__interactiveSocketDes)
            self.__handleInteractive(self.__interactiveSocketDec)


#-----------------------------------------------------------------------------------------------------------------------        
    def __registerPacketClass(self, packetClass):
        self.__logger.debug("Registering packet: packetClass=%s", packetClass)
        self.__interactivePacketClasses[packetClass.TYPE] = packetClass

#-----------------------------------------------------------------------------------------------------------------------  
    def __removeLastIpOctet(self, ipAddress):
        return '.'.join(ipAddress.split('.')[0:3])

#-----------------------------------------------------------------------------------------------------------------------
    def __handleHeartbeatSend(self):
        now = time.monotonic()
       
        if self.__heartbeatSendNextTime <= now:
            self.__heartbeatSendNextTime = self.__heartbeatSendNextTime + self.__configuration.heartbeatSendInterval

            self.__logger.debug("Heartbeat send time had elapsed, updating and sending: heartbeatSendNextTime=%s, packet=%s", 
                                self.__heartbeatSendNextTime,
                                self.__heartbeatSendPacket)

            try:
                self.__heartbeatReceiveSocket.sendto(self.__heartbeatSendPacketPacked, 
                                                    (self.__configuration.heartbeatSendMcGroup, 
                                                     self.__configuration.heartbeatSendPort))
            
            except Exception as e:
                self.__logger.exception("Failed sending heartbeat packet")

#-----------------------------------------------------------------------------------------------------------------------
    def __handleInteractive(self, denSocket):
        try:
            # Receive an interactive packet and get its type, ID and the appropriate interactive reactor
            packetRaw, peerTuple  = self.__interactiveSocketDes.recvfrom(4096)

            try:
                packetId, packetType = struct.unpack_from('IH', packetRaw)
                self.__logger.debug("Received interactive packet: packetRaw=%s packetId=%s peerTuple=%s", 
                                    packetRaw, packetId, peerTuple)

                reactor = self.__interactivePacketsRectors.get(self.__removeLastIpOctet(peerTuple[0]), None)

                if reactor is not None:
                    reactor._handlePacket(packetRaw, packetId, packetType, peerTuple)

                else:
                    self.__logger.warning("Received an unexpected interactive packet," +
                                          "discarding: packetRaw=%s packetId=%s peerTuple=%s", 
                                           packetRaw, packetId, peerTuple)
            except Exception as e:
                self.__logger.exception("Failed receiving and handling interactive packet")
      
        except socket.timeout:
            # Handle unacked send packets on timeout
            try:
                for reactor in self.__interactivePacketsRectors.values():
                    reactor._handleUnAckedPackets()
          
            except Exception as e:
                self.__logger.exception("Failed handling send un-acked packets")
       
#-----------------------------------------------------------------------------------------------------------------------
    def __handleHeartbeatReceive(self):        
        now = time.monotonic()
        
        try:
            # Receive a heartbeat packet
            packetRaw, desTuple  = self.__heartbeatReceiveSocket.recvfrom(4096)
            
            try:
                desIp = desTuple[0]
                heartbeatPacket = packets._PacketHeartbeat.s_createFromRaw(packetRaw)
                self.__logger.debug("Heartbeat packet was received: packet=%s desTuple=%s", heartbeatPacket, desTuple)

                # Get context or create and add if needed
                reactorKey = self.__removeLastIpOctet(desIp)
                interactivePacketsReactor = self.__interactivePacketsRectors.get(reactorKey, None)

                if interactivePacketsReactor is None:
                    self.__logger.info("New DES was discovered, creating an interactive reactor: desIp=%s icd=%s", desIp, 
                    (heartbeatPacket.icdMajorNegotiable, heartbeatPacket.icdMinorNegotiable))
                    
                    interactivePacketsReactor = packets._InteractiveReactor(self.__logger, 
                                                                            desIp, 
                                                                            self.__configuration, 
                                                                            self.__interactiveSocketDes, 
                                                                            self.__interactiveSocketDec, 
                                                                            self.__interactivePacketClasses,
                                                                            self.__securitySystemAdapter)

                    self.__interactivePacketsRectors[reactorKey] = interactivePacketsReactor

                # Update heartbeat data
                interactivePacketsReactor._lastHeartbeatTime = now
            
                if not interactivePacketsReactor.isDesOnline:
                    self.__logger.info("DES changed state to Online: desIp=%s", desIp)
                    interactivePacketsReactor._setDesOnline(True)
           
            except Exception as e:
                self.__logger.exception("Failed receiving and handling heartbeat packet")
       
        except socket.timeout:
            
            try:
                # Check if a DES had timed out and update its reactor
                for reactor in self.__interactivePacketsRectors.values():
                    
                    if reactor.isDesOnline and (now - reactor._lastHeartbeatTime) > self.__configuration.heartbeatReceiveTimeout:
                        self.__logger.info("DES changed state to Offline: desIp=%s", reactor.desIp)
                        reactor._setDesOnline(False)
            
            except Exception as e:
                self.__logger.exception("Failed updating DESs state")


