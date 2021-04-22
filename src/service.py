import logging
import sys 
import servicemanager
import win32serviceutil  
import win32service  
import win32event
import win32evtlog
import win32evtlogutil
import servicemanager  
import time
import logging
import time 
import os
import bridge

#======================================================================================================================
class Service(win32serviceutil.ServiceFramework):
    
    _svc_name_ = 'DdsAcsBridge'
    _svc_display_name_ = 'DDS ACS Bridge'
    _svc_description_ = 'A SW Bridge connecting a DDS to a Security System providing access control'

    __CONFIG_FILE_PATH = os.path.join(os.path.dirname(sys.executable), "bridge.cfg")

#-----------------------------------------------------------------------------------------------------------------------
    class _LoggerHandler(logging.Handler):
      
        def emit(self, record):

            severity = win32evtlog.EVENTLOG_INFORMATION_TYPE

            if record.levelno >= logging.ERROR:
               severity = win32evtlog.EVENTLOG_ERROR_TYPE
       
            elif record.levelno == logging.WARNING:
               severity = win32evtlog.EVENTLOG_WARNING_TYPE

            win32evtlogutil.ReportEvent(Service._svc_name_, 
                                        record.lineno, 
                                        0,
                                        eventType=severity, 
                                        strings=[self.format(record)])
 
#-----------------------------------------------------------------------------------------------------------------------
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        win32evtlogutil.AddSourceToRegistry(self._svc_display_name_, sys.executable, 'Application')
        
        self.__stopEvent = win32event.CreateEvent(None, 0, 0, None)
        self.__shouldRun = False

        loggerHandler = self._LoggerHandler()
        loggerHandler.setFormatter(logging.Formatter('p%(process)s {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s'))
        self.__logger = logging.getLogger(self._svc_name_)
        self.__logger.addHandler(loggerHandler)

        self.__bridge = bridge.Bridge(self.__logger, self.__CONFIG_FILE_PATH)

#-----------------------------------------------------------------------------------------------------------------------
    def SvcDoRun(self):
        
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        
        self.__shouldRun = True
        self.__bridge.start()
      
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        while self.__shouldRun:
            time.sleep(0.1)

#-----------------------------------------------------------------------------------------------------------------------
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
      
        self.__bridge.stop()
        self.__shouldRun = False
        win32event.SetEvent(self.__stopEvent)

#-----------------------------------------------------------------------------------------------------------------------   
if __name__ == '__main__':
 
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(Service)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(Service)