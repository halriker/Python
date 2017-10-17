import win32api
import win32con
import win32file
from StringIO import StringIO
import os
import platform
import _winreg


class GetSysInformation:

    def __init__(self):
        # variable to write a flat file
        self.pwd = os.getcwd()
        self.fileHandle = None
        self.HKEY_CLASSES_ROOT = win32con.HKEY_CLASSES_ROOT
        self.HKEY_CURRENT_USER = win32con.HKEY_CURRENT_USER
        self.HKEY_LOCAL_MACHINE = win32con.HKEY_LOCAL_MACHINE
        self.HKEY_USERS = win32con.HKEY_USERS
        self.FILE_PATH = self.pwd + 'osinfo.txt'
        self.CONST_OS_SUBKEY = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        self.CONST_PROC_SUBKEY = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
        self.CONST_SW_SUBKEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        self.mysys = platform.system()

    @staticmethod
    def get_registry_value(key, subkey, value):

        key = getattr(_winreg, key)
        handle = _winreg.OpenKey(key, subkey)
        (value, type) = _winreg.QueryValueEx(handle, value)
        return value

    def getsysinfo(self):

        if self.mysys == 'Windows':
            self.getwininfo()
        elif self.mysys == 'Linux':
            self.getlinuxinfo()
        elif self.mysys == 'Darwin':
            self.getmacinfo()
        else:
            print "OS Not Supported"

    def getwininfo(self):
        import uuid
        import platform
        # from subprocess import Popen, PIPE, STDOUT
        # p = Popen(['C:\\Windows\\system32\\manage-bde.exe', '-status'], stdout=PIPE, stderr=STDOUT, shell=True)
        # lines = p.stdout.readlines()
        # for line in lines:
        #     print line
        self.serno = uuid.UUID(int=uuid.getnode())
        self.CompName = win32api.GetComputerName()
        self.DomainName = win32api.GetDomainName()
        self.UserName = win32api.GetUserName()
        self.drives = win32api.GetLogicalDriveStrings()
        # mon = win32api.GetMonitorInfo()
        # sinfo =  win32api.GetSystemInfo()
        # regq = win32api.RegQueryInfoKey()
        self.processor = platform.processor()
        self.platform = platform.platform()
        # return os, osbuild, serno, CompName, DomainName, UserName, drives, processor, platform

    def getlinuxinfo(self):
        print 'Linux'

    def getmacinfo(self):
        print 'Mac'
        

    def os_version(self):
        def get(key):
            return self.get_registry_value(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                key)

        ostype = get("ProductName")
        build = get("CurrentBuildNumber")
        return ostype, build


    def getSoftwareList(self):
        try:
            hCounter=0
            hAttCounter=0
            # connecting to the base
            hHandle = win32api.RegConnectRegistry(None,win32con.HKEY_LOCAL_MACHINE)
            # getting the machine name and domain name
            hCompName = win32api.GetComputerName()
            hDomainName = win32api.GetDomainName()
            # opening the sub key to get the list of Softwares installed
            hHandle = win32api.RegOpenKeyEx(self.HKEY_LOCAL_MACHINE,self.CONST_SW_SUBKEY,0,win32con.KEY_ALL_ACCESS)
            # get the total no. of sub keys
            hNoOfSubNodes = win32api.RegQueryInfoKey(hHandle)
            # delete the entire data and insert it again
            #deleteMachineSW(hCompName,hDomainName)
            # browsing each sub Key which can be Applications installed
            while hCounter < hNoOfSubNodes[0]:
                hAppName = win32api.RegEnumKey(hHandle,hCounter)
                hPath = self.CONST_SW_SUBKEY + "\\" + hAppName
                # initialising hAttCounter
                hAttCounter = 0
                hOpenApp = win32api.RegOpenKeyEx(self.HKEY_LOCAL_MACHINE,hPath,0,win32con.KEY_ALL_ACCESS)
                # [1] will give the no. of attributes in this sub key
                hKeyCount = win32api.RegQueryInfoKey(hOpenApp)
                hMaxKeyCount = hKeyCount[1]
                hSWName = ""
                hSWVersion = ""
                while hAttCounter < hMaxKeyCount:
                    hData = win32api.RegEnumValue(hOpenApp,hAttCounter)
                    if hData[0]== "DisplayName":
                        hSWName = hData[1]
                        self.preparefile("SW Name",hSWName)
                    elif hData[0]== "DisplayVersion":
                        hSWVersion = hData[1]
                        self.preparefile("SW Version",hSWVersion)
                    hAttCounter = hAttCounter + 1
                #if (hSWName !=""):
                #insertMachineSW(hCompName,hDomainName,hSWName,hSWVersion)
                hCounter = hCounter + 1
        except:
            self.preparefile("Exception","In exception in getSoftwareList")

    def openFile(self):
        try:
            self.fileHandle = open(self.FILE_PATH,'w')
        except:
            print "Exceptions in openFile"

    def preparefile(self,printCaption,printString):
        try:
            printText = printCaption + " : " + printString
            print printText
            self.fileHandle.write(printText + "\n")
        except:
            print "In Exception of Prepare file"

    def closeFile(self):
        try:
            self.fileHandle.close()
        except:
            print "Exceptions in closeFile"


if __name__ == '__main__':

    # Instantiate GetSysInformation Object
    SysObj = GetSysInformation()
    SysObj.getsysinfo()

    print "Operating System: " + SysObj.platform
    print "Serial No. " + str(SysObj.serno)
    print "Computer Name: " + SysObj.CompName
    print "Domain Name: " + SysObj.DomainName
    print "User Name: " + SysObj.UserName
    print "Logical Drives: " + SysObj.drives
    print "Processor: " + SysObj.processor

    print 'SCRIPT COMPLETE'
