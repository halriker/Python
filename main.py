import win32api
import win32con
import os
import sys
import platform
import getpass
import wmi
import logging
import logging.config
import yaml
from _winreg import *
import _winreg
import errno

if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
else:
    import subprocess


class GetSysInformation:
    def __init__(self):
        # variable to write a flat file
        self.pwd = os.getcwd()

        # Cross Platform Attributes
        self.mysys = platform.system()
        self.machname = platform.node()
        self.processor = platform.processor()
        self.osbuild = platform.platform()
        self.drives = None

        # Windows Attributes
        self.HKEY_LOCAL_MACHINE = 'HKEY_LOCAL_MACHINE'
        self.CONST_SW_SUBKEY = 'SOFTWARE'
        self.dellservtag = None
        self.dfs = None
        self.DomainName = None
        self.UserName = None
        self.ramtot = None
        self.bitlocker = None
        self.roots_hives = {
            "HKEY_CLASSES_ROOT": HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_USER": HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": HKEY_LOCAL_MACHINE,
            "HKEY_USERS": HKEY_USERS,
            "HKEY_PERFORMANCE_DATA": HKEY_PERFORMANCE_DATA,
            "HKEY_CURRENT_CONFIG": HKEY_CURRENT_CONFIG,
            "HKEY_DYN_DATA": HKEY_DYN_DATA
        }
        # Dell Attribs from Registry
        self.sysmanuf = None
        self.sysfam = None
        self.sysprod = None
        self.biosver = None
        self.biosrel = None

        # Mac Specific Attributes
        self.macplatform = None

    def parse_key(self, key):
        key = key.upper()
        parts = key.split('\\')
        root_hive_name = parts[0]
        root_hive = self.roots_hives.get(root_hive_name)
        partial_key = '\\'.join(parts[1:])

        if not root_hive:
            raise Exception('root hive "{}" was not found'.format(root_hive_name))

        return partial_key, root_hive

    def get_sub_keys(self, key):
        partial_key, root_hive = self.parse_key(key)

        with ConnectRegistry(None, root_hive) as reg:
            with OpenKey(reg, partial_key) as key_object:
                sub_keys_count, values_count, last_modified = QueryInfoKey(key_object)
                try:
                    for i in range(sub_keys_count):
                        sub_key_name = EnumKey(key_object, i)
                        yield sub_key_name
                except WindowsError:
                    pass

    def get_values(self, key, fields):
        partial_key, root_hive = self.parse_key(key)

        with ConnectRegistry(None, root_hive) as reg:
            with OpenKey(reg, partial_key) as key_object:
                data = {}
                for field in fields:
                    try:
                        value, type = QueryValueEx(key_object, field)
                        data[field] = value
                    except WindowsError:
                        pass

                return data

    def get_value(self, key, field):
        values = self.get_values(key, [field])
        return values.get(field)

    def join(self, path, *paths):
        path = path.strip('/\\')
        paths = map(lambda x: x.strip('/\\'), paths)
        paths = list(paths)
        result = os.path.join(path, *paths)
        result = result.replace('/', '\\')
        return result

    @staticmethod
    def setup_logging():
        default_path = 'logging.yaml'
        default_level = logging.INFO
        env_key = LOG_CFG
        """Setup logging configuration"""
        path = default_path
        value = os.getenv(env_key, None)
        if value:
            path = value
        if os.path.exists(path):
            with open(path, 'rt') as f:
                config = yaml.safe_load(f.read())
            logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=default_level)

    def check_creds(self):
        logged_in_user = getpass.getuser()
        if 'admin' in logged_in_user:
            logger.info('You are logged in as: ' + logged_in_user)
            return True
        else:
            logger.error('You must run this application from an admin account to get Bitlocker information.')
            return False

    @staticmethod
    def get_service_tag():
        computer = wmi.WMI()
        bios_info = computer.Win32_SystemEnclosure()
        for info in bios_info:
            return info.SerialNumber


    @staticmethod
    def get_free_disk_space():
        c = wmi.WMI()
        for disk in c.Win32_LogicalDisk(DriveType=3):
            dfs = disk.Caption, "%0.2f%% free" % (100.0 * long(disk.FreeSpace) / long(disk.Size))
            return dfs

    @staticmethod
    def get_registry_value(key, subkey, value):

        key = getattr(_winreg, key)
        handle = _winreg.OpenKey(key, subkey)
        (value, type) = _winreg.QueryValueEx(handle, value)
        return value

    def getsysinfo(self):

        if self.mysys == 'Windows':
            logger.info('Windows Operating System Detected')
            self.getwininfo()
        elif self.mysys == 'Linux':
            logger.info('Linux Operating System Detected')
            self.getlinuxinfo()
        elif self.mysys == 'Darwin':
            logger.info('MAC OSX Operating System Detected')
            self.getmacinfo()
        else:
            logger.error('Operating System Not Supported!!!')

    def getwininfo(self):
        self.DomainName = win32api.GetDomainName()
        self.UserName = win32api.GetUserName()
        self.drives = win32api.GetLogicalDriveStrings()
        self.dellservtag = self.get_service_tag()
        self.dfs = self.get_free_disk_space()
        self.get_bios()
        self.get_ram()
        # self.get_bitlocker()

    def getlinuxinfo(self):
        print 'Linux'

    def getmacinfo(self):
        print 'Mac'
        self.macplatform = platform.mac_ver()
        # # !/bin/bash
        # SERIAL = ` / bin / grep
        # Serial / proc / cpuinfo | / usr / bin / awk
        # '{print $3}'
        # `
        # MAC = ` / bin / ip
        # link
        # show
        # eth0 | / usr / bin / awk
        # '/ether/ {print $2}'
        # `
        print 'break'
        subprocess.call(['ioreg', '-l', '|', 'grep', 'IOPlatformSerialNumber'])
        print 'subprocess'

    def get_bios(self):
        def get(key):
            return self.get_registry_value(
                "HKEY_LOCAL_MACHINE",
                "HARDWARE\\DESCRIPTION\\System\\BIOS",
                key)

        logger.info('*** Gathering System BIOS Information From HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS ***')
        self.sysmanuf = get("SystemManufacturer")
        self.sysfam = get("SystemFamily")
        self.sysprod = get("SystemProductName")
        self.biosver = get("BIOSVersion")
        self.biosrel = get("BIOSReleaseDate")

    def get_ram(self):
        computer = wmi.WMI()
        for i in computer.Win32_ComputerSystem():
            ramtotbytes = int(i.TotalPhysicalMemory)
        conv = ramtotbytes/1000000000
        self.ramtot = str(conv)

    def get_bitlocker(self):
        admin = self.check_creds()
        if admin:
            # self.bitlocker = subprocess.call(['manage-bde', '-status'])
            logger.info('admin')
        else:
            x = subprocess.Popen(['nircmdc', 'elevate', 'cmd'], stdout=subprocess.PIPE)
            cmdpid = x.pid
            logger.log('The console PID: ' + str(cmdpid))
            x.communicate(['cmd.exe', '/C', 'manage-bde', '-status'])
            logger.log('f')
            self.bitlocker = ""

    def getSoftwareList(self):

        key = r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

        for sub_key in self.get_sub_keys(key):
            path = self.join(key, sub_key)
            value = self.get_values(path, ['DisplayName', 'DisplayVersion', 'InstallDate'])

            if value:
                logger.info(value)

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

    LOG_CFG = 'C:/Users/hal.riker.SEMA4GENOMICS/PycharmProjects/SysInfo/logging.yaml'
    # Instantiate GetSysInformation Object
    SysObj = GetSysInformation()
    SysObj.setup_logging()
    logger = logging.getLogger(__name__)
    logger.info('Logging Configuration File Path: ' + LOG_CFG)
    logger.info('Logging Setup Complete')
    SysObj.getsysinfo()
    logger.info('System Manufacteur: ' + SysObj.sysmanuf)
    logger.info('System Family: ' + SysObj.sysfam)
    logger.info('System Model: ' + SysObj.sysprod)
    logger.info('BIOS Version: ' + SysObj.biosver)
    logger.info('BIOS Release Date: ' + SysObj.biosrel)
    logger.info('The servie tag is ' + SysObj.get_service_tag())
    # Parse dfs to just percent as string
    logger.info(SysObj.get_free_disk_space())
    logger.info('Operating System: ' + SysObj.osbuild)
    logger.info('Computer Name: ' + SysObj.machname)
    logger.info('Domain Name: ' + SysObj.DomainName)
    logger.info('User Name: ' + SysObj.UserName)
    logger.info('Logical Drives: ' + SysObj.drives)
    logger.info('Processor: ' + SysObj.processor)
    logger.info('Total RAM: ' + SysObj.ramtot + 'GB')
    # Get Installed Software from the Windows Registry
    SysObj.getSoftwareList()

    # Ethernet NIC
    # Wireless NIC
    # IP Address
    # BIT LOCKER INFO
    # System Processes/Software
    logger.info('*** PROCESSING COMPLETE ***')
