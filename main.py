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
import sqlite3
from sqlite3 import Error


if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
else:
    import subprocess

sql_create_machine_table = """ CREATE TABLE IF NOT EXISTS machine (
    									id integer PRIMARY KEY,
    									machine_name text NOT NULL UNIQUE,
    									operating_system text NOT NULL,	
    									domain_name text,
    									user_name text,
    									manufacteur text,
    									family text,
    									model text,
    									bios_ver text,
    									bios_rel_date text,
    									serial_no text,
    									created_date text NOT NULL,
    									updated_date text NOT NULL
    								); """

sql_create_software_table = """ CREATE TABLE IF NOT EXISTS software (
                            id integer PRIMARY KEY,
                            software_name text NOT NULL,
                            version text,
                            install_date text,
                            created_date text NOT NULL,
                            updated_date text NOT NULL,
                            machine_id integer NOT NULL,
                            FOREIGN KEY (machine_id) REFERENCES machine (id)
                        ); """

sql_create_hardware_table = """CREATE TABLE IF NOT EXISTS hardware (
                                    id integer PRIMARY KEY,						
                                    logical_drives text,
                                    logical_drives_free_space text,
                                    processor text,
                                    physical_mem text,
                                    machine_id integer NOT NULL,
                                    created_date text NOT NULL,
                                    updated_date text NOT NULL,
                                    FOREIGN KEY (machine_id) REFERENCES machine (id)
                                );"""


class GetSysInformation:

    def __init__(self):
        # variables to write to SQLite
        self.pwd = os.getcwd()
        self.conn = None
        self.sqlitever = None

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
        self.instsoft = []
        # Dell Attribs from Registry
        self.sysmanuf = None
        self.sysfam = None
        self.sysprod = None
        self.biosver = None
        self.biosrel = None

        # Mac Specific Attributes
        self.macplatform = None

    # Database Methods

    def create_connection(self, db_file):
        """ create a database connection to a SQLite database """
        try:
            self.conn = sqlite3.connect(db_file)
            self.sqlitever = sqlite3.version
            logger.info('SQLite Version: ' + self.sqlitever)
        except Error as e:
            logger.info(e)
        # finally:
        #     self.conn.close()
        #     logger.info('SQLite DB Connection Closed')

    def create_table(self, conn, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            c = conn.cursor()
            c.execute(create_table_sql)
        except Error as e:
            print(e)

    def add_machine(self, conn, machine):
        """
        Add new machine into the machine table
        :param conn:
        :param machine:
        :return: machine id
        """
        sql = ''' INSERT INTO machine(machine_name,operating_system,domain_name,user_name,manufacteur,family,model,bios_ver,bios_rel_date,serial_no,created_date,updated_date)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?) '''
        cur = conn.cursor()
        cur.execute("SELECT machine_name FROM machine WHERE machine_name = ?", (machine[0],))
        data = cur.fetchall()
        if len(data) == 0:
            logger.info('*** Adding machine named %s to the database ***' % machine[0])
            cur.execute(sql, machine)
            return cur.lastrowid
        else:
            logger.warn('Machine found with name %s already exits in the database' % (machine[0]))
            logger.warn('*** EXITING THE SCRIPT ***')
            sys.exit()

    def add_software(self, conn, sw):
        """
        Add Software for machine
        :param conn:
        :param sw:
        :return:
        """

        sql = ''' INSERT INTO software(software_name,version,install_date,created_date,updated_date,machine_id)
            VALUES(?,?,?,?,?,?) '''
        cur = conn.cursor()
        cur.execute(sql, software)
        return cur.lastrowid

    def add_hardware(self, conn, hw):
        """
        Add Hardware for machine
        :param conn:
        :param hw:
        :return:
        """

        sql = ''' INSERT INTO hardware(logical_drives,logical_drives_free_space,processor,physical_mem,machine_id,created_date,updated_date)
            VALUES(?,?,?,?,?,?,?) '''
        cur = conn.cursor()
        cur.execute(sql, hardware)
        return cur.lastrowid

    # Utility Methods

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
                # for k, v in value.iteritems():
                #     print k
                #     print v
                self.instsoft.append(value)


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

    try:
        SysObj.create_connection(os.getcwd() + "\sqlite\pythonsqlite.db")
    except Exception, e:
        print 'error' + e
    finally:
        # create machine table
        SysObj.create_table(SysObj.conn, sql_create_machine_table)
        # create hardware table
        SysObj.create_table(SysObj.conn, sql_create_hardware_table)
        # create software table
        SysObj.create_table(SysObj.conn, sql_create_software_table)

    with SysObj.conn:

        machine = (
            'DESKTOP-0104G2N',
            'Windows-10-10.0.15063',
            'SEMA4GENOMICS',
            'hal.riker',
            'Dell',
            'XPS',
            'XPS 15 9560',
            '1.5.0',
            '08/30/2017',
            'JGC7GH2',
            '10/26/2017',
            '10/26/2017'
        )

        machine_id = SysObj.add_machine(SysObj.conn, machine)

        # INSERT SOFTWARE
        software = (
            'Microsoft Azure Compute Emulator - v2.9.5.3',
            '2.9.8699.20',
            '10/20/2017',
            '10/26/2017',
            '10/26/2017',
            machine_id
        )

        SysObj.add_software(SysObj.conn, software)

        # INSERT HARDWARE
        hardware = (
            'C:',
            '76%',
            'Intel64 Family 6 Model 158 Stepping 9, GenuineIntel',
            '17GB',
            machine_id,
            '10/26/2017',
            '10/26/2017'
        )

        SysObj.add_hardware(SysObj.conn, hardware)

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

    # Future write instsoft to database

    # Ethernet NIC
    # Wireless NIC
    # IP Address
    # BIT LOCKER INFO
    # System Processes/Software
    logger.info('*** PROCESSING COMPLETE ***')
