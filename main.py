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
import datetime


if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
else:
    import subprocess

DBFILE = os.getcwd() + '\sqlite\pythonsqlite.db'

sql_create_machine_table = """ CREATE TABLE IF NOT EXISTS machine (
    									id integer PRIMARY KEY,
    									machine_name text NOT NULL UNIQUE,
    									operating_system text NOT NULL,	
    									domain_name text,
    									user_name text,
    									serial_no text,
    									manufacteur text,
    									family text,
    									model text,
    									bios_ver text,
    									bios_rel_date text,
    									created_date text NOT NULL,
    									updated_date text NOT NULL
    								); """

sql_create_software_table = """ CREATE TABLE IF NOT EXISTS software (
                            id integer auto_increment PRIMARY KEY,
                            software_name text NOT NULL,
                            version text,
                            install_date text,
                            created_date text NOT NULL,
                            updated_date text NOT NULL,
                            machine_id integer NOT NULL,
                            FOREIGN KEY (machine_id) REFERENCES machine (id)
                        ); """

sql_create_hardware_table = """CREATE TABLE IF NOT EXISTS hardware (
                                    id integer auto_increment PRIMARY KEY,						
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
        self.machine = []
        self.software = []
        self.hardware = []

        # Cross Platform Attributes
        self.mysys = platform.system()
        self.machname = platform.node()
        self.machine.append(self.machname)
        self.osbuild = platform.platform()
        self.machine.append(self.osbuild)
        self.processor = platform.processor()
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

    def get_connection(self):
        """ create a database connection to a SQLite database """
        conn = sqlite3.connect(DBFILE, isolation_level=None)
        cursor = conn.cursor()
        return conn, cursor


    def create_table(self, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """

        conn, cursor = self.get_connection()
        if conn is None:
            logger.info("Could not get connection")
            cursor.execute(create_table_sql)

    def add_machine(self, machine):
        """
        Add new machine into the machine table
        :param conn:
        :param machine:
        :return: machine id
        """

        conn, cursor = self.get_connection()
        if conn is None:
            logger.info("Could not get connection")
        # createddate = datetime.date.today()
        # updateddate = datetime.date.today()
        # self.machine.extend([str(createddate), str(updateddate)])

        sql = ''' INSERT INTO machine(machine_name,operating_system,domain_name,user_name,serial_no,manufacteur,family,model,bios_ver,bios_rel_date,created_date,updated_date) 
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?) '''

        cursor.execute("SELECT machine_name FROM machine WHERE machine_name = ?", (machinex[0],))
        logger.info(machinex[0])
        data = cursor.fetchall()
        if len(data) == 0:
            logger.info('*** Adding machine named %s to the database ***' % machinex[0])
            # self.machine[:0] = [idx]
            # mt = tuple(machine)
            logger.info(len(machinex))
            cursor.execute(sql, machinex)
            return cursor.lastrowid
        else:
            logger.warn('Machine found with name %s already exits in the database' % (self.machine[0]))
            logger.warn('*** EXITING THE SCRIPT ***')
            sys.exit()

    def add_software(self, conn, sw, machid):
        """
        Add Software for machine
        :param conn:
        :param sw:
        :return:
        """

        sql = ''' INSERT INTO software(software_name,version,install_date,created_date,updated_date,machine_id)
            VALUES (?,?,?,?,?,?) '''
        logger.info('SQL INSERT for software: ' + sql)
        cur = conn.cursor()
        # Iterate through software list of dictionaries
        for d in software:
            logger.info(d)

            # obtain the value of the key
            for key, value in d.iteritems():
                logger.info(value)
                # Add to value to list so it is ordered? or array?
                if key == 'DisplayName':
                    dnv = value
                elif key == 'DisplayVersion':
                    dvv = value
                elif key == 'InstallDate':
                    if key:
                        instd = value
                    else:
                        instd = None
                elif key == 'updateddate':
                    upd = value
                elif key == 'createddate':
                    cd = value
                elif key == 'machine_id':
                    mid = value
        sqlval = [dnv, dvv, instd, cd, upd, mid]
        cur.execute(sql, sqlval)
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
        # Add to machine tuple variable
        self.DomainName = win32api.GetDomainName()
        self.UserName = win32api.GetUserName()
        self.dellservtag = self.get_service_tag()
        self.machine.extend([self.DomainName, self.UserName, self.dellservtag])
        self.get_bios()
        # self.get_bitlocker()


        # Add to hardware tuple variable
        self.drives = win32api.GetLogicalDriveStrings()
        self.dfs = self.get_free_disk_space()
        self.get_ram()
        self.hardware.append([self.drives, self.dfs, self.ramtot])

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
        self.machine.extend([self.sysmanuf, self.sysfam, self.sysprod, self.biosver, self.biosrel])

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

    def getSoftwareList(self, machineid):

        key = r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        createddate = datetime.date.today()
        updateddate = datetime.date.today()
        mid = machineid

        for sub_key in self.get_sub_keys(key):
            path = self.join(key, sub_key)
            value = self.get_values(path, ['DisplayName', 'DisplayVersion', 'InstallDate'])

            if value:
                logger.info(value)
                value['createddate'] = str(createddate)
                value['updateddate'] = str(updateddate)
                value['machine_id'] = mid
                self.instsoft.extend([value])

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
    logger.info(DBFILE)
    SysObj.getsysinfo()

    machinex = (
                    'DESKTOP-0104G2XYS',
                    'Windows-10-10.0.15063',
                    'SEMA4GENOMICS',
                    'hal.riker',
                    'JGC7GH2',
                    'Dell',
                    'XPS',
                    'XPS 15 9560',
                    '1.5.0',
                    '08/30/2017',
                    '10/26/2017',
                    '10/26/2017'
    )

    # create machine table
    SysObj.create_table(sql_create_machine_table)
    # create hardware table
    SysObj.create_table(sql_create_hardware_table)
    # create software table
    SysObj.create_table(sql_create_software_table)
    # SysObj.create_connection(os.getcwd() + "\sqlite\pythonsqlite.db")
    # SysObj.create_connection()
    machine_id = SysObj.add_machine(machinex)
    SysObj.getSoftwareList(machine_id)
    software = SysObj.instsoft
    SysObj.add_software(SysObj.conn, software, machine_id)

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

    # Future write instsoft to database

    # Ethernet NIC
    # Wireless NIC
    # IP Address
    # BIT LOCKER INFO
    # System Processes/Software
    logger.info('*** PROCESSING COMPLETE ***')
