import win32api
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
import sqlite3
import datetime
from time import sleep
import codecs
if os.name == 'posix' and sys.version_info[0] < 3:
    import subprocess32 as subprocess
else:
    import subprocess


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
        self.hdencrypt = None
        self.fileHandle = None
        self.blfile = None

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

    #################################################################################
    # Enable WMI on client and open firewall                                        #
    #   1. Add a registry key to disable UAC for remote connections.                #
    #   2. Firewall update to allow WMI, remote admin and File and Printer Sharing  #
    #   3. Disable simple file sharing.                                             #
    #################################################################################

    def client_mods(self):
        # Step 1
        keystr = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        sub_key = "LocalAccountTokenFilterPolicy"
        regadd = subprocess.Popen(['nircmdc.exe', "elevate", "cmd", "/K", "reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1"])
        rpid = regadd.pid
        logger.info('CMD PID: ' + str(rpid))
        # Kill CMD PID???????

        # Step 2

    # Database Methods

    def get_connection(self):
        """ create a database connection to a SQLite database """
        conn = sqlite3.connect(DBFILE, isolation_level=None)
        cursor = conn.cursor()
        return conn, cursor

    def create_table(self, create_table_sql):
        """ create a table from the create_table_sql statement
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """

        conn, cursor = self.get_connection()
        if conn is None:
            logger.info("Could not get connection")
        else:
            cursor.execute(create_table_sql)

    def add_machine(self, machine):
        """
        Add new machine into the machine table
        :param machine:
        :return: machine id
        """

        conn, cursor = self.get_connection()
        if conn is None:
            logger.info("Could not get connection")
            sys.exit()
        else:
            logger.info('*** Database Connection Successful ***')
        hd_encryption = self.get_bitlocker()
        logger.info('*** BITLOCKER ENCRYPTION VALUE = ' + hd_encryption)
        createddate = datetime.date.today()
        updateddate = datetime.date.today()
        self.machine.extend([str(hd_encryption), str(createddate), str(updateddate)])

        sql = ''' INSERT INTO machine(machine_name,operating_system,domain_name,user_name,serial_no,manufacteur,family,model,bios_ver,bios_rel_date,hd_encryption,created_date,updated_date) 
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) '''

        cursor.execute("SELECT machine_name FROM machine WHERE machine_name = ?", (machine[0],))
        data = cursor.fetchall()
        if len(data) == 0:
            logger.info('*** Adding machine named %s to the database ***' % machine[0])
            mt = tuple(machine)
            cursor.execute(sql, mt)
            return cursor.lastrowid
        else:
            logger.warn('Machine found with name %s already exits in the database' % (self.machine[0]))
            logger.warn('*** EXITING THE SCRIPT ***')
            sys.exit()

    def add_software(self, sw):
        """
        Add Software for machine
        :param sw:
        :return:
        """

        conn, cursor = self.get_connection()
        if conn is None:
            logger.info("Could not get connection")
            sys.exit()
        else:
            logger.info('*** Database Connection Successful: Software Insert *** ')

        sql = ''' INSERT INTO software(software_name,version,install_date,created_date,updated_date,machine_id) VALUES (?,?,?,?,?,?) '''
        logger.info('SQL INSERT for software: ' + sql)
        # Iterate through software list of dictionaries
        for d in sw:
            # obtain the value of the key
            for key, value in d.iteritems():
                # logger.info(value)
                # Add value to list so it is ordered? or array?
                if key == 'DisplayName':
                    dnv = value
                elif key == 'DisplayVersion':
                    if key:
                        dvv = value
                    else:
                        dvv = None
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
                    machidx = value
            sqlval = [dnv, dvv, instd, cd, upd, machidx]
            sqlvaltup = tuple(sqlval)
            self.software.append(sqlvaltup)
        conn.executemany(sql, self.software)
        for row in conn.execute("select * from software"):
            logger.info(row)
        logger.info('Software Insert Complete')
        return cursor.lastrowid

    def add_hardware(self, hw):
        """
        Add Hardware for machine
        :param hw:
        :return:
        """

        conn, cursor = self.get_connection()
        if conn is None:
            logger.info("Could not get connection")
            sys.exit()

        sql = ''' INSERT INTO hardware(logical_drives,logical_drives_free_space,processor,physical_mem,machine_id,created_date,updated_date)
            VALUES(?,?,?,?,?,?,?) '''
        self.hardware.append(self.processor)
        self.hardware.append(self.ramtot)
        self.hardware.append(machine_id)
        createddate = datetime.date.today()
        updateddate = datetime.date.today()
        self.hardware.extend([str(createddate), str(updateddate)])
        hwtup = tuple(hw)
        cursor.execute(sql, hwtup)
        return cursor.lastrowid

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
        default_path = './sqlite/logging.yaml'
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
        # Add to hardware tuple variable
        self.drives = win32api.GetLogicalDriveStrings()
        self.dfs = self.get_free_disk_space()
        self.get_ram()
        self.hardware.append(self.drives)
        self.hardware.append(self.dfs[1])

    def getlinuxinfo(self):
        print 'Linux'

    def getmacinfo(self):
        print 'Mac'
        self.macplatform = platform.mac_ver()
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

        blfile = os.getcwd() + r"\bloutfile.txt"
        if os.path.isfile(blfile):
            os.remove(blfile)
        else:
            logger.info('File Added: ' + blfile)
        logger.info('Bitlocker Encryption Output File ' + blfile)
        proc = subprocess.Popen(['nircmdc.exe', "elevate", "cmd", "/k", "wmic /namespace:\\\\root\cimv2\security\microsoftvolumeencryption path Win32_EncryptableVolume where DriveLetter='C:' get ProtectionStatus", ">", blfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sleep(5)
        poll = proc.poll()
        if poll is None:
            logger.info('Subprocess Still Running')
        elif poll is not None:
            f = codecs.open(blfile, 'r', encoding='utf_16_le')
            data_f = f.readlines()
            data_f.pop(0)  # take the first line.
            value_f = data_f[0].rstrip()
            self.hdencrypt = value_f
            return value_f

    def getsoftwarelist(self, machineid):

        key = r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        createddate = datetime.date.today()
        updateddate = datetime.date.today()
        mid = machineid

        for sub_key in self.get_sub_keys(key):
            path = self.join(key, sub_key)
            value = self.get_values(path, ['DisplayName', 'DisplayVersion', 'InstallDate'])

            if value:
                # logger.info(value)
                value['createddate'] = str(createddate)
                value['updateddate'] = str(updateddate)
                value['machine_id'] = mid
                self.instsoft.extend([value])

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

    LOG_CFG = os.getcwd() + '\sqlite\logging.yaml'
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
                                hd_encryption,
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

    # Instantiate GetSysInformation Object
    SysObj = GetSysInformation()
    SysObj.setup_logging()
    logger = logging.getLogger(__name__)
    logger.info('Logging Configuration File Path: ' + LOG_CFG)
    logger.info('Logging Setup Complete')
    logger.info('DBFILE Path: ' + DBFILE)
    SysObj.getsysinfo()
    # create machine table
    SysObj.create_table(sql_create_machine_table)
    # create hardware table
    SysObj.create_table(sql_create_hardware_table)
    # create software table
    SysObj.create_table(sql_create_software_table)

    # Log Machine Info
    logger.info('Computer Name: ' + SysObj.machname)
    logger.info('Operating System: ' + SysObj.osbuild)
    logger.info('Domain Name: ' + SysObj.DomainName)
    logger.info('User Name: ' + SysObj.UserName)
    logger.info('The servie tag is ' + SysObj.get_service_tag())
    logger.info('System Manufacteur: ' + SysObj.sysmanuf)
    logger.info('System Family: ' + SysObj.sysfam)
    logger.info('System Model: ' + SysObj.sysprod)
    logger.info('BIOS Version: ' + SysObj.biosver)
    logger.info('BIOS Release Date: ' + SysObj.biosrel)

    # Add PC to machine table
    logger.info('*** BitLocker Check ***')
    machinex = SysObj.machine
    machine_id = SysObj.add_machine(machinex)
    # INSERT HARDWARE INTO hardware table
    logger.info('Logical Drives: ' + SysObj.drives)
    # Parse dfs to just percent as string
    logger.info(SysObj.get_free_disk_space())
    logger.info('Processor: ' + SysObj.processor)
    logger.info('Total RAM: ' + SysObj.ramtot + 'GB')
    SysObj.add_hardware(SysObj.hardware)
    # Get installed software and add to software table
    SysObj.getsoftwarelist(machine_id)
    sw = SysObj.instsoft
    SysObj.add_software(sw)
    logger.info('*** PROCESSING COMPLETE ***')
