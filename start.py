from configparser import ConfigParser
from nano25519 import ed25519_oop as ed25519
from hashlib import blake2b
import subprocess
from prompt_toolkit import prompt
from Crypto.Cipher import DES
import binascii, time, io, pyqrcode, random, getpass, socket, sys, platform
import tornado.gen, tornado.ioloop, tornado.iostream, tornado.tcpserver
from modules import nano

import tkinter

raw_in_xrb = 1000000000000000000000000000000.0
server_payin = 100000000000000000000000000000 #0.1Nano
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

def display_qr(account):
    data = 'xrb:' + account
    xrb_qr = pyqrcode.create(data, encoding='iso-8859-1')
    print(xrb_qr.terminal())

#def display_qr(account):
#    data = 'xrb:' + account
#    print(data)
#    xrb_qr = pyqrcode.create(data)
#    code_xbm = xrb_qr.xbm(scale=4)
#    top = tkinter.Tk()
#    code_bmp = tkinter.BitmapImage(data=code_xbm)
#    code_bmp.config(background="black")
#    label = tkinter.Label(image=code_bmp)
#    label.pack()

def wait_for_reply(account):
    pending = nano.get_pending(str(account))
    while len(pending) == 0:
       pending = nano.get_pending(str(account))
       time.sleep(2)
       print('.', end='', flush=True)

    print()

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        des = DES.new(password.encode('utf-8'), DES.MODE_ECB)
        plaintext = des.decrypt(ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    with open(filename, 'wb') as output:
        des = DES.new(password.encode('utf-8'), DES.MODE_ECB)
        ciphertext = des.encrypt(plaintext.encode('utf-8'))
        output.write(ciphertext)

class SimpleTcpClient(object):
    client_id = 0
    
    def __init__(self, stream, account, wallet_seed, index):
        super().__init__()
        SimpleTcpClient.client_id += 1
        self.id = SimpleTcpClient.client_id
        self.stream = stream
        self.account = account
        self.wallet_seed = wallet_seed
        self.index = index
        
        self.stream.socket.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.stream.socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.stream.set_close_callback(self.on_disconnect)


    @tornado.gen.coroutine
    def on_disconnect(self):
        self.log("disconnected")
        yield []

    @tornado.gen.coroutine
    def on_connect(self):
        raddr = 'closed'
        try:
            raddr = '%s:%d' % self.stream.socket.getpeername()
        except Exception:
            pass
        self.log('new, %s' % raddr)

        yield self.dispatch_client()

    def log(self, msg, *args, **kwargs):
        print('[connection %d] %s' % (self.id, msg.format(*args, **kwargs)))

    @tornado.gen.coroutine
    def dispatch_client(self):
        try:
            while True:
                line = yield self.stream.read_until(b'\n')
                self.log('got |%s|' % line.decode('utf-8').strip())
                print("{} {}".format(time.strftime("%d/%m/%Y %H:%M:%S"),line))
                split_data = line.rstrip().decode('utf8').split(",")
                
                if split_data[0] == "shutdown":
                    print("Shutdown Socket Server and Exit")
                    tornado.ioloop.IOLoop.instance().stop()
                    sys.exit()
                
                elif split_data[0] == "pay_server":
                    print("Pay Nano to Server")
                    dest_account = 'xrb_' + split_data[1]
                    amount = str(server_payin)
                    previous = nano.get_previous(self.account)
                    current_balance = nano.get_balance(previous)
                    if int(current_balance) >= server_payin:
                        yield nano.send_xrb(dest_account, int(amount), self.account, int(self.index), self.wallet_seed)
                    else:
                        print("Error - insufficient funds")

                elif split_data[0] == "balance":
                    print("Nano Balance")
                    new_balance = 'Empty'
                    try:
                        previous = nano.get_previous(self.account)
                        current_balance = nano.get_balance(previous)
                        new_balance = float(current_balance) / raw_in_xrb
                    except:
                        pass
                    print("Balance: {}".format(new_balance))
                    return_string = "{} Nano".format(new_balance)
                    yield self.stream.write(return_string.encode('ascii'))

        except tornado.iostream.StreamClosedError:
                pass

class SimpleTcpServer(tornado.tcpserver.TCPServer):
    
    def __init__(self, account, wallet_seed, index):
        super().__init__()
        self.account = account
        self.wallet_seed = wallet_seed
        self.index = index
    
    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        """
            Called for each new connection, stream.socket is
            a reference to socket object
            """
        connection = SimpleTcpClient(stream, self.account, self.wallet_seed, self.index)
        yield connection.on_connect()

@tornado.gen.coroutine
def check_account(account, wallet_seed, index):
    #print("Check for blocks")
    pending = nano.get_pending(str(account))
    #print("Pending Len:" + str(len(pending)))
    
    while len(pending) > 0:
        pending = nano.get_pending(str(account))
        print(len(pending))
        nano.receive_xrb(int(index), account, wallet_seed)

def main():
    print("Starting Nanoquake2")

    parser = ConfigParser()
    config_files = parser.read('config.ini')

    while True:
        password = prompt('Enter password: ', is_password=True)
        password_confirm = prompt('Confirm password: ', is_password=True)
        if password == password_confirm and len(password) == 8:
            break
        if len(password) != 8:
            print("Please enter a password of 8 characters (due to the use of DES to encrypt)")
        else:
            print("Password Mismatch!")

    if len(config_files) == 0:
        print("Generating Wallet Seed")
        full_wallet_seed = hex(random.SystemRandom().getrandbits(256))
        wallet_seed = full_wallet_seed[2:].upper()
        print("Wallet Seed (make a copy of this in a safe place!): ", wallet_seed)
        write_encrypted(password, 'seed.txt', wallet_seed)

        cfgfile = open("config.ini",'w')
        parser.add_section('wallet')

        priv_key, pub_key = nano.seed_account(str(wallet_seed), 0)
        public_key = str(binascii.hexlify(pub_key), 'ascii')
        print("Public Key: ", str(public_key))

        account = nano.account_xrb(str(public_key))
        print("Account Address: ", account)

        parser.set('wallet', 'account', account)
        parser.set('wallet', 'index', '0')

        parser.write(cfgfile)
        cfgfile.close()

        index = 0
        seed = wallet_seed

    else:
        print("Config file found")
        print("Decoding wallet seed with your password")
        try:
            wallet_seed = read_encrypted(password, 'seed.txt', string=True)
        except:
            print('\nError decoding seed, check password and try again')
            sys.exit()

    account = parser.get('wallet', 'account')
    index = int(parser.get('wallet', 'index'))

    print(account)
    print(index)

    previous = nano.get_previous(str(account))
    print(previous)
    if previous != "":
        current_balance = float(nano.get_balance(previous)) / raw_in_xrb
    else:
        current_balance = 0
    display_qr(account)
    print("This is your game account address: {}, your balance is {} Nano".format(account, current_balance))


    while True:
        print("Nanoquake Menu")
        print("1. Start the Game")
        print("2. TopUp Your Game Balance")
        print("3. Withdraw Funds")
        print("4. Exit")
        
        menu1 = 0
        try:
            menu1 = int(input("Please select an option: "))
        except:
            pass

        if menu1 == 4:
            print("Exiting Nanoquake")
            sys.exit()

        elif menu1 == 3:
            print("Withdraw Funds")
            withdraw_dest = input("Destination Address: ")
            previous = nano.get_previous(str(account))
            current_balance = nano.get_balance(previous)
            nano.send_xrb(withdraw_dest, int(current_balance), account, int(index), wallet_seed)

        elif menu1 == 2:
            previous = nano.get_previous(str(account))
            pending = nano.get_pending(str(account))
            #print(previous)

            if (len(previous) == 0) and (len(pending) == 0):
                print("Please send at least 0.1Nano to this account")
                print("Waiting for funds...")
                wait_for_reply(account)

            pending = nano.get_pending(str(account))
            if (len(previous) == 0) and (len(pending) > 0):
                print("Opening Account")
                nano.open_xrb(int(index), account, wallet_seed)

            #print("Rx Pending: ", pending)
            pending = nano.get_pending(str(account))
            #print("Pending Len:" + str(len(pending)))

            while len(pending) > 0:
                pending = nano.get_pending(str(account))
                print(len(pending))
                nano.receive_xrb(int(index), account, wallet_seed)
            
            previous = nano.get_previous(str(account))
            current_balance = nano.get_balance(previous)
            while int(current_balance) < server_payin:
                print("Insufficient funds - please deposit at least 0.1 Nano")
                wait_for_reply(account)
                while len(pending) > 0:
                    pending = nano.get_pending(str(account))
                    print(len(pending))
                    nano.receive_xrb(int(index), account, wallet_seed)
            else:
                print("Sufficient Funds - Lets Go!")
                print("Your Balance: {}".format(current_balance))

        elif menu1 == 1:
            print("Starting Quake2")
            #game_args = "+set nano_address {} +set vid_fullscreen 0".format(account[4:])
            game_args = "+set nano_address {} +set vid_fullscreen 0 &".format(account[4:])
            print(game_args)
            if platform.system() == 'Windows':
                full_command = "start quake2 " + game_args
            else:
                full_command = "release/quake2 " + game_args
            print(full_command)

            process = subprocess.run(full_command, shell=True)

            # tcp server
            server = SimpleTcpServer(account, wallet_seed, index)
            server.listen(PORT, HOST)
            print("Listening on %s:%d..." % (HOST, PORT))
            
            #
            pc = tornado.ioloop.PeriodicCallback(lambda: check_account(account, wallet_seed, index), 10000)
            pc.start()
            
            # infinite loop
            tornado.ioloop.IOLoop.instance().start()
        else:
            print("Error, incorret option selected")
            sys.exit()

if __name__ == "__main__":
    
    main()
