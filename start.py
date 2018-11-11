from configparser import ConfigParser
from nano25519 import ed25519_oop as ed25519
from hashlib import blake2b
import subprocess
from prompt_toolkit import prompt
from Crypto.Cipher import DES
import binascii, time, io, pyqrcode, random, getpass, socket, sys, platform, os
import tornado.gen, tornado.ioloop, tornado.iostream, tornado.tcpserver
from modules import nano
import tkinter
from decimal import Decimal

raw_in_xrb = 1000000000000000000000000000000.0
server_payin = 100000000000000000000000000000 #0.1Nano
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

last_pay_time = 0

#def display_qr(account):
#    data = 'xrb:' + account
#    xrb_qr = pyqrcode.create(data, encoding='iso-8859-1')
#    print(xrb_qr.terminal())

def display_qr(account):
    data = 'xrb:' + account
    print('Account Address: ' + account)
    print()
    print("Close NanoQuake Wallet QR code window when ready to process transactions...")
    xrb_qr = pyqrcode.create(data)
    code_xbm = xrb_qr.xbm(scale=4)
    top = tkinter.Tk()
    top.title("NanoQuake Wallet")
    code_bmp = tkinter.BitmapImage(data=code_xbm)
    code_bmp.config(background="white")
    label = tkinter.Label(image=code_bmp)
    label.pack()
    textlabel = tkinter.Label(text="Close this window after scanning")
    textlabel.pack()
    top.mainloop()

def wait_for_reply(account):
    counter = 0
    pending = nano.get_pending(str(account))
    while True:
        counter = counter + 1
        if counter == 30:
            print("\nWaited 1 minute... Going back to menu, please check if transaction went through...")
            break
        else:
            if len(pending) == 0:
                pending = nano.get_pending(str(account))
                print('.', end='', flush=True)
                time.sleep(2)
            else:
                print("\nPending transaction detected")
                break

def print_decimal(float_number):
    return float_number

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
                    global last_pay_time
                    dest_account = 'xrb_' + split_data[1]
                    amount = str(server_payin)
                    current_balance = 'Empty'
                    time_difference = time.time() - last_pay_time
                    print(time_difference)
                    if time_difference > 30:
                        try:
                            previous = nano.get_previous(self.account)
                            current_balance = nano.get_balance(previous)
                        except:
                            pass


                        if current_balance == 'Empty' or current_balance == '':
                            return_string = "Error empty balance"
                            yield self.stream.write(return_string.encode('ascii'))
                        if int(current_balance) >= server_payin:
                            return_block = nano.send_xrb(dest_account, int(amount), self.account, int(self.index), self.wallet_seed)
                            last_pay_time = time.time()
                            return_string = "Block: {}".format(return_block)
                            yield self.stream.write(return_string.encode('ascii'))
                        else:
                            print("Error - insufficient funds")
                            return_string = "Error insufficent funds"
                            yield self.stream.write(return_string.encode('ascii'))
                    else:
                        print("Last pay in less that 30 seconds ago")
                        return_string = "Last pay in less that 30 seconds ago"
                        yield self.stream.write(return_string.encode('ascii'))


                elif split_data[0] == "balance":
                    print("Nano Balance")
                    new_balance = 'Empty'
                    try:
                        #r = nano.get_rates()
                        previous = nano.get_previous(self.account)
                        current_balance = nano.get_balance(previous)
                        new_balance = Decimal(current_balance) / Decimal(raw_in_xrb)
                    except:
                        pass
                    if new_balance != 'Empty':
                        print("Balance: {:.3}".format(new_balance))
                        #print("- $:",Decimal(r.json()['NANO']['USD'])*new_balance)
                        #print("- £:",Decimal(r.json()['NANO']['GBP'])*new_balance)
                        #print("- €:",Decimal(r.json()['NANO']['EUR'])*new_balance)

                    return_string = "{:.5} Nano".format(new_balance)
                    yield self.stream.write(return_string.encode('ascii'))

                elif split_data[0] == "nano_address":
                    return_string = "{}".format(self.account[4:])
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
        nano.receive_xrb(int(index), account, wallet_seed)

def main():
    print("Starting NanoQuake2...")
    print()

    parser = ConfigParser()
    config_files = parser.read('config.ini')

    while True:
        password = prompt('Enter password: ', is_password=True)
        password_confirm = prompt('Confirm password: ', is_password=True)
        if password == password_confirm and len(password) == 8:
            break
        if len(password) != 8:
            print("Please enter a password of EXACTLY 8 characters (due to the use of DES to encrypt)")
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
        print()
        print("Config file found")
        print("Decoding wallet seed with your password")
        try:
            wallet_seed = read_encrypted(password, 'seed.txt', string=True)
            priv_key, pub_key = nano.seed_account(str(wallet_seed), 0)
            public_key = str(binascii.hexlify(pub_key), 'ascii')
            print("Public Key: ", str(public_key))
        
            account = nano.account_xrb(str(public_key))
            print("Account Address: ", account)
        except:
            print('\nError decoding seed, check password and try again')
            sys.exit()

    index = 0
    previous = nano.get_previous(str(account))
    print()
    print("This is your game account address: {}".format(account))

    if previous != "":
        current_balance = Decimal(nano.get_balance(previous)) / Decimal(raw_in_xrb)
        print("Your balance is {:.5} Nano".format(print_decimal(current_balance)))
    else:
        current_balance = 0
        print("Your balance is 0 Nano")
    r = nano.get_rates()

    print()
    print("NANO Rates")
    print("- $:",r.json()['NANO']['USD'])
    print("- £:",r.json()['NANO']['GBP'])
    print("- €:",r.json()['NANO']['EUR'])

 

    while True:
        print()
        print("--------------")
        print("NanoQuake Menu")
        print("--------------")
        print("1. Start Game - Lets Get REKT...")
        print("2. Top-up Game Balance")
        print("3. Withdraw Funds")
        print("4. Display Seed")
        print("5. Check Balance")
        print("6. Exit")
        print()

        menu1 = 0
        try:
            menu1 = int(input("Please select an option: "))
        except:
            pass

        if menu1 == 6:
            print("Exiting NanoQuake")
            sys.exit()

        elif menu1 == 5:
             previous = nano.get_previous(str(account))
             current_balance = nano.get_balance(previous)
             if current_balance == "":
                current_balance = 0
             if int(current_balance) < server_payin:
                print()
                print("Insufficient funds - please deposit at least 0.1 Nano")
                print("{} Raw Detected...".format(current_balance))
                #Scan for new blocks, wait for pending
             pending = nano.get_pending(str(account))
             if len(pending) > 0:
                print()
                print("This account has pending transactions. Follow option 2 to process...".format(current_balance))

             print("\nBalance: {:.5} Nano\n".format(Decimal(current_balance) / Decimal(raw_in_xrb)))

        elif menu1 == 4:
             print("\nSeed: {}\n".format(wallet_seed))

        elif menu1 == 3:
            print("Withdraw Funds")
            withdraw_dest = input("Destination Address: ")
            previous = nano.get_previous(str(account))
            current_balance = nano.get_balance(previous)
            nano.send_xrb(withdraw_dest, int(current_balance), account, int(index), wallet_seed)

        elif menu1 == 2:
            display_qr(account)
            previous = nano.get_previous(str(account))
            pending = nano.get_pending(str(account))

            #Scan for new blocks, wait for pending
            if len(pending) == 0:
                print("Waiting for funds...")
                wait_for_reply(account)
            
            # Process any pending blocks
            pending = nano.get_pending(str(account))
            
            if len(pending) > 0:
                print("Processing...")

            while len(pending) > 0:
                pending = nano.get_pending(str(account))
                if len(previous) == 0:
                    print("Opening Account")
                    nano.open_xrb(int(index), account, wallet_seed)
                    #We get previous after opening the account to switch it to receive rather than open
                    time.sleep(2) #Just to make sure that the block as been recorded
                    previous = nano.get_previous(str(account))
                else:
                    nano.receive_xrb(int(index), account, wallet_seed)
                    print('.', end='', flush=True)
                    time.sleep(2) #give it chance so we down display message twice

            previous = nano.get_previous(str(account))
            current_balance = nano.get_balance(previous)
            if int(current_balance) < server_payin:
                print()
                print("Insufficient funds - please deposit at least 0.1 Nano")
                print("({} Raw Detected)".format(current_balance))
            else:
                print()
                print("Sufficient Funds - Lets Go!")
                print("Your balance is {:.5} Nano".format(Decimal(current_balance) / Decimal(raw_in_xrb)))

        elif menu1 == 1:
            previous = nano.get_previous(str(account))
            current_balance = nano.get_balance(previous)
            
            #try:
            current_dir = os.getcwd()
            print(current_dir)
            #os.remove('~/.yq2/baseq2/config.cfg')
                #except OSError:
                #    pass

            print("Starting Quake2")
            #game_args = "+set nano_address {} +set vid_fullscreen 0".format(account[4:])
            game_args = "+set vid_fullscreen 0 &"
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
            pc = tornado.ioloop.PeriodicCallback(lambda: check_account(account, wallet_seed, index), 20000)
            pc.start()
            
            # infinite loop
            tornado.ioloop.IOLoop.instance().start()
        else:
            print("Error, incorrect option selected")
            sys.exit()

if __name__ == "__main__":
    
    main()
