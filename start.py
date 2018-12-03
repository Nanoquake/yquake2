import binascii, time, io, pyqrcode, random, socket, sys, platform, os, threading, platform, tkinter, hashlib, subprocess, urllib.request, zipfile, shutil
import tornado.gen, tornado.ioloop, tornado.iostream, tornado.tcpserver
from modules import nano
from decimal import Decimal
from pathlib import Path
from nano25519 import ed25519_oop as ed25519
from hashlib import blake2b
from prompt_toolkit import prompt
from Crypto.Cipher import AES

raw_in_xrb = 1000000000000000000000000000000.0
server_payin = 100000000000000000000000000000 #0.1Nano
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

last_pay_time = 0

pbar = None


def reporthook(blocknum, blocksize, totalsize):
    readsofar = blocknum * blocksize
    if totalsize > 0:
        percent = readsofar * 1e2 / totalsize
        s = "\r%5.1f%% %*d / %d" % (percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
        if readsofar >= totalsize: # near the end
            sys.stderr.write("\n")
    else: # total size is unknown
        sys.stderr.write("read %d\n" % (readsofar,))

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
    
    while True:
        pending = nano.get_pending(str(account))

        if counter == 30:
            print("\nWaited 1 minute... Going back to menu, please check if transaction went through...")
            break
        else:
            if len(pending) == 0 or pending == "timeout":
                print('.', end='', flush=True)
                time.sleep(2)
            else:
                print("\nPending transaction detected")
                break
                    
        counter = counter + 1

def read_encrypted(password, filename, string=True):
    #https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
    
    key = hashlib.sha256(password).digest()
    
    with open(filename, 'rb') as input:
        
        IV = 16 * '\x00'           # Initialization vector: this needs to be changed
        mode = AES.MODE_CBC
        decryptor = AES.new(key, mode, IV=IV.encode("utf8"))
        
        ciphertext = input.read()
        plaintext = decryptor.decrypt(ciphertext)
        if len(plaintext) != 64:
            print("Error - empty seed, please delete your seedAES.txt and start again")
            sys.exit()
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    #https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
    
    key = hashlib.sha256(password).digest()
    
    with open(filename, 'wb') as output:
        IV = 16 * '\x00'           # Initialization vector: this needs to be changed
        mode = AES.MODE_CBC
        encryptor = AES.new(key, mode, IV=IV.encode("utf8"))

        ciphertext = encryptor.encrypt(plaintext.encode('utf-8'))
        output.write(ciphertext)

def send_xrb_thread(dest_account, amount, account, index, wallet_seed):
    return_block = nano.send_xrb(dest_account, amount, account, int(index), wallet_seed)

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
                            current_balance = nano.get_account_balance(self.account)
                        except:
                            pass


                        if current_balance == 'Empty' or current_balance == '':
                            return_string = "Error - empty balance"
                            yield self.stream.write(return_string.encode('ascii'))
                        elif current_balance == 'timeout':
                            return_string = "Error - timeout checking balance"
                            yield self.stream.write(return_string.encode('ascii'))
                        
                        if int(current_balance) >= server_payin:
                            t = threading.Thread(target=send_xrb_thread, args=(dest_account, int(amount), self.account, int(self.index), self.wallet_seed,))
                            t.start()
                            last_pay_time = time.time()
                            return_string = "Payment Sent"
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
                        current_balance = nano.get_account_balance(self.account)
                        print(current_balance)
                    except:
                        pass

                    if current_balance == 'Empty':
                        return_string = "Error - empty balance"
                    elif current_balance == 'timeout':
                        return_string = "Error - timeout checking balance"
                    else:
                        new_balance = Decimal(current_balance) / Decimal(raw_in_xrb)
                        print("Balance: {:.5}".format(new_balance))
                        return_string = "{:.5} Nano".format(new_balance)
                    
                    yield self.stream.write(return_string.encode('ascii'))

                elif split_data[0] == "nano_address":
                    return_string = "{}".format(self.account[4:])
                    yield self.stream.write(return_string.encode('ascii'))

                elif split_data[0] == "rates":
                    try:
                        r = nano.get_rates()
                        return_string = "USD:" + str(r.json()['NANO']['USD']) + " - GBP:" + str(r.json()['NANO']['GBP']) + " - EURO:" + str(r.json()['NANO']['EUR'])
                        yield self.stream.write(return_string.encode('ascii'))

                    except:
                        pass 
                    


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
    if pending != "timeout":
        while len(pending) > 0:
            pending = nano.get_pending(str(account))
            nano.receive_xrb(int(index), account, wallet_seed)

def main():
    dir_path = str(Path.home())
    print("Starting NanoQuake2...")
    print()
    print("Current Dir: {}".format(dir_path))
    print("System: {}".format(platform.system()))
    
    # determine if application is a script file or frozen exe
    # https://stackoverflow.com/questions/404744/determining-application-path-in-a-python-exe-generated-by-pyinstaller
    if getattr(sys, 'frozen', False):
        work_dir = sys._MEIPASS
    elif __file__:
        work_dir = os.path.dirname(os.path.abspath(__file__))

    print("Work Dir: {}".format(work_dir))
    
    
    if(platform.system() == "Linux" or platform.system() == "Darwin"):
        dir_exists = Path(dir_path + '/.nanoquake').exists()
        if dir_exists == False:
            print("Making a new config directory")
            os.mkdir(dir_path + '/.nanoquake')
        nanoquake_path = dir_path + '/.nanoquake'

    elif(platform.system() == "Windows"):
        dir_exists = Path(dir_path + '/AppData/Local/NanoQuake').exists()
        if dir_exists == False:
            print("Making a new config directory")
            os.mkdir(dir_path + '/AppData/Local/NanoQuake')
        nanoquake_path = dir_path + '/AppData/Local/NanoQuake'

    else:
        print("Error - system not recognised")
        time.sleep(5)
        sys.exit()

    print("Config Directory: {}".format(nanoquake_path))
    
    old_exists = Path(nanoquake_path + '/seed.txt').exists()
    if old_exists == True:
        print("Old seed file detected, as encryption has been upgraded please import your old seed, you can extract it with the decodeOldseed.py script")
    
    exists = Path(nanoquake_path + '/seedAES.txt').exists()
    
    while True:
        if exists:
            password = prompt('Enter password: ', is_password=True)
        else:
            password = prompt('Please enter a new password: ', is_password=True)
        password_confirm = prompt('Confirm password: ', is_password=True)
        if password == password_confirm:
            break
        else:
            print("Password Mismatch!")


    if exists == False:
        print()
        print("1. Generate a new seed")
        print("2. Import a seed")
        
        premenu = int(input("Please select an option: "))
        
        wallet_seed = None
        
        if premenu == 1:
            print("Generating Wallet Seed")
            full_wallet_seed = hex(random.SystemRandom().getrandbits(256))
            wallet_seed = full_wallet_seed[2:].upper()
            print("Wallet Seed (make a copy of this in a safe place!): ", wallet_seed)

        elif premenu == 2:
            imported_seed = input("Your wallet seed (64 chars): ")
            wallet_seed = imported_seed.upper()
            print("If you still have an old encrypted seed (in seed.txt) remember that it is unsafe, you should delete it, once you have backed up your seed safely")
        

        write_encrypted(password.encode('utf8'), nanoquake_path + '/seedAES.txt', wallet_seed)
        priv_key, pub_key = nano.seed_account(str(wallet_seed), 0)
        public_key = str(binascii.hexlify(pub_key), 'ascii')
        print("Public Key: ", str(public_key))

        account = nano.account_xrb(str(public_key))
        print("Account Address: ", account)

        seed = wallet_seed

    else:
        print()
        print("Seed file found")
        print("Decoding wallet seed with your password")
        try:
            wallet_seed = read_encrypted(password.encode('utf8'), nanoquake_path + '/seedAES.txt', string=True)
            priv_key, pub_key = nano.seed_account(str(wallet_seed), 0)
            public_key = str(binascii.hexlify(pub_key), 'ascii')
            print("Public Key: ", str(public_key))
        
            account = nano.account_xrb(str(public_key))
            print("Account Address: ", account)
        except:
            print('\nError decoding seed, check password and try again')
            sys.exit()

    index = 0
    print()
    print("This is your game account address: {}".format(account))
    current_balance = nano.get_account_balance(account)
    if current_balance != "timeout":
        print("\nBalance: {:.5} Nano\n".format(Decimal(current_balance) / Decimal(raw_in_xrb)))

    r = nano.get_rates()
    if r != "timeout":

        print()
        print("NANO Rates")
        print("- $:",r.json()['NANO']['USD'])
        print("- £:",r.json()['NANO']['GBP'])
        print("- €:",r.json()['NANO']['EUR'])

    if Path(work_dir + '/release/baseq2/pak0.pak').exists() == False or Path(work_dir + '/release/baseq2/players').exists() == False:
        print("No Demo Files present, do you want to download them?")
        reply = input("Y/N: ")
        
        if reply == 'y' or reply == 'Y':
            if Path(work_dir + '/q2-314-demo-x86.exe').exists() == False:
                print("Downloading...")
                try:
                    urllib.request.urlretrieve('http://deponie.yamagi.org/quake2/idstuff/q2-314-demo-x86.exe', work_dir + '/q2-314-demo-x86.exe', reporthook)
                except:
                    print("Failed to download demo files")
                    time.sleep(5)
                    sys.exit()
                        
            print("Download Complete, now unzipping...")
            with zipfile.ZipFile(work_dir + '/q2-314-demo-x86.exe',"r") as zip_ref:
                zip_ref.extractall(work_dir + '/demo/')
            print("Copying Files")
            shutil.copy(work_dir + '/demo/Install/Data/baseq2/pak0.pak', work_dir + '/release/baseq2/pak0.pak')
            shutil.copytree(work_dir + '/demo/Install/Data/baseq2/players', work_dir + '/release/baseq2/players')
            print("Grabbing Maps")
            if Path(work_dir + '/release/baseq2/maps').exists() == False:
                os.mkdir(work_dir + '/release/baseq2/maps')
            
            print(" - q2dm1")
            try:
                urllib.request.urlretrieve('http://www.andrewbullock.net/quake2/q2files/tourney/maps/q2dm1.bsp', work_dir + '/release/baseq2/maps/q2dm1.bsp', reporthook)
            except:
                print("Failed to download q2dm1")
            print(" - ztn2dm1")
            try:
                urllib.request.urlretrieve('http://www.andrewbullock.net/quake2/q2files/tourney/maps/ztn2dm1.bsp', work_dir + '/release/baseq2/maps/ztn2dm1.bsp', reporthook)
            except:
                print("Failed to download ztn2dm1")
            print(" - tltf")
            try:
                urllib.request.urlretrieve('http://www.andrewbullock.net/quake2/q2files/tourney/maps/tltf.bsp', work_dir + '/release/baseq2/maps/tltf.bsp', reporthook)
            except:
                print("Failed to download tltf")
        else:
            print("Not downloading")
    
 

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
             current_balance = nano.get_account_balance(account)
             if current_balance == "":
                current_balance = 0
             elif current_balance == "timeout":
                 print("\nTimeout Error - try again")
             if int(current_balance) < server_payin:
                print()
                print("Insufficient funds - please deposit at least 0.1 Nano")
                print("{} Raw Detected...".format(current_balance))
                #Scan for new blocks, wait for pending
             pending = nano.get_pending(str(account))
             if pending == "timeout":
                print("Error - timeout")
             else:
                 if len(pending) > 0:
                    print()
                    print("This account has pending transactions. Follow option 2 to process...".format(current_balance))

             print("\nBalance: {:.5} Nano\n".format(Decimal(current_balance) / Decimal(raw_in_xrb)))

        elif menu1 == 4:
             print("\nSeed: {}\n".format(wallet_seed))

        elif menu1 == 3:
            print("Withdraw Funds")
            withdraw_dest = input("Destination Address: ")
            current_balance = nano.get_account_balance(account)
            if current_balance == "timeout":
                print("Error - timeout, try again")
            else:
                nano.send_xrb(withdraw_dest, int(current_balance), account, int(index), wallet_seed)

        elif menu1 == 2:
            display_qr(account)
            previous = nano.get_previous(str(account))
            if previous == "timeout":
                continue
            pending = nano.get_pending(str(account))
            if pending == "timeout":
                continue

            #Scan for new blocks, wait for pending
            if len(pending) == 0:
                print("Waiting for funds...")
                wait_for_reply(account)
            
            # Process any pending blocks
            pending = nano.get_pending(str(account))
            if pending == "timeout":
                continue

            if len(pending) > 0:
                print("Processing...")

            while len(pending) > 0:
                pending = nano.get_pending(str(account))
                if pending == "timeout":
                    continue

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

            current_balance = nano.get_account_balance(account)
            if current_balance == "timeout":
                continue
            if int(current_balance) < server_payin:
                print()
                print("Insufficient funds - please deposit at least 0.1 Nano")
                print("({} Raw Detected)".format(current_balance))
            else:
                print()
                print("Sufficient Funds - Lets Go!")
                print("Your balance is {:.5} Nano".format(Decimal(current_balance) / Decimal(raw_in_xrb)))

        elif menu1 == 1:

            print("Starting Quake2")

            game_args = "+set vid_fullscreen 0 &"
            print(game_args)
            if platform.system() == 'Windows':
                full_command = "start " + work_dir + "/release/yquake2 " + game_args
            else:
                full_command = work_dir + "/release/quake2 " + game_args
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
