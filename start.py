import binascii, time, io, pyqrcode, random, socket, sys, platform, os, threading, platform, hashlib, subprocess, urllib.request, zipfile, shutil
from tkinter import *
import tornado.gen, tornado.ioloop, tornado.iostream, tornado.tcpserver
from modules import nano
from decimal import Decimal
from pathlib import Path
from nano25519 import ed25519_oop as ed25519
from hashlib import blake2b
from prompt_toolkit import prompt
from Crypto.Cipher import AES
import asyncio

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
        if percent >= 100:
            percent = 100
        s = "\r%5.1f%% %*d / %d" % (percent, len(str(totalsize)), readsofar, totalsize)
        sys.stderr.write(s)
        if readsofar >= totalsize: # near the end
            sys.stderr.write("\n")
    else: # total size is unknown
        sys.stderr.write("read %d\n" % (readsofar,))

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
    
    def run(self):
        self.listen(PORT, HOST)
        print("Listening on %s:%d..." % (HOST, PORT))
        # infinite loop
        tornado.ioloop.IOLoop.instance().start()
    
    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        """
            Called for each new connection, stream.socket is
            a reference to socket object
            """
        connection = SimpleTcpClient(stream, self.account, self.wallet_seed, self.index)
        yield connection.on_connect()

class PasswordDialog:
    
    def __init__(self, parent, exists):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        
        if exists == True:
            Label(top, text="Enter Your Password").pack()
        else:
            Label(top, text="Enter New Password").pack()
        
        self.e = Entry(top, show='*')
        self.e.pack(padx=5)
        
        Label(top, text="Confirm").pack()
        
        self.f = Entry(top, show='*')
        self.f.pack(padx=5)
        
        b = Button(top, text="OK", command=self.ok)
        b.pack(pady=5)
    
    def ok(self):

        if self.e.get() == self.f.get():
            self.password = self.e.get()
            self.top.destroy()

    def get_password(self):
        return self.password

class withdrawAllDialog:
    
    def __init__(self, parent, account, index, wallet_seed):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        
        self.account = account
        self.index = index
        self.wallet_seed = wallet_seed

        Label(top, text="Destination Address").pack()
        
        self.withdraw_dest = Entry(top)
        self.withdraw_dest.pack(padx=5)
        
        c = Button(top, text="OK", command=self.withdraw)
        c.pack(pady=5)
    
    def withdraw(self):
        current_balance = nano.get_account_balance(self.account)
        if current_balance == "timeout":
            print("Error - timeout, try again")
        else:
            nano.send_xrb(self.withdraw_dest.get(), int(current_balance), self.account, int(self.index), self.wallet_seed)
        self.top.destroy()

class GenerateSeedDialog:
    
    def __init__(self, parent, wallet_seed):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
 
        self.wallet_seed = wallet_seed
        
        generate = Button(top, text="Generate New Seed", command=self.generateSeed)
        generate.pack(pady=5)
        
        Label(top, text="Import Seed").pack()
        
        self.import_seed = Entry(top)
        self.import_seed.pack(padx=5)
        
        c = Button(top, text="OK", command=self.import_func)
        c.pack(pady=5)
    
    def generateSeed(self):
        full_wallet_seed = hex(random.SystemRandom().getrandbits(256))
        self.wallet_seed = full_wallet_seed[2:].upper()
        print("Wallet Seed (make a copy of this in a safe place!): {}".format(self.wallet_seed))
        self.top.destroy()
    
    def import_func(self):
        self.wallet_seed = self.import_seed.get().upper()
        self.top.destroy()

    def get_seed(self):
        return self.wallet_seed

class DownloadDialog:
    
    def __init__(self, parent, work_dir):
        
        self.work_dir = work_dir
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        
        Label(top, text="Download Maps").pack()
        
        c = Button(top, text="Yes", command=self.download)
        c.pack(pady=5)
        d = Button(top, text="No", command=self.closeWindow)
        d.pack(pady=5)
    
    def download(self):
        if Path(self.work_dir + '/q2-314-demo-x86.exe').exists() == False:
            print("Downloading...")
            try:
                urllib.request.urlretrieve('http://deponie.yamagi.org/quake2/idstuff/q2-314-demo-x86.exe', self.work_dir + '/q2-314-demo-x86.exe', reporthook)
            except:
                print("Failed to download demo files")
                time.sleep(5)
                sys.exit()
            
            print("Download Complete, now unzipping...")
            with zipfile.ZipFile(self.work_dir + '/q2-314-demo-x86.exe',"r") as zip_ref:
                zip_ref.extractall(self.work_dir + '/demo/')
            
            print("Copying Files")
            shutil.copy(self.work_dir + '/demo/Install/Data/baseq2/pak0.pak', self.work_dir + '/release/baseq2/pak0.pak')
            shutil.copytree(self.work_dir + '/demo/Install/Data/baseq2/players', self.work_dir + '/release/baseq2/players')
            
            print("Grabbing Maps")
            if Path(self.work_dir + '/release/baseq2/maps').exists() == False:
                os.mkdir(self.work_dir + '/release/baseq2/maps')
            
            print(" - q2dm1")
            try:
                urllib.request.urlretrieve('http://www.andrewbullock.net/quake2/q2files/tourney/maps/q2dm1.bsp', self.work_dir + '/release/baseq2/maps/q2dm1.bsp', reporthook)
            except:
                print("Failed to download q2dm1")
            print(" - ztn2dm1")
            try:
                urllib.request.urlretrieve('http://www.andrewbullock.net/quake2/q2files/tourney/maps/ztn2dm1.bsp', self.work_dir + '/release/baseq2/maps/ztn2dm1.bsp', reporthook)
            except:
                print("Failed to download ztn2dm1")
            print(" - tltf")
            try:
                urllib.request.urlretrieve('http://www.andrewbullock.net/quake2/q2files/tourney/maps/tltf.bsp', self.work_dir + '/release/baseq2/maps/tltf.bsp', reporthook)
            except:
                print("Failed to download tltf")

        self.top.destroy()

    def closeWindow(self):
        self.top.destroy()

def start_server(account, wallet_seed, index):
    # tcp server
    server = SimpleTcpServer(account, wallet_seed, index)
    
    asyncio.set_event_loop(asyncio.new_event_loop())
    server.run()

def thread_startGame(work_dir, account, wallet_seed, index):
    t = threading.Thread(target=startGame, args=(work_dir,))
    t.start()


    tcp = threading.Thread(target=start_server, args=(account, wallet_seed, index,))
    tcp.daemon = True
    tcp.start()


def startGame(work_dir):
    print("Starting Quake2")
        
    game_args = "+set vid_fullscreen 0 &"
    print(game_args)
    if platform.system() == 'Windows':
        full_command = "start " + work_dir + "/release/yquake2 " + game_args
    else:
        full_command = work_dir + "/release/quake2 " + game_args

    print(full_command)
            
    process = subprocess.run(full_command, shell=True)
            


def exitGame():
    print("Shutdown Socket Server and Exit")
    tornado.ioloop.IOLoop.instance().stop()
    sys.exit()

def update_txt(root, y, account, wallet_seed, index, listbox):
    # Process any pending blocks
    print("Checking for update")
    pending = nano.get_pending(str(account))
    if pending == "timeout":
        root.update_idletasks()
        root.after(5000, lambda: update_txt(root, y, account, wallet_seed, index, listbox))
        return

    previous = nano.get_previous(str(account))
    if len(pending) > 0:
        print("Processing...")
        while len(pending) > 0:
            pending = nano.get_pending(str(account))
            if pending == "timeout":
                continue
        
            try:
                if len(previous) == 0:
                    print("Opening Account")
                    hash, balance = nano.open_xrb(int(index), account, wallet_seed)
                    print("Reply {} {}".format(reply, balance))
                    if hash != 'timeout' and hash != None:
                        listbox.insert(END, "{}... {:.4} Nano".format(hash['hash'][:24], Decimal(balance) / Decimal(raw_in_xrb)))
                    #We get previous after opening the account to switch it to receive rather than open
                    previous = nano.get_previous(str(account))
                else:
                    hash, balance = nano.receive_xrb(int(index), account, wallet_seed)
                    print("Reply {} {}".format(hash, balance))
                    if hash != 'timeout' and hash != None:
                        listbox.insert(END, "{}... {:.4} Nano".format(hash['hash'][:24], Decimal(balance) / Decimal(raw_in_xrb)))
            except:
                print("Error processing blocks")

    try:
        current_balance = nano.get_account_balance(account)
        if current_balance != "timeout":
            y.config(text="{:.3} Nano".format(Decimal(current_balance) / Decimal(raw_in_xrb)))
        else:
            y.config(text="Timeout")
    except:
        y.config(text="Account Not Open")

    root.update_idletasks()
    root.after(5000, lambda: update_txt(root, y, account, wallet_seed, index, listbox))

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

    root = Tk()
    root.geometry("500x700")
    w = Label(root, text="NanoQuake", bg="green", fg="black")
    w.pack(fill=X)

    root.update()

    d = PasswordDialog(root, exists)

    root.wait_window(d.top)

    password = d.get_password()

    if exists == False:
        
        wallet_seed = None
        
        genImpSeed = GenerateSeedDialog(root, wallet_seed)
        root.wait_window(genImpSeed.top)
        
        wallet_seed = genImpSeed.get_seed()

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
        print("\nBalance: {:.3} Nano\n".format(Decimal(current_balance) / Decimal(raw_in_xrb)))

    r = nano.get_rates()
    if r != "timeout":

        print()
        print("NANO Rates")
        print("- $:",r.json()['NANO']['USD'])
        print("- £:",r.json()['NANO']['GBP'])
        print("- €:",r.json()['NANO']['EUR'])

    if Path(work_dir + '/release/baseq2/pak0.pak').exists() == False or Path(work_dir + '/release/baseq2/players').exists() == False:
        
        f = DownloadDialog(root, work_dir)
        root.wait_window(f.top)
    
    data = 'xrb:' + account
    xrb_qr = pyqrcode.create(data)
    code_xbm = xrb_qr.xbm(scale=4)
    code_bmp = BitmapImage(data=code_xbm)
    code_bmp.config(background="white")
    label = Label(root, image=code_bmp)
    label.pack()
    
    w = Label(root, text="Your Game Account: ")
    w.pack()
    data_string = StringVar()
    data_string.set(account)
    w = Entry(root, textvariable=data_string, fg="black", bg="white", bd=0, state="readonly")
    w.pack()
    w.pack(fill=X)
    y = Label(root, text="Your Balance: ")
    y.pack()
    if current_balance != "timeout":
        y = Label(root, text="{:.3} Nano".format(Decimal(current_balance) / Decimal(raw_in_xrb)))
    else:
        y = Label(root, text="Timeout")

    y.pack()

    listbox = Listbox(root)
    listbox.pack(fill=BOTH, expand=1)

    c = Button(root, text="Start Game", command=lambda: thread_startGame(work_dir, account, wallet_seed, index))
    c.pack(pady=5)
 
    withdraw = Button(root, text="Withdraw All", command=lambda: withdrawAllDialog(root, account, index, wallet_seed))
    withdraw.pack(pady=5)
    
    quit = Button(root, text="Exit", command=exitGame)
    quit.pack(pady=5)

    root.update()

    root.after(5000,lambda: update_txt(root, y, account, wallet_seed, index, listbox))
    root.mainloop()

if __name__ == "__main__":

    main()
