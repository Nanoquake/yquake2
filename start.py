import binascii, time, io, pyqrcode, random, socket, sys, platform, os, threading, platform, hashlib, subprocess, urllib.request, zipfile, shutil
from tkinter import *
from tkinter import ttk
import tornado.gen, tornado.ioloop, tornado.iostream, tornado.tcpserver
from modules import nano
from decimal import Decimal
from pathlib import Path
from nano25519 import ed25519_oop as ed25519
from hashlib import blake2b
from prompt_toolkit import prompt
from Crypto.Cipher import AES
import asyncio
import gettext, configparser
from tkinter.messagebox import showinfo
from tkinter import font
import webbrowser

raw_in_xrb = 1000000000000000000000000000000.0
server_payin = 100000000000000000000000000000 #0.1Nano
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

last_pay_time = 0
quake_running = 0

languages = [("English", "en"), ("Français", "fr"), ("Español", "es"), ("Nederlands", "nl"), ("bahasa Indonesia", "id"), ("Português", "pt")]

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
            print(_("Error - empty seed, please delete your seedAES.txt and start again"))
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
  
    def __init__(self, stream, account, wallet_seed, index, listbox):
        super().__init__()
        SimpleTcpClient.client_id += 1
        self.id = SimpleTcpClient.client_id
        self.stream = stream
        self.account = account
        self.wallet_seed = wallet_seed
        self.index = index
        self.listbox = listbox
        
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
                    print(_("Shutting down Quake"))
                    global quake_running
                    quake_running = 0
                
                elif split_data[0] == "pay_server":
                    print(_("Pay Nano to Server"))
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
                            return_string = _("Error - empty balance")
                            yield self.stream.write(return_string.encode('ascii'))
                        elif current_balance == 'timeout':
                            return_string = _("Error - timeout checking balance")
                            yield self.stream.write(return_string.encode('ascii'))
                        
                        if int(current_balance) >= server_payin:
                            t = threading.Thread(target=send_xrb_thread, args=(dest_account, int(amount), self.account, int(self.index), self.wallet_seed,))
                            t.start()
                            last_pay_time = time.time()
                            self.listbox.insert(END, "{}                              {:.4} Nano".format('Pay In', Decimal(amount) / Decimal(raw_in_xrb)))
                            self.listbox.itemconfig(END, {'bg':'coral2'})
                            return_string = _("Payment Sent")
                            yield self.stream.write(return_string.encode('ascii'))
                        else:
                            print(_("Error - insufficient funds"))
                            return_string = _("Error insufficent funds")
                            yield self.stream.write(return_string.encode('ascii'))
                    else:
                        print(_("Last pay in less that 30 seconds ago"))
                        return_string = _("Last pay in less that 30 seconds ago")
                        yield self.stream.write(return_string.encode('ascii'))


                elif split_data[0] == "balance":
                    print(_("Nano Balance"))
                    new_balance = 'Empty'
                    try:
                        current_balance = nano.get_account_balance(self.account)
                        print(current_balance)
                    except:
                        pass

                    if current_balance == 'Empty':
                        return_string = _("Error - empty balance")
                    elif current_balance == 'timeout':
                        return_string = _("Error - timeout checking balance")
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
    
    def __init__(self, account, wallet_seed, index, listbox):
        super().__init__()
        self.account = account
        self.wallet_seed = wallet_seed
        self.index = index
        self.listbox = listbox
    
    def run(self):
        self.listen(PORT, HOST)
        print(_("Listening on %s:%d...") % (HOST, PORT))
        # infinite loop
        tornado.ioloop.IOLoop.instance().start()
    
    @tornado.gen.coroutine
    def handle_stream(self, stream, address):
        """
            Called for each new connection, stream.socket is
            a reference to socket object
            """
        connection = SimpleTcpClient(stream, self.account, self.wallet_seed, self.index, self.listbox)
        yield connection.on_connect()

class PasswordDialog:
    
    def __init__(self, parent, exists):


        def callback(event):
            webbrowser.open_new(r"https://github.com/Nanoquake/yquake2/wiki/FAQ")

        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.ok)
        
        self.exists = exists
        
        if exists == True:
            Label(top, pady=20, font=("Sans", 16), fg="white", bg="#000034", text=_("Enter Your Password")).pack()
            top.geometry("500x200+0+0")
            top.configure(bg="#000034") 
            self.e = Entry(top, font=('Sans', 12), show='*')
            self.e.pack(padx=5, pady=10)
            self.e.focus_force()



            b = Button(top, text=_("OK"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.ok)
            b.pack(pady=10)


            link = Label(top, text="Forgot password? ", fg="#4a90e2", bg="#000034", cursor="hand2")
            link.pack(side="right")
            link.bind("<Button-1>", callback)


        else:
            Label(top, font=("Sans", 16), fg="white", bg="#000034", text=_("Enter New Password")).pack(pady=(10, 5))
            top.geometry("500x200+0+0")
            top.configure(bg="#000034") 
            self.e = Entry(top, show='*')
            self.e.pack(padx=5, pady=(0, 10))
            self.e.focus_force()
            
            Label(top, font=("Sans", 16), fg="white", bg="#000034", text=_("Confirm")).pack()
        
            self.f = Entry(top, show='*')
            self.f.pack(padx=5, pady=(5, 10))
        
            b = Button(top, text=_("OK"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.ok)
            b.pack(pady=20, side=BOTTOM)



    def ok(self, *args):

        if self.exists == True:
            self.password = self.e.get()
            self.top.destroy()
        else:
            if self.e.get() == self.f.get():
                self.password = self.e.get()
                self.top.destroy()

    def get_password(self):
        return self.password

class SelectLanguageDialog:
    
    def __init__(self, parent, nanoquake_path):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.ok)
        self.nanoquake_path = nanoquake_path
        self.lang = "None"
        top.geometry("500x300+0+0")
        top.configure(bg="#000034")        
        self.v = StringVar()
        self.v.set("none") # initialize
        
        for lang, lang_code in languages:
            s = ttk.Style()
            s.configure("TRadiobutton", font=('Sans', 12), background="#000034", foreground="white")
            a = ttk.Radiobutton(top, style="TRadiobutton", text=lang, variable=self.v, value=lang_code).pack(fill=X, padx=20, pady=5)
        
        b = Button(top, text="OK", width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.ok)
        b.pack(pady=10, padx=5, side=BOTTOM)

    def ok(self, *args):

        print(self.v.get())
        if self.v.get() != "none":
            parser = configparser.ConfigParser()
            parser.add_section('general')
            parser.set('general', 'language', self.v.get())
            cfgfile = open(self.nanoquake_path + '/config.ini','w')
            parser.write(cfgfile)
            cfgfile.close()
        
            self.top.destroy()

    def get_lang(self):
        return self.v.get()


class withdrawAllDialog:
    
    def __init__(self, parent, account, index, wallet_seed, listbox):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.withdraw)
        top.geometry("500x200+0+0")
        top.configure(bg="#000034")        
        self.account = account
        self.index = index
        self.wallet_seed = wallet_seed
        self.listbox = listbox

        Label(top, pady=10, bg="#000034", fg="white", font=("Sans", 16), text=_("Destination Address")).pack()
        
        self.withdraw_dest = Entry(top)
        self.withdraw_dest.pack(fill=X, padx=10, pady=10)
        self.withdraw_dest.focus()
        
        c = Button(top, text=_("OK"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.withdraw)
        c.pack(pady=5)

        e = Button(top, text=_("Back"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.close)
        e.pack(pady=10, padx=10)
    
    def close(self):
        self.top.destroy()

    def withdraw(self):
        current_balance = nano.get_account_balance(self.account)
        if current_balance == "timeout":
            print(_("Error - timeout, try again"))
        else:
            nano.send_xrb(self.withdraw_dest.get(), int(current_balance), self.account, int(self.index), self.wallet_seed)
            self.listbox.insert(END, "{}                              {:.4} Nano".format('Withdraw', Decimal(current_balance) / Decimal(raw_in_xrb)))
            self.listbox.itemconfig(END, {'bg':'coral2'})
        self.top.destroy()

class settingsDialog:
    
    def __init__(self, parent, nanoquake_path, wallet_seed):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.close)
        top.geometry("500x250+0+0")
        top.configure(bg="#000034")
        self.nanoquake_path = nanoquake_path
        self.wallet_seed = wallet_seed

        Label(top, font=("Sans", 16), bg="#000034", fg="white", pady=15, text=_("Settings")).pack()        
        e = Button(top, text=_("Back"), width="20", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.close)
        e.pack(pady=10, padx=10, side=BOTTOM)
        c = Button(top, text=_("Show My Seed"), width="20", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", takefocus=False, command=self.show_seed)
        c.pack(pady=10, padx=10, side=BOTTOM)
        b = Button(top, text=_("Show Disclaimer"), width="20", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", takefocus=False, command=self.show_disclaimer)
        b.pack(pady=10, padx=10, side=BOTTOM)
        d = Button(top, text=_("Change My Language"), width="20", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white",takefocus=False, command=self.change_lang)
        d.pack(pady=10, padx=10, side=BOTTOM)
    
    def close(self):
        self.top.destroy()
    
    def show_seed(self):
        showinfo ("NanoQuake", self.wallet_seed, parent=self.top)

    def change_lang(self):

        lang = SelectLanguageDialog(self.top, self.nanoquake_path)
        self.top.wait_window(lang.top)
    
        selected_language = lang.get_lang()
        print(selected_language)
        showinfo("NanoQuake", _("Restarting with new settings"))
        sys.exit()

    def show_disclaimer(self):
        disclaimer = disclaimerDialog(self.top)
        self.top.wait_window(disclaimer.top)


class disclaimerDialog:
    
    def __init__(self, parent):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.close)
        top.geometry("500x250+0+0")
        top.configure(bg="#000034")
        
        text = Text(top, width=62, height=10, font=('Sans', 10))
        text.insert('1.0', _('DISCLAIMER\n* To participate in the NanoQuake events you must be a natural person\n who is at least 18 years of age or older.\n* It is your responsibility to determine whether the state, country, territory \nor jurisdiction in which you are located, permits the usage of NanoQuake \nsoftware and the ability to pay-in to a game.'))
        text.pack(pady=5, padx=10)
        text['state'] = 'disabled'
        e = Button(top, text=_("OK"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.close)
        e.pack(pady=10, padx=10, side=BOTTOM)
    
    def close(self):
        self.top.destroy()


class GenerateSeedDialog:
    
    def __init__(self, parent, wallet_seed):
        
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.generateSeed)
        top.geometry("500x200+0+0")
        top.configure(bg="#000034")
 
        self.wallet_seed = wallet_seed

       
        Label(top, pady=5, font=("Sans", 16), bg="#000034", fg="white", text=_("Import Seed")).pack()
        
        self.import_seed = Entry(top)
        self.import_seed.pack(fill=X, padx=20, pady=5)
        
        c = Button(top, text=_("OK"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.import_func)
        c.pack(pady=5)


        generate = Button(top, text=_("Generate New Seed"), font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.generateSeed)
        generate.pack(pady=15, ipadx=15, side=BOTTOM)

    
    def generateSeed(self):
        full_wallet_seed = hex(random.SystemRandom().getrandbits(256))
        self.wallet_seed = full_wallet_seed[2:].upper()
        print(_("Wallet Seed (make a copy of this in a safe place!): {}").format(self.wallet_seed))
        self.top.destroy()
    
    def import_func(self):
        self.wallet_seed = self.import_seed.get().upper()
        if len(self.wallet_seed) == 64:
            self.top.destroy()
        else:
            print("Error - incorrect seed")
            showinfo("NanoQuake", "Error - incorrect seed", parent=self.top)

    def get_seed(self):
        return self.wallet_seed

class DownloadDialog:
    
    def __init__(self, parent, work_dir):
        
        self.work_dir = work_dir
        top = self.top = Toplevel(parent)
        top.title("NanoQuake")
        top.bind('<Return>', self.download)
        top.geometry("500x200+0+0")
        top.configure(bg="#000034")
        
        Label(top, pady=15, font=("Sans", 16), bg="#000034", fg="white", text=_("Download Pak Files")).pack()
        
        self.c = Button(top, text=_("Yes"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.download)
        self.c.pack(pady=5)
        self.d = Button(top, text=_("No"), width="10", font=('Sans', 10), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", command=self.closeWindow)
        self.d.pack(pady=5)
   
        self.progressbar = ttk.Progressbar(top, length=500)
        self.progressbar.pack(pady=10)

        self.e = Label(top, font=("Sans", 10), bg="#000034", fg="white", text=_("Download Status"))
        self.e.pack(pady=5)
    
    def reporthook(self, blocknum, blocksize, totalsize):
        readsofar = blocknum * blocksize
        if totalsize > 0:
            percent = readsofar * 1e2 / totalsize
            if percent >= 100:
                percent = 100
            s = "\r%5.1f%% %*d / %d" % (percent, len(str(totalsize)), readsofar, totalsize)
            sys.stderr.write(s)
            self.progressbar['value'] = percent
            self.top.update()
            if readsofar >= totalsize: # near the end
                sys.stderr.write("\n")
        else: # total size is unknown
            sys.stderr.write("read %d\n" % (readsofar,))
    
    def download(self):
        self.c.config(state=DISABLED)
        self.d.config(text=_("Close"))
        if Path(self.work_dir + '/q2-314-demo-x86.exe').exists() == False:
            print(_("Downloading..."))
            self.e.config(text=_("Downloading Demo Pak..."))
            self.top.update()
            
            try:
                urllib.request.urlretrieve('http://deponie.yamagi.org/quake2/idstuff/q2-314-demo-x86.exe', self.work_dir + '/q2-314-demo-x86.exe', self.reporthook)
            except:
                print(_("Failed to download demo files"))
                time.sleep(5)
                sys.exit()
            
            print(_("Download Complete, now unzipping..."))
            self.e.config(text=_("Download Complete, now unzipping"))
            self.e.update()
            with zipfile.ZipFile(self.work_dir + '/q2-314-demo-x86.exe',"r") as zip_ref:
                zip_ref.extractall(self.work_dir + '/demo/')
            
            print(_("Copying Files"))
            self.e.config(text=_("Copying Files"))
            self.e.update()
            shutil.copy(self.work_dir + '/demo/Install/Data/baseq2/pak0.pak', self.work_dir + '/release/baseq2/pak0.pak')
            shutil.copytree(self.work_dir + '/demo/Install/Data/baseq2/players', self.work_dir + '/release/baseq2/players')

            if platform.system() == 'Windows':
                print(_("Grabbing Curl Files"))
                try:
                     with zipfile.ZipFile(self.work_dir + '/curl.zip',"r") as zip_ref:
                        zip_ref.extractall(self.work_dir + '/curl/')
                     shutil.copy(self.work_dir + '/curl/libcrypto-1_1-x64.dll', self.work_dir + '/release/libcrypto-1_1-x64.dll')
                     shutil.copy(self.work_dir + '/curl/libcurl-x64.dll', self.work_dir + '/release/libcurl.dll')
                     shutil.copy(self.work_dir + '/curl/libssl-1_1-x64.dll', self.work_dir + '/release/libssl-1_1-x64.dll')
                except:
                    print(_("Failed to download curl files"))

        self.top.destroy()

    def closeWindow(self):
        self.top.destroy()

def start_server(account, wallet_seed, index, listbox):
    # tcp server
    server = SimpleTcpServer(account, wallet_seed, index, listbox)
    
    asyncio.set_event_loop(asyncio.new_event_loop())
    server.run()

def thread_startGame(work_dir, account, wallet_seed, index):
    global quake_running
    
    if quake_running == 0:
        t = threading.Thread(target=startGame, args=(work_dir,))
        t.start()
        quake_running = 1
    else:
        print(_("Quake already running"))



def startGame(work_dir):
    print(_("Starting Quake2"))
        
    game_args = "+set vid_fullscreen 0 &"
    print(game_args)
    if platform.system() == 'Windows':
        full_command = r"start .{} &".format("\\release\yquake2.exe")
    else:
        full_command = work_dir + "/release/quake2 " + game_args

    print(full_command)
            
    process = subprocess.run(full_command, shell=True)
            


def exitGame():
    print(_("Shutdown Socket Server and Exit"))
    tornado.ioloop.IOLoop.instance().stop()
    sys.exit()

def update_txt(root, y, account, wallet_seed, index, listbox):
    # Process any pending blocks
    print(_("Checking for update"))
    pending = nano.get_pending(str(account))
    if pending == "timeout":
        root.update_idletasks()
        root.after(5000, lambda: update_txt(root, y, account, wallet_seed, index, listbox))
        return

    previous = nano.get_previous(str(account))
    if len(pending) > 0:
        print(_("Processing..."))
        while len(pending) > 0:
            pending = nano.get_pending(str(account))
            if pending == "timeout":
                continue
        
            try:
                if len(previous) == 0:
                    print(_("Opening Account"))
                    hash, balance = nano.open_xrb(int(index), account, wallet_seed)
                    print(_("Reply {} {}").format(reply, balance))
                    if hash != 'timeout' and hash != None:
                        listbox.insert(END, "{}... {:.4} Nano".format(hash['hash'][:24], Decimal(balance) / Decimal(raw_in_xrb)))
                        listbox.itemconfig(END, {'bg':'spring green'})
                    #We get previous after opening the account to switch it to receive rather than open
                    previous = nano.get_previous(str(account))
                else:
                    hash, balance = nano.receive_xrb(int(index), account, wallet_seed)
                    print(_("Reply {} {}").format(hash, balance))
                    if hash != 'timeout' and hash != None:
                        listbox.insert(END, "{}... {:.4} Nano".format(hash['hash'][:24], Decimal(balance) / Decimal(raw_in_xrb)))
                        listbox.itemconfig(END, {'bg':'spring green'})
            except:
                print(_("Error processing blocks"))

    try:
        current_balance = nano.get_account_balance(account)
        if current_balance != "timeout":
            y.config(text="{:.3} Nano".format(Decimal(current_balance) / Decimal(raw_in_xrb)))
        else:
            y.config(text=_("Timeout"))
    except:
        y.config(text=_("Account Not Open"))

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
    root.overrideredirect(1)
    root.withdraw()
    root.geometry("500x650+0+0")
    root.configure(background="#000034")
    root.wm_title("NanoQuake v1.62")
    root.iconbitmap("nanoquake.ico")

    root.update()



    parser = configparser.ConfigParser()
    config_files = parser.read(nanoquake_path + '/config.ini')

    if len(config_files) == 0:
        lang = SelectLanguageDialog(root, nanoquake_path)
        root.wait_window(lang.top)
        selected_language = lang.get_lang()
        print(selected_language)
        parser.add_section('general')
        parser.set('general', 'language', selected_language)
        
        cfgfile = open(nanoquake_path + '/config.ini','w')
        parser.write(cfgfile)
        cfgfile.close()

    selected_language = parser.get('general', 'language')
    print(selected_language)
    localedirectory = work_dir + '/locale'
    try:
        lang1 = gettext.translation('nanoquake', localedir=localedirectory, languages=[selected_language])
        lang1.install()
    except:
        print("Error - not able to locate translation files, back to default")

    try:
        disclaimer_bool = parser.get('general', 'disclaimer')
    except:
        disclaimer_bool = "False"

    if disclaimer_bool != "True":
        disclaimer = disclaimerDialog(root)
        root.wait_window(disclaimer.top)
        parser.set('general', 'disclaimer', "True")
        
        cfgfile = open(nanoquake_path + '/config.ini','w')
        parser.write(cfgfile)
        cfgfile.close()
    
    while True:
        
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
            print(_("Public Key: "), str(public_key))

            account = nano.account_xrb(str(public_key))
            print(_("Account Address: "), account)

            seed = wallet_seed
            break

        else:
            print()
            print(_("Seed file found"))
            print(_("Decoding wallet seed with your password"))
            try:
                wallet_seed = read_encrypted(password.encode('utf8'), nanoquake_path + '/seedAES.txt', string=True)
                priv_key, pub_key = nano.seed_account(str(wallet_seed), 0)
                public_key = str(binascii.hexlify(pub_key), 'ascii')
                print(_("Public Key: "), str(public_key))
            
                account = nano.account_xrb(str(public_key))
                print(_("Account Address: "), account)
                break
            except:
                print('\nError decoding seed, check password and try again')


    index = 0
    print()
    print(_("This is your game account address: {}").format(account))
    current_balance = nano.get_account_balance(account)
    if current_balance != "timeout":
        print(_("\nBalance: {:.3} Nano\n").format(Decimal(current_balance) / Decimal(raw_in_xrb)))

    r = nano.get_rates()
    if r != "timeout":

        print()
        print(_("NANO Rates"))
        print("- $:",r.json()['NANO']['USD'])
        print("- £:",r.json()['NANO']['GBP'])
        print("- €:",r.json()['NANO']['EUR'])

    if Path(work_dir + '/release/baseq2/pak0.pak').exists() == False or Path(work_dir + '/release/baseq2/players').exists() == False:
        
        f = DownloadDialog(root, work_dir)
        root.wait_window(f.top)

    
    if account == "xrb_33rhi9bp69i5zaftkyiacjmhwqnz1mcnfm9y6mpk8qx4xpht9cs9dzbxb9gb":
        showinfo("NanoQuake", "Error incorrect seed - please delete seedAES.txt and restart NanoQuake")
        sys.exit()


    root.deiconify()
    root.overrideredirect(0)


    w = Label(root, font=('Sans', 10), fg="#F4FAFF", bg="#000034", text=_("Your Game Account: "))
    w.pack(pady=5)


    
    data = 'xrb:' + account
    xrb_qr = pyqrcode.create(data)
    code_xbm = xrb_qr.xbm(scale=4)
    code_bmp = BitmapImage(data=code_xbm)
    code_bmp.config(background="white")
    label = Label(root, image=code_bmp)
    label.pack(pady=5)

    data_string = StringVar()
    data_string.set(account)
    w = Entry(root, textvariable=data_string, justify="center", state="readonly")
    w.config(bd="0", font=('Sans', 10), fg="white", readonlybackground="#000034")
    w.pack()
    w.pack(pady=(5, 10), fill=X)    

    y = Label(root, font=('Sans', 10), fg="#F4FAFF", bg="#000034", text=_("Your Balance: "))
    y.pack()
    if current_balance != "timeout":
        y = Label(root, font=('Sans', 14, 'bold'), fg="white", bg="#000034", text="{:.3} Nano".format(Decimal(current_balance) / Decimal(raw_in_xrb)))
    else:
        y = Label(root, fg="white", bg="#000034", text=_("Timeout"))

    y.pack(pady=(0, 5))

    listbox = Listbox(root, bg="white")
    listbox.pack(fill=BOTH, padx=5, expand=1)


    c = Button(root, text=_("Start Game"), width="12", font=('Sans', 12), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", takefocus=False, command=lambda: thread_startGame(work_dir, account, wallet_seed, index))
    c.pack(pady=(20, 0), ipadx=20)
 
    withdraw = Button(root, text=_("Withdraw All"), width="12", font=('Sans', 12), relief=RIDGE, bd="0", bg="#4a90e2", fg="white", takefocus=False, command=lambda: withdrawAllDialog(root, account, index, wallet_seed, listbox))
    withdraw.pack(pady=20, ipadx=20)


    settings = Button(root, font=('Sans', 20), relief=RIDGE, bd="0", text=_("⚙"), bg="#000034", fg="#4a90e2", activebackground="#000034", activeforeground="white", takefocus=False, command=lambda: settingsDialog(root, nanoquake_path, wallet_seed))
    settings.place(relx=.88, rely=.01)


#    quit = Button(root, text=_("Exit"), command=exitGame)
#    quit.pack(pady=5)

    tcp = threading.Thread(target=start_server, args=(account, wallet_seed, index, listbox,))
    tcp.daemon = True
    tcp.start()
    
    root.update()

    root.after(5000,lambda: update_txt(root, y, account, wallet_seed, index, listbox))
    root.mainloop()

if __name__ == "__main__":

    main()
