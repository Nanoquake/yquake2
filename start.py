import random, getpass
from configparser import SafeConfigParser
from simplecrypt import encrypt, decrypt
import pyqrcode
from nano25519 import ed25519_oop as ed25519
from pyblake2 import blake2b
import binascii, time
from subprocess import Popen, PIPE
import io
from modules import nano

raw_in_xrb = 1000000000000000000000000000000.0


def follow(thefile):
    thefile.seek(0,2) # Go to the end of the file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1) # Sleep briefly
            continue
        yield line

def display_qr(account):
    data = 'xrb:' + account
    xrb_qr = pyqrcode.create(data, encoding='iso-8859-1')
    print(xrb_qr.terminal())

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
        plaintext = decrypt(password, ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    with open(filename, 'wb') as output:
        ciphertext = encrypt(password, plaintext)
        output.write(ciphertext)

print("Starting Nanoquake2")

parser = SafeConfigParser()
config_files = parser.read('config.ini')

while True:
    password = getpass.getpass('Enter password: ')
    password_confirm = getpass.getpass('Confirm password: ')
    if password == password_confirm:
        break
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

display_qr(account)
print("This is your game account address: {}".format(account))

previous = nano.get_previous(str(account))
pending = nano.get_pending(str(account))
#print(previous)

if (len(previous) == 0) and (len(pending) == 0):
    print("Please send at least 0.1Nano to this account")
    print("Waiting for funds...")
    wait_for_reply(account)
else:
    print('You already have enough balance, great!')

pending = nano.get_pending(str(account))
if (len(previous) == 0) and (len(pending) > 0):
    print("Opening Account")
    nano.open_xrb(int(index), account, wallet_seed)

print("Rx Pending: ", pending)
pending = nano.get_pending(str(account))
print("Pending Len:" + str(len(pending)))

while len(pending) > 0:
    pending = nano.get_pending(str(account))
    print(len(pending))
    nano.receive_xrb(int(index), account, wallet_seed)

print("Starting Quake2")
game_args = "+set nano_address {} +set vid_fullscreen 0".format(account[4:])
print(game_args) 
full_command = "release/quake2 " + game_args
print(full_command)

process = Popen(["release/quake2", game_args, "&"], stdout=PIPE, encoding='utf8', shell=True)

f = open('/Users/jamescoxon/.yq2/baseq2/qconsole.log')
loglines = follow(f)

for line in loglines:
    print (line)
 
print("Done")
