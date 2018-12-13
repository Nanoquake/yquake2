import time, json, random

import binascii
from bitstring import BitArray
from hashlib import blake2b
from nano25519 import ed25519_oop as ed25519
import ctypes, requests

representative = 'xrb_1kd4h9nqaxengni43xy9775gcag8ptw8ddjifnm77qes1efuoqikoqy5sjq3'

def private_public(private):
    return ed25519.SigningKey(private).get_verifying_key().to_bytes()


def xrb_account(address):
    # Given a string containing an XRB address, confirm validity and
    # provide resulting hex address
    if len(address) == 64 and (address[:4] == 'xrb_'):
        # each index = binary value, account_lookup[0] == '1'
        account_map = "13456789abcdefghijkmnopqrstuwxyz"
        account_lookup = {}
        # populate lookup index with prebuilt bitarrays ready to append
        for i in range(32):
            account_lookup[account_map[i]] = BitArray(uint=i ,length=5)

        # we want everything after 'xrb_' but before the 8-char checksum
        acrop_key = address[4:-8]
        # extract checksum
        acrop_check = address[-8:]

        # convert base-32 (5-bit) values to byte string by appending each
        # 5-bit value to the bitstring, essentially bitshifting << 5 and
        # then adding the 5-bit value.
        number_l = BitArray()
        for x in range(0, len(acrop_key)):
            number_l.append(account_lookup[acrop_key[x]])
        # reduce from 260 to 256 bit (upper 4 bits are never used as account
        # is a uint256)
        number_l = number_l[4:]

        check_l = BitArray()
        for x in range(0, len(acrop_check)):
            check_l.append(account_lookup[acrop_check[x]])

        # reverse byte order to match hashing format
        check_l.byteswap()
        result = number_l.hex.upper()

        # verify checksum
        h = blake2b(digest_size=5)
        h.update(number_l.bytes)
        if (h.hexdigest() == check_l.hex):
            return result
        else:
            return False
    else:
        return False


def account_xrb(account):
    # Given a string containing a hex address, encode to public address
    # format with checksum
    # each index = binary value, account_lookup['00001'] == '3'
    account_map = "13456789abcdefghijkmnopqrstuwxyz"
    account_lookup = {}
    # populate lookup index for binary string to base-32 string character
    for i in range(32):
        account_lookup[BitArray(uint=i ,length=5).bin] = account_map[i]
    # hex string > binary
    account = BitArray(hex=account)

    # get checksum
    h = blake2b(digest_size=5)
    h.update(account.bytes)
    checksum = BitArray(hex=h.hexdigest())

    # encode checksum
    # swap bytes for compatibility with original implementation
    checksum.byteswap()
    encode_check = ''
    for x in range(0 ,int(len(checksum.bin ) /5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_check += account_lookup[checksum.bin[ x *5: x * 5 +5]]

    # encode account
    encode_account = ''
    while len(account.bin) < 260:
        # pad our binary value so it is 260 bits long before conversion
        # (first value can only be 00000 '1' or 00001 '3')
        account = '0b0' + account
    for x in range(0 ,int(len(account.bin ) /5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_account += account_lookup[account.bin[ x *5: x * 5 +5]]

    # build final address string
    return 'xrb_' +encode_account +encode_check


def seed_account(seed, index):
    # Given an account seed and index #, provide the account private and
    # public keys
    h = blake2b(digest_size=32)

    seed_data = BitArray(hex=seed)
    seed_index = BitArray(int=index ,length=32)

    h.update(seed_data.bytes)
    h.update(seed_index.bytes)

    account_key = BitArray(h.digest())
    return account_key.bytes, private_public(account_key.bytes)


def receive_xrb(index, account, wallet_seed):
    # Get pending blocks

    rx_data = get_pending(str(account))
    if len(rx_data) == 0:
        return

    for block in rx_data:
        #print(block)
        block_hash = block
        #print(rx_data[block])
        balance = int(rx_data[block]['amount'])
        source = rx_data[block]['source']

    previous = get_previous(str(account))

    current_balance = get_balance(previous)
    if current_balance == 'timeout':
        return 'timeout'
    #print(current_balance)
    new_balance = int(current_balance) + int(balance)
    hex_balance = hex(new_balance)
    #print(hex_balance)
    hex_final_balance = hex_balance[2:].upper().rjust(32, '0')
    #print(hex_final_balance)

    priv_key, pub_key = seed_account(wallet_seed, int(index))
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    # print("Starting PoW Generation")
    work = get_pow(previous)
    if work == 'timeout':
        return 'timeout'
    # print("Completed PoW Generation")

    # Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex='0x0000000000000000000000000000000000000000000000000000000000000006').bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)
    bh.update(BitArray(hex=previous).bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)
    bh.update(BitArray(hex=hex_final_balance).bytes)
    bh.update(BitArray(hex=block_hash).bytes)

    sig = ed25519.SigningKey(priv_key +pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')

    finished_block = '{ "type" : "state", "previous" : "%s", "representative" : "%s" , "account" : "%s", "balance" : "%s", "link" : "%s", \
            "work" : "%s", "signature" : "%s" }' % \
    (previous, account, account, new_balance, block_hash, work, signature)

    data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"process", "block" : finished_block}, timeout=1)
    block_reply = data.json()
    return block_reply, balance


def get_address(index, wallet_seed):
    # Generate address
    print("Generate Address")
    priv_key, pub_key = seed_account(wallet_seed, int(index))
    public_key = str(binascii.hexlify(pub_key), 'ascii')
    print("Public Key: ", str(public_key))

    account = account_xrb(str(public_key))
    print("Account Address: ", account)
    return account

def get_rates():
    try:
        r = requests.get('https://min-api.cryptocompare.com/data/pricemulti?fsyms=NANO&tsyms=USD,EUR,GBP&extraParams=nanoquake', timeout=3)
        print("Querying CryptoCompare for fiat rates")
        return r
    except requests.exceptions.Timeout:
        print("Error: Timeout")
        return "timeout"


def open_xrb(index, account, wallet_seed):
    # Get pending blocks

    rx_data = get_pending(str(account))
    for block in rx_data:
        #print(block)
        block_hash = block
        #print(rx_data[block])
        balance = int(rx_data[block]['amount'])
        source = rx_data[block]['source']

    hex_balance = hex(balance)
    #print(hex_balance)
    hex_final_balance = hex_balance[2:].upper().rjust(32, '0')
    #print(hex_final_balance)

    priv_key, pub_key = seed_account(wallet_seed, int(index))
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    # print("Starting PoW Generation")
    work = get_pow(str(public_key, 'ascii'))
    # print("Completed PoW Generation")

    # Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex='0x0000000000000000000000000000000000000000000000000000000000000006').bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)
    bh.update(BitArray(hex='0x0000000000000000000000000000000000000000000000000000000000000000').bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)
    bh.update(BitArray(hex=hex_final_balance).bytes)
    bh.update(BitArray(hex=block_hash).bytes)

    sig = ed25519.SigningKey(priv_key + pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')

    finished_block = '{ "type" : "state", "previous" : "0000000000000000000000000000000000000000000000000000000000000000", "representative" : "%s" , "account" : "%s", "balance" : "%s", "link" : "%s", \
            "work" : "%s", "signature" : "%s" }' % (account, account, balance, block_hash, work, signature)
    
    data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"process", "block" : finished_block}, timeout=1)
    block_reply = data.json()
    return block_reply, balance


def send_xrb(dest_account, amount, account, index, wallet_seed):

    previous = get_previous(str(account))

    current_balance = get_balance(previous)
    #print(current_balance)
    new_balance = int(current_balance) - int(amount)
    hex_balance = hex(new_balance)

    #print(hex_balance)
    hex_final_balance = hex_balance[2:].upper().rjust(32, '0')
    #print(hex_final_balance)

    priv_key, pub_key = seed_account(wallet_seed, int(index))
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    # print("Starting PoW Generation")
    work = get_pow(previous)
    # print("Completed PoW Generation")

    # Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex='0x0000000000000000000000000000000000000000000000000000000000000006').bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)
    bh.update(BitArray(hex=previous).bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)
    bh.update(BitArray(hex=hex_final_balance).bytes)
    bh.update(BitArray(hex=xrb_account(dest_account)).bytes)

    sig = ed25519.SigningKey(priv_key + pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')

    finished_block = '{ "type" : "state", "previous" : "%s", "representative" : "%s" , "account" : "%s", "balance" : "%s", "link" : "%s", \
            "work" : "%s", "signature" : "%s" }' % (
    previous, account, account, new_balance, dest_account, work, signature)

    data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"process", "block" : finished_block}, timeout=1)
    block_reply = data.json()
    return block_reply['hash']


def get_pow(hash):
    data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"work_generate", "hash" : hash}, timeout=10)
    #ws = create_connection('ws://yapraiwallet.space:8000')
    #data = json.dumps({'action': 'work_generate', 'hash': hash})
    #ws.send(data)
    #block_work = json.loads(str(ws.recv()))
    block_work = data.json()
    work = block_work['work']
    #ws.close()

#    work = ''
#    while work == '' :
#      try:   
#        json_request = '{"hash" : "%s" }' % hash
#        print(json_request)
#        print("Generating PoW via Work Server")
#        r = requests.post('http://178.62.11.37/work', data = json_request)
#        rx = r.json()
#        work = rx['work']
#      except:
#        pass

#    lib=ctypes.CDLL("./libmpow.so")
#    lib.pow_generate.restype = ctypes.c_char_p
#    work = lib.pow_generate(ctypes.c_char_p(hash.encode("utf-8"))).decode("utf-8")
#    print(work)

    return work


def get_previous(account):
    # Get account info
    accounts_list = [account]
    try:
        data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"accounts_frontiers", "accounts" : accounts_list}, timeout=1)
    except requests.exceptions.Timeout:
        print("Error: Timeout")
        return "timeout"

    account_info = data.json()

    if len(account_info['frontiers']) == 0:
        return ""
    else:
        previous = account_info['frontiers'][account]
        return previous


def get_balance(hash):
    # Get balance from hash
    try:
        data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"block", "hash" : hash}, timeout=1)
    except requests.exceptions.Timeout:
        print("Error: Timeout")
        return "timeout"

    rx_data = data.json()
    if "error" in rx_data:
        return ""
    else:
        new_rx = json.loads(str(rx_data['contents']))
        return new_rx['balance']

def get_account_balance(account):
    # Get balance from hash
    try:
        data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"account_balance", "account" : account}, timeout=1)
    except requests.exceptions.Timeout:
        print("Error: Timeout")
        return "timeout"

    rx_data = data.json()
    #print(rx_data)
    if "error" in rx_data:
        return ""
    else:
        #new_rx = json.loads(str(rx_data['contents']))
        return rx_data['balance']

def get_pending(account):
    try:
        data = requests.post('https://yapraiwallet.space/quake/api', json = {"action":"pending", "count" : "1", "account" : account, "source" : "true"}, timeout=1)
    except requests.exceptions.Timeout:
        print("Error: Timeout")
        return "timeout"

    rx_data = data.json()

    return rx_data['blocks']
