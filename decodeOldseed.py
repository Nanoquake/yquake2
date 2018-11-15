from Crypto.Cipher import DES
from prompt_toolkit import prompt

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        des = DES.new(password.encode('utf-8'), DES.MODE_ECB)
        plaintext = des.decrypt(ciphertext)
        if len(plaintext) != 64:
            print("Error - empty seed, please delete your seed.txt and config.ini")
            sys.exit()
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext


while True:
        password = prompt('Enter password: ', is_password=True)
        password_confirm = prompt('Confirm password: ', is_password=True)
        if password == password_confirm and len(password) == 8:
            wallet_seed = read_encrypted(password, 'seed.txt', string=True)
            print("Your Wallet Seed is {}".format(wallet_seed))
            break
        if len(password) != 8:
            print("Please enter a password of EXACTLY 8 characters (due to the use of DES to encrypt)")
        else:
            print("Password Mismatch!")
