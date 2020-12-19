# Authors: Filippo Dolente & Angelo Carbone
# 2020-12-05
# ver 1.1

# Module for input management

# *----------------import---------------*#

import os
import hashlib
import uuid
import pyAesCrypt
import subprocess
import platform
from Crypto import Random
from Crypto.Cipher import AES
import re
import database
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import scan_file

# *----------------Global Variables and Constants---------------*#


KEY_FILE = "ckey.txt"

# unencrypted file with the private key hash
HASH_KEY = "hashkey.txt"

# for the 'open' to read file KEY_FILE
FILE_PATH = r'ckey.txt'

# file for save temporarily the hash of key and the iv
KEY = "key.txt"

# all special symbols
regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')

SIX_HOUR = 360
MINUTE = 60
MINIMUM_LENGHT_KEY = 8
key_bytes = 32
bufferSize = 64 * 1024


global deleted_file
global path_deleted_file
global created_file
global observer
deleted_file = 'd'
created_file = 'e'

# *----------------Setter and Getter---------------*#


def set_iv(iv_t):
    """Set the IV"""
    global iv
    iv = iv_t


def ret_iv():
    """Return the IV"""
    return iv

# *----------------Class---------------*#


class movehandler(FileSystemEventHandler):

  """overriding the on_moved, on_deleted on_created methods"""

  # file deleted
  def on_deleted(self, event):
    global deleted_file
    global path_deleted_file
    deleted_file = str(event.src_path)
    path_deleted_file = str(event.src_path)
    # Take name file
    deleted_file = deleted_file.rsplit('\\', 1)[1]

  # file renamed
  def on_moved(self, event):
    print("File renamed, check logfile")
    # Update namefile (path) in the database
    database.update_path_element(event.src_path, event.dest_path)
    # Report event in logfile
    scan_file.log_renamed(event.src_path,event.dest_path)

  # file created
  def on_created(self, event):
    global created_file
    global deleted_file
    global path_deleted_file
    created_file = str(event.src_path)
    # Take name file
    created_file = created_file.rsplit('\\',1)[1]
    if created_file == deleted_file:
        # Moved file
        print("File moved, check logfile")
        scan_file.log_moved(path_deleted_file, created_file)
        database.update_path_element(deleted_file,created_file)
        # Assign insignificant values to global variables, to reset environment
        created_file = 'a'
        deleted_file = 'b'
        path_deleted_file = 'c'

# *----------------Functions---------------*#


def pad_key(pk):
    """Add space values to complete the 32 bytes 'pk' key"""

    pad_size = key_bytes - len(pk) % key_bytes

    # Add missing bytes with 'white spaces'
    fit_text = pk + (" " * pad_size)

    return str(fit_text)


def calculate_hash_and_iv(key):
    """Calculates the hash value of the key and
    the Initialization Vector for the AES"""

    # uuid is used to generate a random number
    salt = uuid.uuid4().hex

    # Calculate the IV for AES algorithm
    iv_t = Random.new().read(AES.block_size)
    set_iv(iv_t)

    return hashlib.sha256(salt.encode() + key.encode()).hexdigest() + ':' + salt + '###' + iv_t.hex()


def check_password(hashed_password, user_password):
    """Split the file with the hash, salt and IV
    and retrieve the IV, also check that the key
    hash has not changed.
    Returns true if the keys are the same, false otherwise"""

    password, salt_iv = hashed_password.split(':')
    salt, iv_t = salt_iv.split('###')
    set_iv(bytearray.fromhex(iv_t))

    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()


def allow_permission():
    """Grants read, write and execute
    permissions to the file with the key"""

    if platform.system() == 'Linux':
        os.chmod(KEY_FILE, 777)
    elif platform.system() == 'Windows':
        subprocess.check_output(['icacls.exe', FILE_PATH, '/grant', 'everyone:(F)'], stderr=subprocess.STDOUT)


def deny_permission():
    """Deny read, write and execute
    permissions to the file with the key"""

    if platform.system() == 'Linux':
        os.chmod(KEY_FILE, 000)
        pass
    elif platform.system() == 'Windows':
        subprocess.check_output(['icacls.exe', FILE_PATH, '/deny', 'everyone:(F)'], stderr=subprocess.STDOUT)


def frequency_input():
    """Retrieves the scan frequency value"""

    frequency = input()

    # Check on Input type
    stop = True
    while stop:
        try:
            val = float(frequency)
            stop = False
        except ValueError:
            print("No.. input is not a number")
            print("Insert scan frequency in minutes")
            frequency = input()
    if val > SIX_HOUR:
        print("Value too high, frequency set to: 1h")
        val = MINUTE
    return val


def crypt_file(key, filename):

    """Encrypt file with AES 32-bytes key algorithm"""

    pyAesCrypt.encryptFile(filename, KEY_FILE, key, bufferSize)
    # Delete file not encrypted:
    try:
        os.remove(filename)
    except OSError as e:
        print("Error: %s : %s" % (filename, e.strerror))

    deny_permission()


def decrypt_file(filename, password):
    """Decrypt file with AES 32-bytes key algorithm
    and write the value in HASH_KEY.
    Once the key has been read, the file is deleted"""

    allow_permission()
    pyAesCrypt.decryptFile(filename, HASH_KEY, password, bufferSize)
    deny_permission()

    f = open(HASH_KEY, 'r')
    hash_key = f.read()
    f.close()

    try:
        os.remove(HASH_KEY)
    except OSError as e:
        print("Error: %s : %s" % (HASH_KEY, e.strerror))

    return hash_key


def private_key_input_first():
    """Function that is performed only the first time the
    program is opened and there is no database. The function
    checks the robustness of the key, calls the function to
    calculate the hash and the IV, and writes them to a file.
    Finally it encrypts the file with AES algorithm"""

    # Check key strength and length
    stop = True
    while stop:
        pk = input()
        valid_key = check_size_key(pk)
        if not valid_pk(valid_key):
            print("Invalid key")
        else:
            print("key it's ok!")
            stop = False

    hash_key_and_iv = calculate_hash_and_iv(valid_key)

    #Save key and IV
    f = open(KEY, 'w+')
    f.write(hash_key_and_iv)
    f.close()
    crypt_file(valid_key, KEY)

    return valid_key, iv


def stop_obs():
    """Close the thread with the observer"""
    observer.stop()


def path_to_scan():
    """Retrieves the absolute path on which
    to perform the integrity check"""

    path_scan = input()
    while not os.path.isdir(path_scan):
        print("The path does not exists, retry...")
        path_scan = input()

    # Start the Watchdog, an observer on changes on files in the path
    event_handler = movehandler()
    global observer
    observer = Observer()
    observer.schedule(event_handler, path_scan, recursive=True)
    observer.start()

    return path_scan


def valid_pk(pk):
    """Validation PRIVATE KEY"""
    valid = True

    if len(pk) < MINIMUM_LENGHT_KEY:
        print("Required key with at least 8 characters")
        valid = False

    if not any(char.isdigit() for char in pk):
        print('A key with at least one numeric character is required')
        valid = False

    if not any(char.isupper() for char in pk):
        print('A key with at least one capital letter is required')
        valid = False

    if not any(char.islower() for char in pk):
        print('Required key with at least one lowercase letter')
        valid = False

    if regex.search(pk) is None:
        print('Required key with at least one special character')
        valid = False
    return valid


def check_size_key(pk):
    """Check the length of the key, and complete it to 32 bytes"""

    if len(pk) > key_bytes:
        print("key too long, truncked till 32-bytes, the new key is: ")
        private_key = pk[0:32]
        print(private_key)
    else:
        # key too short, padding till 32-bytes
        private_key = pad_key(pk)

    return private_key
