# Authors: Filippo Dolente & Angelo Carbone
# 2020-12-05
# ver 1.1

# *----------------Import---------------*#
import math
import os
import signal
import sqlite3
import time
import database
import scan_file
import insert_input

# *----------------Header---------------*#

print("_____________________________________________________")
print("Welcome to Uannacrai Antivirus 1.1v\n\nAuthors:\n Filippo Dolente & Angelo Carbone")
print("_____________________________________________________\n")

print("REMEMBER: press 'CTRL+C' to pause execution and take a coffee\n\n")

# *----------------Constants---------------*#

# AES encrypted file containing the hash key and the IV
KEY_FILE = "ckey.txt"
MINUTE = 60

# *----------------Global Variables---------------*#

# Contains the seconds of "pause" taken
global pauset

# True if program should terminate
global exit_c
exit_c = False

# True if a pause is called
global pause_called
pause_called = False


# *----------------Functions---------------*#

def handler(signum, frame):
    """This function handles the interrupt event,
    the user can decide to terminate the program by writing 'quit'
    or resume execution by pressing 'enter'"""

    spause_time = time.time()
    print("press 'quit' to exit or press 'enter' to resume the execution...")
    inp = input()
    bpause_time = time.time()
    if inp == "quit":
        database.close_conn()
        global exit_c
        exit_c = True
    else:
        global pause_called
        pause_called = True
        global pauset
        # Calculate the time spent on break
        pauset = bpause_time-spause_time

# *----------------Main---------------*#

# Set the signal handler
signal.signal(signal.SIGINT, handler)

# Check the existence of the database and file with the private key
if database.check_db():
    if not os.path.exists(KEY_FILE):
        print("File with key does not exists")
        exit(-1)

    print("DataBase found.. insert Private Key")

    pk = input()
    # Check private key strength
    private_key = insert_input.check_size_key(pk)

    # Key checking
    stop = True
    while stop:
        try:
            # Raise ValueError if AES can't decrypt file
            stored_key_and_iv = insert_input.decrypt_file(KEY_FILE, private_key)
            stop = False
        except ValueError:
            # Remove all permissions on the file if it failed to decrypt it
            insert_input.deny_permission()
            print("Invalid key, can't decrypt file, retry:")
            pk = input()
            private_key = insert_input.check_size_key(pk)

    # Check if hash in the file is the same hash of the private key insert by the user
    while not insert_input.check_password(stored_key_and_iv, private_key):
        print("Invalid key")
        pk = input()
        private_key = insert_input.check_size_key(pk)

    # IV: iInizialized Vector for AES algorithm
    iv = insert_input.ret_iv()

    database.get_db(private_key, iv)

else:
    print("No DataBase found. Insert the private key for encryption/decrytpion")
    # Create the file with the private key and the IV
    private_key, iv = insert_input.private_key_input_first()
    database.create_db(private_key, iv)

print("Insert scan frequency in minuts")
frequency = insert_input.frequency_input()*MINUTE

print("Insert absolute path to scan (format C:\\...)")
path_scan = insert_input.path_to_scan()

# -----------------------------------------------------------
# Cycles counter
counter = 1
while not exit_c:
    # Take time
    start = time.time()
    try:
        scan_file.scanning(path_scan)
    except sqlite3.ProgrammingError:
        print("Connection to Database closed...")
        break
    if not pause_called:
        end_time = math.fabs(frequency-(time.time()-start))
    else:
        end_time = math.fabs(frequency-(math.fabs((time.time()-pauset))-start))
        pause_called = False
    if end_time > frequency:
        end_time = frequency
    print("-------- End ",counter, "° scan cycle, I'm waiting for timer... ------")
    counter += 1
    time.sleep(end_time)

# Stop Observer Thread
insert_input.stop_obs()
