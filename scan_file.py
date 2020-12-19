# Authors: Filippo Dolente & Angelo Carbone
# 2020-12-05
# ver 1.1

# Module for scanning management

# *----------------Imports---------------*#

import os
import platform
import threading
import winsound
import database
import hashlib
import logging
import ctypes
from datetime import datetime


# *----------------Global Variables and Constants---------------*#

# Create the log file
LOG_FILE = "logfile.log"
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(message)s')

# The size of each read from the file (64kb)
BLOCK_SIZE = 65536

# *----------------Functions---------------*#


def calculate_hash(element):
    """Calculate and return the hash with SHA256 algorithm
    of the element passed as parameter"""

    # If the file has not been opened for reading,
    # file_skipped will be True and the hash will not be returned
    file_skipped = False

    # create the hash object
    file_hash = hashlib.sha256()

    try:
        with open(element, 'rb') as f:   # open the file to read it's bytes
            fb = f.read(BLOCK_SIZE)
            while len(fb) > 0:           # while there is still data being read from the file
                file_hash.update(fb)     # update the hash
                fb = f.read(BLOCK_SIZE)  # read the next block from the file
    except:
        print("A file is skipped because it's open by another program")
        file_skipped = True

    if file_skipped:
        return -1
    else:
        # Print the hash
        print("Hash: ", file_hash.hexdigest())
        return file_hash.hexdigest()


def compare_hash(hash1, hash2):
    """Compare two hashes,
    if they are equal it returns True,
    False otherwise"""

    str_hash1 = str(hash1)
    str_hash2 = str(hash2)

    if str_hash1 != str_hash2:
        return False
    else:
        return True


def alert_box(path):
    """Create an alert window indicating in which file
    the anomalous event was detected"""

    message = "file " + str(path) + " changed"
    ctypes.windll.user32.MessageBoxW(0, message, "Anomalous event detected", 0x00001000)


def log_delete(filename):
    """writes the 'file deleted' event to the log file"""
    logging.info('FILE-DELETED: \n \t%s\n', filename)


def log_moved(filename1, filename2):
    """writes the 'file moved' event to the log file"""
    logging.info('FILE-MOVED: \n \t%s -- to: %s\n', filename1, filename2)


def log_renamed(oldname, newname):
    """writes the 'file renamed' event to the log file"""
    logging.info('FILE-RENAMED: \n \t%s -- to: %s\n', oldname, newname)


def send_alert(old_correct_timestamp,fresh_hash,old_hash,elem,now):
    """writes the anomalous event to the log file.
    Also emits an alert sound and calls the alert_box function to launch an alert window."""

    logging.info('ANOMALOUS EVENT %s:\n \tpath: %s -\n \told-hash: %s - \n \tnew-hash: %s - \n \tLatest correct timestamp: %s\n',now,elem,old_hash,fresh_hash,old_correct_timestamp)

    # BEEP sound
    if platform.system() == 'Windows':
        duration = 1000  # milliseconds
        freq = 440  # Hz
        winsound.Beep(freq, duration)
    elif platform.system() == 'Linux' | 'Mac':
        duration = 1  # seconds
        freq = 440  # Hz
        os.system('play -nq -t alsa synth {} sine {}'.format(duration, freq))

    # Alert window in a separate Thread to avoid blocking the main execution
    thread = threading.Thread(target=alert_box, args=(elem,))
    thread.start()


def scanning(path_scan,):
    """Scan the files in 'path_scan'.
    For each file with the extension exe, bat, vb, sh, bin
    the hash is calculated and inserted into a database,
    updating the timestamp at each cycle and comparing the hash"""

    for root, dirs, files in os.walk(path_scan):
        for file in files:
            if file.endswith(".exe" or ".bat" or ".vb" or ".sh" or ".bin"):
                print("File analyzed: ", os.path.join(root, file))

                # elem contains the path of the file
                elem = os.path.join(root, file)
                # fresh_hash contains the hash of elem
                fresh_hash = calculate_hash(elem)

                if fresh_hash != -1:  # the file was read correctly and the hash was calculated by the function

                    # current date and time
                    now = datetime.now()
                    timestamp = datetime.timestamp(now)

                    if not database.select_db(elem):
                        database.insert_element(elem, fresh_hash, timestamp)
                    else:
                        # else executed if the item was already in the database

                        # retrieve the hash saved in the database
                        old_hash = database.return_hash_element(elem)
                        # Compare the hash just calculated with the hash in the database
                        hash_val = compare_hash(fresh_hash, old_hash)

                        if hash_val:
                            database.update_timestamp_element(elem, timestamp)
                        else:
                            # else executed if the two hashes are different (anomaly found)
                            now_time = datetime.now()
                            old_correct_timestamp = database.return_timestamp(elem)

                            # the hash in the database is updated otherwise
                            # the same anomaly is identified at each scan cycle
                            database.update_hash(elem, fresh_hash)
                            database.update_timestamp_element(elem, now_time)

                            # Record the alert in the log file
                            send_alert(old_correct_timestamp, fresh_hash, old_hash, elem,now_time)
