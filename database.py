# Authors: Filippo Dolente & Angelo Carbone
# 2020-12-05
# ver 1.1

# Module for database management

# *----------------Imports---------------*#

import os
import sqlite3
import aesencrypt

# *----------------Global Variables and Constants---------------*#

DATABASE_NAME = "uc_db.db"

# connection
global conn
# cursor
global c
# private key
global PK
# Initialization Vector
global iv
# *----------------Functions---------------*#


def check_db():
    """Checks the existence of the database,
    returns True if it exists, False otherwise"""

    return os.path.isfile(DATABASE_NAME)


def set_conn():
    """set the connection with the database and the cursor"""
    global conn
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    global c
    c = conn.cursor()


def set_pk(private_key):
    """set the Private Key variable"""
    global PK
    PK = private_key


def setiv(iv_t):
    """Set the IV"""
    global iv
    iv = iv_t


def create_db(private_key, iv_t):
    """ Create the database for save data"""

    setiv(iv_t)  #set IV
    set_conn()   # set connection

    # Create the table
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (ID INTEGER PRIMARY KEY,path text, hashcode text, timestamp text)''')
    conn.commit()

    set_pk(private_key) # set PK


def get_db(private_key, iv_t):
    """get database"""
    setiv(iv_t)  # Set IV
    set_conn()  # Set connection
    set_pk(private_key)


def encrypt(plaintext, key):
    """encrypt plaintext with AES
    algorithm using key 'key'"""

    return aesencrypt.encrypt(key.encode(), plaintext, iv)


def decrypt(chipertext, key):
    """decrypt chipertext with AES
    algorithm using key 'key'"""

    return aesencrypt.decrypt(key.encode(), iv, chipertext)


def insert_element(element, fresh_hash, timestamp):
    """Inserts an item with its hash
    and timestamp into the database"""

    # encrypt the element
    aes_elem = encrypt(element, PK)
    # encrypt the hash
    aes_fresh_hash = encrypt(fresh_hash,PK)

    # encrypt the timestamp
    timestamp_str = str(timestamp)
    aes_timestamp = encrypt(timestamp_str, PK)

    values = [(aes_elem, aes_fresh_hash,aes_timestamp),
                ]

    # Avoid SQL INJECTION
    c.executemany('INSERT INTO files VALUES (NULL,?,?,?)', values)
    conn.commit()


def return_hash_element(element):
    """Return the hash of the element"""

    cryp_element = encrypt(element, PK)
    old_path = (cryp_element,)
    c.execute('SELECT hashcode FROM files WHERE path=?', old_path)
    old_hash = c.fetchone()
    old_hash_final = decrypt(old_hash[0],PK)

    return old_hash_final


def select_db(element):
    """Returns True if the element passed as
    a parameter is in database, false otherwise"""

    cryp_element = encrypt(element, PK)
    to_take = (cryp_element,)
    c.execute('SELECT * FROM files WHERE path=?', to_take)
    row = c.fetchone()
    if row is not None:
        return True
    else:
        return False


def update_timestamp_element(elem, timestamp):
    """Updates the timestamp of an item in the
    database with the timestamp passed as a parameter"""

    timestamp_str = str(timestamp)
    aes_timestamp = encrypt(timestamp_str, PK)
    aes_elem = encrypt(str(elem), PK)

    values = [(aes_timestamp, aes_elem), ]
    c.executemany('UPDATE files SET timestamp = ? WHERE path=?', values)
    conn.commit()


def update_path_element(old_path, new_path):
    """Update the path of a file if the file has been moved"""

    if select_db(old_path):
        aes_new_path = encrypt(new_path, PK)
        aes_old_path = encrypt(old_path, PK)
        values = [(aes_new_path, aes_old_path)]
        c.executemany('UPDATE files SET path = ? WHERE path = ?', values)
        conn.commit()


def update_hash(elem, new_hash):
    """Update the hash of the item passed as a parameter"""

    aes_new_hash = encrypt(new_hash, PK)
    aes_elem = encrypt(elem, PK)

    values = [(aes_new_hash, aes_elem)]
    c.executemany('UPDATE files SET hashcode = ? WHERE path = ?', values)
    conn.commit()


def return_timestamp(elem):
    """Returns the timestamp of the element passed as a parameter.
     The timestamp indicates the calculation of the hash"""

    cryp_element=encrypt(str(elem), PK)
    path_for_timestamp = (cryp_element,)
    c.execute('SELECT timestamp FROM files WHERE path =?', path_for_timestamp)
    timestamp_taken = c.fetchone()
    timestamp_final = decrypt(timestamp_taken[0], PK)
    return timestamp_final


def close_conn():
    """Close connection to database"""
    c.close()
