from fileinput import close
from random import randbytes
from Crypto.Cipher import Salsa20
import binascii
import sys
import getopt
import csv

import os


def createCryptKey():
    p1 = randbytes(16)
    return p1


def cryptFile(filename, key):
    cipher = Salsa20.new(key)
    blob_data = bytearray()
    with open(filename, "rb") as original_file:
        blob_data = binascii.hexlify(original_file.read())
        close()
    with open(filename, "wb") as original_file:
        cryptFile = cipher.encrypt(blob_data)
        original_file.seek(0)
        original_file.write(cryptFile)
        original_file.truncate()
    return cipher.nonce


def decryptFile(filename, key):
    blob_data = bytearray()
    with open(filename, "rb") as original_file:
        blob_data = binascii.hexlify(original_file.read())
        close()
    with open(filename, "wb") as original_file:
        cryptFile = cipher.encrypt(blob_data)
        original_file.seek(0)
        original_file.write(cryptFile)
        original_file.truncate()


def get_filepaths(directory):

    file_paths = []
    for root, directories, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)
    return file_paths  # Self-explanatory.


def main(argv):
    header = ['Filename', 'Key', 'Nonce']

    folderToCrypt = r""
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile="])
    except getopt.GetoptError:
        print("cryptop-soc.py -i <folderToCrypt>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("cryptop-soc.py -i <path to folder without \"\">")
            sys.exit()
        elif opt in ("-i", "--filetocrypt"):
            folderToCrypt = arg

    print("Input file is {}\n".format(folderToCrypt))
    with open('./decrypt_data.csv', 'w', encoding='UTF8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header)
        for f in get_filepaths(folderToCrypt):
            key = createCryptKey()
            nonce = cryptFile(f, key)
            print("Encrypted:")
            print("\tFilename:{}\n\tKey:{}\n\tNonce:{}\n".format(f, key, nonce))
            writer.writerow([f, key, nonce])
    csv_file.close()


if __name__ == "__main__":
    main(sys.argv[1:])
