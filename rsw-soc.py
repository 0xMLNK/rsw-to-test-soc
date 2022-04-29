import os
import sys
import csv
import time
import psutil
import getopt
import binascii
import win32api
import win32process
import ctypes as c
from fileinput import close
from random import randbytes
from ctypes import wintypes as w
from Cryptodome.Cipher import Salsa20


def get_filepaths(directory):
    file_paths = []
    for root, directories, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)
    return file_paths


def generate_crypto_key():
    p1 = randbytes(16)
    return p1


def encrypt_single_file(filename, key):
    cipher = Salsa20.new(key)
    with open(filename, "rb") as original_file:
        blob_data = binascii.hexlify(original_file.read())
        close()
    with open(filename, "wb") as original_file:
        crypt_file = cipher.encrypt(blob_data)
        original_file.seek(0)
        original_file.write(crypt_file)
        original_file.truncate()
    return cipher.nonce


def encrypt_files_in_path(argv):
    header = ['Filename', 'Key', 'Nonce']

    folder_to_crypt = r""
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile="])
    except getopt.GetoptError:
        print("cryptop-soc.py -i <folder_to_crypt>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("cryptop-soc.py -i <path to folder without \"\">")
            sys.exit()
        elif opt in ("-i", "--filetocrypt"):
            folder_to_crypt = arg

    print("All data in {} will be encrypted\n".format(folder_to_crypt))
    with open('./decrypt_data.csv', 'w', encoding='UTF8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header)
        for f in get_filepaths(folder_to_crypt):
            key = generate_crypto_key()
            nonce = encrypt_single_file(f, key)
            print("Encrypted:")
            print("\tFilename:{}\n\tKey:{}\n\tNonce:{}\n".format(f, key, nonce))
            writer.writerow([f, key, nonce])
    print("\tDecryption information was saved in {}\n".format(csv_file))
    csv_file.close()


def decrypt_singe_file(filename, key):
    print("TODO")


def get_pid_by_name(process_name):
    my_pid = None
    pids = psutil.pids()
    for pid in pids:
        ps = psutil.Process(pid)
        if process_name in ps.name():
            my_pid = ps.pid

    process_all_access = 0x1F0FFF
    process_handle = win32api.OpenProcess(process_all_access, False, my_pid)
    modules = win32process.EnumProcessModules(process_handle)
    process_handle.close()
    base_addr = modules[0]
    print("TEST_2:"
          "\n\tProcess Name: {}"
          "\n\tProcess PID: {}"
          "\n\tProcess Base Address: {}".format(process_name, my_pid, base_addr))

    return my_pid, base_addr, process_name


def read_process_memory_test():
    process_info_arr = get_pid_by_name("notepad.exe")
    process_id = int(process_info_arr[0])
    process_header_addr = process_info_arr[1]
    process_name = process_info_arr[2]
    strlen = 255
    process_vm_read = 0x0010

    k32 = c.WinDLL('kernel32', use_last_error=True)

    open_process = k32.OpenProcess
    open_process.argtypes = w.DWORD, w.BOOL, w.DWORD
    open_process.restype = w.HANDLE

    read_process_memory = k32.ReadProcessMemory
    read_process_memory.argtypes = w.HANDLE, w.LPCVOID, w.LPVOID, c.c_size_t, c.POINTER(c.c_size_t)
    read_process_memory.restype = w.BOOL

    close_handle = k32.CloseHandle
    close_handle.argtypes = [w.HANDLE]
    close_handle.restype = w.BOOL

    process_handle = open_process(process_vm_read, 0, process_id)
    print("\tTEST_2: Process Handel: " + str(process_handle))
    buffer = c.create_string_buffer(strlen)
    size = c.c_size_t()
    if k32.ReadProcessMemory(process_handle, process_header_addr, buffer, strlen, c.byref(size)):
        print("\tTEST_2: READ PROCESS MEMORY RESULT:\t\t\nSTRLEN: {}\t\t\nBINARY OUTPUT: {}".format(size.value, buffer.raw))
        close_handle(process_handle)

    else:
        print("Could'n read {} process memory.".format(process_name))
        close_handle(process_handle)


def main(argv):
    path_to_programm = r"C:\Windows\System32\notepad.exe"
    print("TEST_1: Crypting files in {}\n".format(argv))
    encrypt_files_in_path(argv)
    print("TEST_2: Read process memory from {}".format(path_to_programm))
    os.startfile(path_to_programm)
    time.sleep(1)
    read_process_memory_test()


if __name__ == "__main__":
    main(sys.argv[1:])
