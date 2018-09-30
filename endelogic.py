# Imports required for the program

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import threading
import os
import bcrypt

class EncrypterDecrypter:
    # Constructor of the class
    def __init__(self, file_loc, k):
        self.stop_all_thread = False
        self.general_error = False
        self.file_loc = file_loc
        self.percent_complete = 0
        self.op_running = True
        self.pass_mismatch = False
        self.block_size = 16
        self.error_msg = ''
        self.updateKeyFileLoc(self.file_loc, k)

    # Function to update the file location and key
    # and cipher object whenever the user encrypts or decrypts
    def updateKeyFileLoc(self, file_loc, k):
        self.file_loc = file_loc
        self.key_and_iv = self.createKeyAndIV(k)
        self.cipher = AES.new(self.key_and_iv[0], AES.MODE_CBC, self.key_and_iv[1])
        self.op_running = True
        self.pass_mismatch = False
        self.percent_complete = 0
        self.general_error = False

    # Create Key and IV for encryption and decryption using the key provided by the user
    def createKeyAndIV(self, key):
        keyarr = bytearray(key, 'UTF-8')
        if len(keyarr) < 32:
            diff = 32 - len(keyarr)
            i = 32 - diff
            while i < 32:
                keyarr.append(2)
                i += 1
        iv = bytearray(16)
        i = 0
        while i < 16:
            iv[i] = keyarr[i]
            i += 1
        key_and_iv = [keyarr, iv]
        return key_and_iv

    # Create file extension for encryption
    def _createEncryptFileExtn(self):
        return self.file_loc + '.crypto256'

    # Create file extension for decryption
    def _createDecryptFileExt(self):
        return self.file_loc.replace('.crypto256', '')

    # Thread to encrypt the file
    def encrypt(self):
        try:
            with open(self.file_loc, 'rb') as ifile:
                with open(self._createEncryptFileExtn(), 'ab') as ofile:
                    read_length = 5242880
                    total_file_size = os.path.getsize(self.file_loc)
                    size_processed = 0
                    c = ifile.read(read_length)
                    hash_pw = bcrypt.hashpw(bytes(self.key_and_iv[0]), bcrypt.gensalt(12))
                    ofile.write(hash_pw)
                    self.op_running = True
                    while c != b'' and (not self.stop_all_thread):
                        size_processed += len(c)
                        if len(c) % self.block_size == 0:
                            ofile.write(self.cipher.encrypt(c))
                        else:
                            print('padding done')
                            ofile.write(self.cipher.encrypt(pad(c, self.block_size)))

                        self.percent_complete = (size_processed/total_file_size) * 100
                        c = ifile.read(read_length)
                    self.op_running = False
        except IOError as io:
            self.general_error = True
            self.error_msg = io
        except Exception as ex:
            self.general_error = True
            self.error_msg = ex

    # Thread to decrypt the file
    def decrypt(self):
        try:
            with open(self.file_loc, 'rb') as ifile:
                with open(self._createDecryptFileExt(), 'ab') as ofile:
                    read_length = 5242880
                    total_file_size = os.path.getsize(self.file_loc)
                    size_processed = 0
                    hash_pw = ifile.read(60)
                    size_processed += len(hash_pw)
                    if bcrypt.checkpw(bytes(self.key_and_iv[0]), hash_pw):
                        self.pass_mismatch = False
                        c = ifile.read(read_length)
                        self.op_running = True
                        while c != b'' and (not self.stop_all_thread):
                            size_processed += len(c)
                            if len(c) % read_length == 0:
                                ofile.write(self.cipher.decrypt(c))
                            else:
                                try:
                                    ofile.write(unpad(self.cipher.decrypt(c), self.block_size))
                                except:
                                    ofile.write(self.cipher.decrypt(c))
                            self.percent_complete = (size_processed/total_file_size) * 100
                            c = ifile.read(read_length)
                        self.op_running = False
                    else:
                        self.pass_mismatch = True
                        self.op_running = False
        except IOError as io:
            self.general_error = True
            self.error_msg = io
        except Exception as ex:
            self.general_error = True
            self.error_msg = ex

    # Method to start the thread for encryption
    def startEncryption(self):
        threading.Thread(target=self.encrypt).start()

    # Method to start the thread for decryption
    def startDecryption(self):
        threading.Thread(target=self.decrypt).start()

    # Method for deleting if the encryption decryption went wrong
    def delFile(self):
        os.remove(self._createDecryptFileExt())



