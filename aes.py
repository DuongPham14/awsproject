import os, sys, io
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from array import array

def encrypt(message, key):
    #While loop to catch keys that are shorter than 32 bytes
        while (len(key) < 32):
            try:
                raise Exception('ValueError')
            except Exception as error:
                print ("This key is", 32-len(key), "characters short")
                sys.exit(0)    
    #Converting string key and message into bytes
        bytekey = bytes(key, 'utf-8')
        bytemessage = bytes(message, 'utf-8') 
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_bytemessage = padder.update(bytemessage)
        padded_bytemessage += padder.finalize()
    #Generate IV from system's random generator       
        iv = os.urandom(16)
    #Creating an AES CBC cipher
        cipher = Cipher(algorithms.AES(bytekey), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_bytemessage) + encryptor.finalize()
        return ct, iv

def decrypt(eMessage, iv, key):
    #Converting key into byte version
        bytekey = bytes(key, 'utf-8')
    #Re-creating cipher based on key and IV
        cipher = Cipher(algorithms.AES(bytekey), modes.CBC(iv), default_backend())
    #Decrypting based on cipher
        decryptor = cipher.decryptor()
    #Outputting the original message
        originalByteMessage = decryptor.update(eMessage) + decryptor.finalize()
    #Creating an unpadder
        unpadder = padding.PKCS7(128).unpadder()
    #Removing padding from byte message
        data = unpadder.update(originalByteMessage)
        originalUnpaddedMessage = data + unpadder.finalize()
    #Converting back to string
        originalMessage = originalUnpaddedMessage.decode('utf-8')
        return originalMessage

def MyfileEncrypt(filepath):
    #Open file as a byte array
        with open(filepath, "rb") as f:
            byte_array = bytearray(f.read())
            byte_Astring = bytes(byte_array)
    #Generating key and iv
        key = os.urandom(32)
        iv = os.urandom(16)
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_BAstring = padder.update(byte_Astring)
        padded_BAstring += padder.finalize()
    #Creating AES CBC cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_BAstring) + encryptor.finalize()
        with open(filepath, 'wb') as outfile:
            outfile.write(iv)
            outfile.write(ct)
 #Getting file extension
        ext = filepath[-4:]
        return ct, iv, key, ext 

def MyfileDecrypt(ct, iv, key, saveFilepath):
    #Re-creating cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Creating decryptor
        decryptor = cipher.decryptor()
    #Decrypt file to byte array
        originalByteFile = decryptor.update(ct) + decryptor.finalize()
    #Removing padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(originalByteFile)
        originalUnpaddedString = data + unpadder.finalize()
    #Saving picture to specified location
        f = open(saveFilepath, "wb")
        f.write(bytearray(originalUnpaddedString))
        f.close()

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    #Opening file as a byte array
        with open(filepath, "rb") as f:
            byte_array = bytearray(f.read())
            byte_Astring = bytes(byte_array)
    #Generating key and iv
        key = os.urandom(32)
        iv = os.urandom(16)
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_BAstring = padder.update(byte_Astring)
        padded_BAstring += padder.finalize()
    #Creating AES CBC cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_BAstring) + encryptor.finalize()
        ext = filepath[-4:]
    #Reading the key and creating a public key
        with open(RSA_Publickey_filepath, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                default_backend()
            )
    #Creating a cipher for cipher key
        RSACipher = public_key.encrypt(
            key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label = None
            )
        )
        with open(filepath, 'wb') as outfile:
            outfile.write(iv)
            outfile.write(ct)
            outfile.write(RSACipher)
        return RSACipher, ct, iv, ext

def MyRSADecrypt(RSACipher, ct, iv, ext, RSA_Privatekey_filepath, saveFilepath):
    #Reading the key and creating a private key
        with open(RSA_Privatekey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend = default_backend()
            )
    #Decrypting the cipher key with the private key
        key = private_key.decrypt(
            RSACipher,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    #Re-creating cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Creating decryptor
        decryptor = cipher.decryptor()
    #Decrypting file to byte array
        originalByteFile = decryptor.update(ct) + decryptor.finalize()
    #Removing padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(originalByteFile)
        originalUnpaddedString = data + unpadder.finalize()
    #Saving picture to specified location
        f = open(saveFilepath, "wb")
        f.write(bytearray(originalUnpaddedString))
        f.close()
