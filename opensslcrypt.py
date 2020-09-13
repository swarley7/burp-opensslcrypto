from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
# from exceptions_fix import FixBurpExceptions
import re
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import SecretKeySpec
import binascii
import time

from hashlib import md5
from hashlib import sha256

from java.util import Base64

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

# This encryption mode is no longer secure by today's standards.
# See note in original question above.

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def encrypt(payload, key):
    salt = bytearray([1,2,3,4,5,6,7,8])
    k2, iv2 = derive_key_and_iv(key, salt, 32, 16)
    aesKey = SecretKeySpec(k2, "AES")
    aesIV = IvParameterSpec(iv2)
    # print key, binascii.hexlify(salt), binascii.hexlify(k2), binascii.hexlify(iv2), payload, "TESTING - ENCRYPT"

    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIV)
    encrypted = cipher.doFinal(payload)
    out = Base64.getEncoder().encode(b'Salted__' + salt + encrypted)
    # print("DEBUG enc:", out.tostring(), binascii.hexlify(salt), binascii.hexlify(k2), binascii.hexlify(iv2), key)
    return out

# decryptJython uses javax.crypto.Cipher to decrypt payload with key/iv
# using AES/CFB/NOPADDING
def decrypt(payload, key):
    decoded = Base64.getDecoder().decode(payload)
    # print("Lol - decoded: ", decoded)

    if decoded.tostring()[:8] != "Salted__":
        print decoded.tostring()[:8]
        return False
    decoded = decoded[8:]
    
    salt = decoded[:8]
    k2, iv2 = derive_key_and_iv(key, salt, 32, 16)
    # print key, binascii.hexlify(salt), binascii.hexlify(k2), binascii.hexlify(iv2), payload, "TESTING - DECRYPT"
    aesKey = SecretKeySpec(k2, "AES")
    aesIV = IvParameterSpec(iv2)

    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    cipher.init(Cipher.DECRYPT_MODE, aesKey, aesIV)
    return cipher.doFinal(decoded[8:])

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("EncryptedTrash")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        # sys.stdout = callbacks.getStdout()
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return Base64InputTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#




class Base64InputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
        self.pattern = re.compile("(U2FsdGVkX.*)") # // Finds the "Salted__" Openssl signature 
        self.contentLengthpattern = re.compile("X-Content-Length: (\\d+)") # // Finds the "Salted__" Openssl signature 

        self.sigPattern = re.compile("X-Signature: (\\w+)\r\n") # // Finds the "Salted__" Openssl signature 
        self.timePattern = re.compile("X-Request-Time: (\\d+)")# // Gets the timestamp - used to construcct the passphrase
        self.encHeaderPattern = re.compile("X-Content-Encoding: enc")# // Finds the enc type content encoding     #
        self.the_stuffing_request = b""

    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Serialized input"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        self.the_stuffing_request = content.tostring()
        # print self.the_stuffing_request
        # print self.encHeaderPattern.search(self.the_stuffing_request), "True????"
        if self.encHeaderPattern.search(self.the_stuffing_request) is not None:
            ciphertext = self.pattern.search(self.the_stuffing_request)
            if ciphertext is not None:
                # print(ciphertext.groups()[0])
                return True
            return False
        return False
        # enable this tab for requests containing a data parameter
        
    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            # retrieve the data parameter
            parameter = self.pattern.search(self.the_stuffing_request).groups()[0]
            passphrase = "anonymous-" + str(self.timePattern.search(self.the_stuffing_request).groups()[0])
            decrypted = decrypt(parameter, passphrase)
            # print ("Lol, ", decrypted)
            # deserialize the parameter value
            self._txtInput.setText(decrypted)
            self._txtInput.setEditable(self._editable)
        
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the deserialized data
        if self._txtInput.isTextModified():
            # reserialize the data
            text = self._txtInput.getText()
            # print text.tostring()
            updatetime = str(int(time.time()) * 1000)
            passphrase = "anonymous-" + updatetime
            encrypted = encrypt(text.tostring(), passphrase) 
            input_ = encrypted.tostring()
            
            # update the request with the new parameter value
            req = self.pattern.sub(input_, self.the_stuffing_request)
            x = text.tostring() + "-" + passphrase + "-" + str(len(text))
            len_header = "X-Content-Length: " + str(len(text))
            sig= "X-Signature: " + sha256(x).hexdigest() + "\r\n"
            timeHeader= "X-Request-Time: " + updatetime
            # print (sig , x)
            req = self.sigPattern.sub(sig, req)
            req = self.contentLengthpattern.sub(len_header, req)
            req = self.timePattern.sub(timeHeader, req)
            
            #self.the_stuffing_request = req # update req - not sure if this is even necessary; stuff jython / burp
            return req
            
        else:c
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()

# FixBurpExceptions()