import json
import os
import sys
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from getpass import getpass



       
       
       
       
       


def ask_cred(key):
    
    
    site = input("Enter site : ")
    username = input("Enter username : ")
    password= getpass("Enter Password: ").encode()
    nonce = os.urandom(12)
    
    
        
    
    
    
    chacha=ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce,password,associated_data=None)
    
    
    
    
    users={
        
        
        "site":site,
        "username":username,
        "password":ciphertext.hex(),
        "nonce":nonce.hex(),
         
    }
    
    
    cred_entry(users)

def cred_entry(users):
    

    if os.path.exists("creds.json"):
    
        with open ("creds.json","r",encoding="utf-8") as f :
            
            try:
                data = json.load(f)
            
            except Exception as e:
                print("Error occured")
                data=[]
    
    else:
        data=[]
    

    data.append(users)
    with open("creds.json","w",encoding="utf-8") as f :
        
        json.dump(data,f,indent=4)
   
            
    print("User saved succesfully")
    
    
def cred_delete(key):
    
    site_del=input("Enter site to delete : ")
    
    if os.path.exists("creds.json"):
    
        with open ("creds.json","r",encoding="utf-8") as f :
            
            try:
                data = json.load(f)
            
            except Exception as e:
                print("Error occured")
                
                data=[]
    
    else:
        data=[]
    
    original_len = len(data)
    
    data=[user for user in data if user["site"]!=site_del]
    if original_len > len(data):
        with open("creds.json","w",encoding="utf-8") as f :
         
        
        
            json.dump(data,f,indent=4) 
            print(f"Deleted Successfully")
    else:
        print(f"{site_del} not found on database")
    
    
    
def creds_view(key):
    
    site_name = input("Enter site to view : ")
    if os.path.exists("creds.json"):
        
        with open ("creds.json","r",encoding="utf-8") as f :
            
            try:
                
                data = json.load(f)
                for d in data:
                    if site_name.lower() in d['site'].lower():
                        
                        nonce=bytes.fromhex(d["nonce"])
                        password=bytes.fromhex(d["password"])
                        chacha = ChaCha20Poly1305(key)
                        decrypted_password = chacha.decrypt(nonce,password,associated_data=None)
                        
                        try:
                            password_str = decrypted_password.decode("utf-8")
                        except UnicodeDecodeError:
                             password_str = decrypted_password.hex()
                                
                        
                        
                        
                        
                           
                        print(f"username: {d['username']}\nPassword : {password_str} ")
                        break
                    else:
                        print("Credentials not found ")
            except Exception as e:
                print("Error occurred")
                
    else:
        print("file not found")    
                        
                
            
    
    
    
    
def master_password():
        
  
    
    password = getpass("Create your Master Password: ").encode()
    
        

    salt_pass = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_pass,
        iterations=1200000
        )
    
    
        
    key = kdf.derive(password)
    
    chacha = ChaCha20Poly1305(key)
    nonce=os.urandom(12)
    text = "for decryption purpose".encode()
    ciphertext=chacha.encrypt(nonce,text,associated_data=None)
    

    vault_metadata= {
        "salt":salt_pass.hex(),
        "iterations":1200000,
        "algorithm":'SHA256',
        "nonce":nonce.hex(),
        "ciphertext":ciphertext.hex()
        
    }
    
    
    with open("vault_meta.json","w",encoding="utf-8") as f:
        json.dump(vault_metadata,f,indent=4)
    
    
        
        
def user_verification():
    
    entered_password =getpass("Enter your Master Password: ").encode()
    
    
    with open("vault_meta.json","r",encoding="utf-8") as f :
        data = json.load(f)  
        
    salt=bytes.fromhex(data["salt"])
    nonce=bytes.fromhex(data["nonce"])  
    iterations=data["iterations"]
    ciphertext=bytes.fromhex(data["ciphertext"])
        
    kdf =PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1200000
    )
    key=kdf.derive(entered_password) 
    chacha = ChaCha20Poly1305(key)
    try:
        
        decrypted = chacha.decrypt(nonce,ciphertext,associated_data=None)
        if decrypted == b"for decryption purpose":
            print("verification success")
            return key
    except Exception as e:
        print("Verification failed ")
        return False
        
    
 

    

        
def start(key):
    
    
  
    response=input("Add , delete or view  ? ")

    if(response.lower() == 'add'):
        ask_cred(key)
    elif response.lower() == 'view':
        creds_view(key)
    else:
        cred_delete(key)     
     
     
     
def intital_check():
    
    if os.path.exists("vault_meta.json"):
        key = user_verification()
        
        if key:
            start(key)
        
    else:
        master_password()
        locker()
        key = user_verification()
        if key:
            start(key)
    
    
    


    
intital_check()
    
    
