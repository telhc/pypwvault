# Python Password Vault

A python password saver capable of encrypting and keeping any account details.

![](/images/pypwmanmenu.png)

## Features
- Authentication and encryption using a master password
- Simple editing
- Encryption using fernet
- Saving entries with (Account, Password, Description)
- Supports importing and exporting to CSV file format (not recommended)

## How to use it
Simply download pypwman.py and run it to start vaulting!

## How it works
On pypwman.py's first execution, it will run a setup and prompt for the creation of a master password.  
*Note*: If you forget your master password, you will **not** be able to retrieve the passwords you store in the future.
After the setup, it will create two files (**key.key** & **saves.save**) in the same directory, they will store 
your encrypted master password and keys to decrypt saves.save so **do not delete** them.

## Encryption Method
The setup generates a Fernet key and encrypts it with a SHA256 key generated uniquely using the master password.  
A salt is also generated and the encrypted Fernet key is stored in the key.key file.  
The SHA256 key (generated from masterpw) that is used to decrypt the encrypted Fernet key is not stored for obvious reasons.  
Instead, the hash of the combination of masterpw+salt+encrypted_fernet_key is stored for the validation of the correct master password.  
The decrypted Fernet key is used to encrypt the entries that the user inputs and saved to saves.save (saves.save is in a csv format when decrpyted with the Fernet key)
