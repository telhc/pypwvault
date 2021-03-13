import sys
import base64
import os
import bcrypt
import numpy as np
import pandas as pd

if os.name == 'nt':
    from msvcrt import getch
else:
    from getch import getch

from datetime import datetime

from io import StringIO

from cryptography.fernet import Fernet

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

KEY_PATH = "key.key"
SAVE_PATH = "saves.save"
CSV_PATH = "pw.csv"
SALT_LEN = 29
KEY_LEN = 44
HASHED_PW_LEN = 60
IV_LEN = 16

CSV_COLS = ["Acc", "Pw", "...", "Date"]

EXIT = 0
READ = 1
ENTR = 2
DELT = 3
EDIT = 4
IMPT = 6
EXPT = 7
WIPE = 99

ESC = b'\x1b'
BKSPC = b'\x08'
NULL = b'\xe0'

"""
key.key contains:
	salt(29)
	encrypted_fnet_key(44)
	hashed_pw(60)
	IV(16)

idea:
master auth:
	hashed_pw = bcrypt.hashpw(master_pw + salt + encrypted_fnet_key, salt)

encypted_fnet_key = encrypt_fnet_key(master_pw, key)

use decrypted fnet key to save to saves.save
"""

# todo key.key path pick
def setup():
	print("Running setup...")
	while (True):
		master_pw = input("create master password: ").encode()
		conf = input("confirm master password: ").encode()
		if master_pw == conf:
			break
		input("mismatch, try again...")
		clear()

	salt = bcrypt.gensalt()

	fnet_key = Fernet.generate_key()

	IV = Random.new().read(AES.block_size)
	encrypted_fnet_key = encrypt_fnet_key(master_pw, fnet_key, IV)

	combo_pw = master_pw + salt + encrypted_fnet_key

	hashed_pw = bcrypt.hashpw(combo_pw, salt)

	with open(KEY_PATH, "wb") as file:
		file.write(salt)
		file.write(encrypted_fnet_key)
		file.write(hashed_pw)
		file.write(IV)

	open(SAVE_PATH, "x")

	input("key.key saved, DO NOT REMOVE\nsaves.save written\ndone...")

def clear():
	os.system('cls' if os.name=="nt" else "clear")

def master_auth(encoded_pw_input, key_dict):
	combo_pw_to_auth = encoded_pw_input + key_dict['salt'] + key_dict['encrypted_fnet_key']
	hashed_pw_check = bcrypt.hashpw(combo_pw_to_auth, key_dict['salt'])	

	return key_dict['hashed_pw'] == hashed_pw_check

def read_key_file(key_file):
	key_dict = {}
	with open(key_file, "rb") as file:
		key_dict['salt'] = file.read(SALT_LEN)
		key_dict['encrypted_fnet_key'] = file.read(KEY_LEN)
		key_dict['hashed_pw'] = file.read(HASHED_PW_LEN)
		key_dict['IV'] = file.read(IV_LEN)
	return key_dict

def encrypt_fnet_key(master_pw, fnet_key, IV):
	key = SHA256.new(master_pw).digest()	
	encryptor = AES.new(key, AES.MODE_CFB, IV)
	return encryptor.encrypt(fnet_key)

def decrypt_fnet_key(master_pw, IV, encrypted_fnet_key):
	key = SHA256.new(master_pw).digest()
	decryptor = AES.new(key, AES.MODE_CFB, IV)
	return decryptor.decrypt(encrypted_fnet_key)

def get_fcryptor(master_pw, key_dict):
	encrypted_fnet_key = key_dict['encrypted_fnet_key']
	fnet_key = decrypt_fnet_key(master_pw, key_dict['IV'], encrypted_fnet_key)
	return Fernet(fnet_key)

def decrypt_save_file(master_pw, key_dict, save_file):
	Fdecryptor = get_fcryptor(master_pw, key_dict)

	with open(save_file, "rb") as file:
		encrypted_entries = file.read()

	if encrypted_entries == b'':
		return ""

	decrypted_csv_string = Fdecryptor.decrypt(encrypted_entries)

	return decrypted_csv_string.decode()

def get_savefile_df(master_pw, key_dict, save_file, fillna=True):

	decrypted_csv_string = decrypt_save_file(master_pw, key_dict, save_file)

	if decrypted_csv_string == "":
		return pd.DataFrame(columns=CSV_COLS)

	if fillna:
		return pd.read_csv(StringIO(decrypted_csv_string)).fillna("")
	else:
		return pd.read_csv(StringIO(decrypted_csv_string))

def get_confirm(msg):
	try:
		return True if input(msg)[0].lower()=='y' else False
	except IndexError:
		return False

def make_entry(master_pw, key_dict, save_file):
	input_fields = {"Account": None, "Password": None, "Details": None}
	cancel = False

	while not cancel:
		clear()
		print("Making an Entry... (Esc to cancel)\n")
		for field in input_fields:
			entry = escable_input(field+": ")
			if entry == ESC:
				cancel = True
				break
			else:
				input_fields[field] = entry

		if not cancel and get_confirm("Confirm? (Y/n) "):
			break

	input_fields['Date'] = datetime.now()

	new_df = pd.DataFrame([list(input_fields.values())], columns = CSV_COLS)

	if not cancel:
		append_df_to_savefile(master_pw, new_df, key_dict, save_file)
		print("\nInserted")
		print(new_df)		
		input("\ndone...")
		return
	
def append_df_to_savefile(master_pw, new_df, key_dict, save_file):
	Fencryptor = get_fcryptor(master_pw, key_dict)

	df = get_savefile_df(master_pw, key_dict, save_file)

	csv_string = StringIO()

	df.append(new_df).to_csv(csv_string, index=False)

	encoded_entries = csv_string.getvalue().encode()

	encrypted_entries = Fencryptor.encrypt(encoded_entries)

	with open(save_file, "wb") as file:
		file.write(encrypted_entries)

def escable_input(msg, s="", i=0):
	s = str(s)
	print(msg, end=s)
	sys.stdout.flush()
	# s = ""
	# i = 0
	while True:
		c = getch()
		if os.name != "nt":
			c = c.encode()                    

		if c == NULL:
			c = getch()
			if os.name != "nt":
				c = c.encode()

			if c == b'K': # left arrow
				if i!=0:
					sys.stdout.write('\b')
					i -= 1
			elif c == b'M': # right arrow
				if len(s)>i:
					sys.stdout.write(s[i])			
					i += 1
			elif c == b'S':	# delete
				if len(s)>i:
					s2 = '' if len(s)==i+1 else s[i+1:]
					sys.stdout.write(s2 + ' \b' + '\b'*len(s2))
					s = s[:i] + s2
			elif c == b'G': # home
				sys.stdout.write('\b'*len(s[:i]))
				i = 0
			elif c == b'O': # end
				sys.stdout.write(s[i:])
				i = len(s)
			sys.stdout.flush()
			continue

		elif c == ESC:
			return ESC
		elif c == b'\r' or c == b'\n':
			print()
			sys.stdout.flush()
			return s
		elif c == BKSPC:
			if i!=0:
				sys.stdout.write('\b' + s[i:] + ' \b' + '\b'*len(s[i:]))
				sys.stdout.flush()
				s = s[:i-1] + s[i:]
				i -= 1
		else:
			sys.stdout.write(c.decode() + s[i:] + '\b'*len(s[i:]))		
			sys.stdout.flush()
			s = s[:i] + c.decode() + s[i:]
			i += 1

def escable_int_input(msg):	
	while True:
		i = escable_input(msg)
		if i == ESC:
			return ESC
		try:
			return int(i)
		except ValueError:
			print("Please Enter a Number...")			
			pass

def export_to_csv(master_pw, key_dict, save_file):
	if not get_confirm("EXPORTING IS DANGEROUS, PROCEED? (Y/n) "):
		return
	df = get_savefile_df(master_pw, key_dict, save_file)
	df.to_csv(CSV_PATH, sep='\t', index=True)

def import_from_csv(master_pw, key_dict, save_file, csv_file):
	df = pd.read_csv(csv_file, sep='\t', index_col=0)
	append_df_to_savefile(master_pw, df, key_dict, save_file)
	input("Imported")

def wipe_save(save_file, noconf=False):
	if noconf or get_confirm("ARE YOU SURE YOU WANT TO WIPE SAVES.SAVE? (Y/n) "):
		with open(SAVE_PATH, "wb") as file:
			file.write(b'')
		return None if noconf else input("wiped")
	else:
		return input("cancelled")

def get_op():
	ops = [READ, ENTR, DELT, EDIT, IMPT, EXPT, WIPE, EXIT]
	ops = [str(i) for i in ops]
	while True:
		op = input("Select option:\n1) Read\n2) Insert\n3) Delete\n4) Edit\n6) Import\n7) Export\n99) Wipe\n0) Exit\n~ ")
		if op in ops:
			return int(op)
		clear()

def get_row(df, operation):
	if len(df)==0:
		input("\nNo Entries to {}".format(operation))
		return ESC
	
	while True:
		i = escable_int_input("\nSelect Entry to {}: ".format(operation))
		if i == ESC:
			return ESC
		if i < 0 or i >= len(df):
			print("\nInvalid Row to {}...".format(operation))
			continue
		return i

def delete_menu(master_pw, key_dict, save_file):	
	while True:
		df = get_savefile_df(master_pw, key_dict, save_file)
		clear()
		print("Delete Menu (Esc to Cancel)\n")
		print_df(df, nodate=False)
		
		i = get_row(df, "Delete")
		if i == ESC:
			return ESC

		if not get_confirm("\nDelete Entry {}? (Y/n) ".format(i)):
			continue

		print("\nDeleted\n")
		print(df.iloc[i].to_frame().T)
		df = df.drop(i)
		wipe_save(save_file, noconf=True)
		append_df_to_savefile(master_pw, df, key_dict, save_file)
		input("...")

def format_df_date(df):
	ret_df = df.copy()
	dates = df["Date"]
	for i, date in enumerate(dates):
		date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f")
		date = date.strftime("%d/%m/%y %H%M")
		ret_df["Date"][i] = date
	return ret_df

def print_df(df, nodate=True, modes=False):
	if modes:
		while True:
			clear()
			print(format_df_date(df))
			print("\nSorting by Index")
			if escable_input("\nEnter (cycle)\tEsc (end)...") == ESC:
					return
			for c in CSV_COLS:				
				clear()
				print(format_df_date(df.sort_values(c)))
				print("\nSorting by {}".format(c))						
				if escable_input("\nEnter (cycle)\tEsc (end)...") == ESC:
					return

	if len(df) == 0:
		print("No Entries Yet...")
		return
	if nodate:
		print(df[CSV_COLS[:-1]])
	else:
		print(df)


def edit_menu(master_pw, key_dict, save_file):
	df = get_savefile_df(master_pw, key_dict, save_file)

	while True:
		clear()
		print("Edit Menu (Esc to Cancel)\n")
		print_df(df, nodate=False)
		
		i = get_row(df, "Edit")
		if i == ESC:
			return ESC

		entries = df.iloc[i]
		new_entries = []

		for j, entry in enumerate(entries):
			if j == 3:
				new_entry = datetime.now()
			else:				
				new_entry = escable_input("{}: ".format(CSV_COLS[j]), s=entry, i=len(str(entry)))

			if new_entry == ESC:
				break
			else:
				new_entries.append(new_entry)

		if new_entry == ESC:
			continue

		if get_confirm("Write new changes? (Y/n) "):
			df.iloc[i] = new_entries
			wipe_save(save_file, noconf=True)
			append_df_to_savefile(master_pw, df, key_dict, save_file)
			input("done...")


def get_user_input(master_pw):
	clear()

	key_dict = read_key_file(KEY_PATH)

	op = get_op()

	# todo
	# sortsave swap entries func

	if op == READ:
		df = get_savefile_df(master_pw, key_dict, SAVE_PATH)
		print_df(df, modes=True)		
	elif op == ENTR:
		make_entry(master_pw, key_dict, SAVE_PATH)		
	elif op == DELT:
		delete_menu(master_pw, key_dict, SAVE_PATH)
	elif op == EDIT:
		edit_menu(master_pw, key_dict, SAVE_PATH)
	elif op == WIPE:
		wipe_save(SAVE_PATH)		
	elif op == EXPT:
		export_to_csv(master_pw, key_dict, SAVE_PATH)
	elif op == IMPT:
		# todo csvpath input cleaning
		target_csv = input("Enter csv path to import: ")
		import_from_csv(master_pw, key_dict, SAVE_PATH, target_csv)

	return get_user_input(master_pw) if op!=EXIT else EXIT

def authenticate():
	key_dict = read_key_file(KEY_PATH)

	while (True):		
		master_pw = input("Enter Master Password: ").encode()		
		if master_auth(master_pw, key_dict):
			break
		print("wrong pw")

	return master_pw

def main():
	# first setup
	if not os.path.exists(KEY_PATH):
		setup()
	
	master_pw = authenticate()	
	
	get_user_input(master_pw)

	input("Exiting...")


if __name__ == "__main__":
	main()


