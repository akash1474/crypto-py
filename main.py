import base64
import os
import argparse
import math
from getpass import getpass
from colorit import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def Crypto():
	password=getpass(prompt="Key: ")
	salt=b"\xae\xd5\xcfj\xd1\xad\ry'\x0fm\xd6>\xf4\xad\x9d"
	kdf=PBKDF2HMAC(
		algorithm=hashes.SHA512(),
		length=32,# affects the size
		salt=salt,
		iterations=37689,
		backend=default_backend()
		)
	gen_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	return Fernet(key=gen_key)

init_colorit()

def ui_update(string):
    sys.stdout.write(f'{string}\r')
    sys.stdout.flush()

def print_msg_box(msg, indent=1, width=None, title=None):
    """Print message-box with optional title."""
    lines = msg.split('\n')
    space = " " * indent
    if not width:
        width = max(map(len, lines))
    box = f'╔{"═" * (width + indent * 2)}╗\n'.center(os.get_terminal_size()[0])  # upper_border
    if title:
        box += f'║{space}{title:<{width}}{space}║\n'  # title
        box += f'║{space}{"-" * len(title):<{width}}{space}║\n'  # underscore
    box += ''.join([f'║{space}{color(line,Colors.orange):<{width}}{space}║\n' for line in lines])
    box += f'╚{"═" * (width + indent * 2)}╝'.center(os.get_terminal_size()[0])  # lower_border
    print(box)

def draw_line(char="-",center=False):
	if(center and len(char)==1):
		count=int(os.get_terminal_size()[0]//2)
		print((char*count).center(os.get_terminal_size()[0]))
	elif(len(char)==1):
		print(char*os.get_terminal_size()[0])
	else:
		raise f"{char} should be of length 1"


def show_doc():
	print_msg_box("crypto v0.1.2")
	# print(color("crypto v0.1.1".center(os.get_terminal_size()[0]),Colors.orange))
	print(color("Documentation:",Colors.green))
	print("   »",color("--encrypt/-e:",Colors.blue),"Encrypting the file")
	print("   »",color("--decrypt/-d:",Colors.blue),"Decrypting the file")
	print("   »",color("--all:",Colors.blue),"Selecting all files in current dir")
	print("   »",color("--file/-f:",Colors.blue),"To provide a file")
	print("   »",color("--files/-fls:",Colors.blue),"To select multiple files")
	print("   »",color("--doc/-i:",Colors.blue),"Show Documentation\n")
	print(color(" ☼",Colors.red),color("Encrypting and Decrypting a file",Colors.yellow))
	print("   Encrypting »",color("crypto -e -f file.ext",Colors.orange))
	print("   Decrypting »",color("crypto -d -f file.ext\n",Colors.orange))
	print(color("\n ☼",Colors.red),color("Encrypting all the file in a folder",Colors.yellow))
	print("   Encrypting »",color("crypto -e --all",Colors.orange))
	print("   Decrypting »",color("crypto -d --all",Colors.orange))
	print(color("\n ☼",Colors.red),color("Encrypting and Decrypting multiple specific file",Colors.yellow))
	print("   Encrypting »",color("crypto -e -fls file1.ext file2.ext filen.ext",Colors.orange))
	print("   Decrypting »",color("crypto -d -fls file1.ext file2.ext filen.ext\n",Colors.orange))

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])

def show_file_stats(file,s1,s2,enc=False):
	print(file,color(convert_size(s1),Colors.orange),color(" » ",Colors.green),color(convert_size(s2),Colors.red))
	print(color(f"{'Encryption' if enc else 'Decryption'} Completed",Colors.purple))

## Body ##
def encrypt(filename,fernet,show_stats=False):
	s1=os.path.getsize(filename)
	s2=0
	with open(filename,'r+b') as f:
		data=f.read()
		enc=fernet.encrypt(data)
		with open(filename,'wb') as enc_file:
			enc_file.write(enc)
			enc_file.close()
		f.close()
		s2=os.path.getsize(filename)

	if(show_stats):
		show_file_stats(filename,s1,s2,enc=True)

	return s2-s1

def decrypt(filename,fernet,show_stats=False):
	s1=os.path.getsize(filename)
	s2=0
	with open(filename,'r+b') as f:
		data=f.read()
		dec=fernet.decrypt(data)
		with open(filename,'wb') as dec_file:
			dec_file.write(dec)
			dec_file.close()
		f.close()
		s2=os.path.getsize(filename)

	if(show_stats):
		show_file_stats(filename,s1,s2)
	return s1-s2

def enc_all(arr=os.listdir()):
	fernet=Crypto()
	print(color("Encrypting Files....",Colors.purple))
	count=0 
	for file in arr:
		try:
			ds=encrypt(file,fernet)
			count+=1
			pr_str="{0} {1:<38} {2}".format(color("Encrypted:  ",Colors.green),color(f"δs={convert_size(ds)}",Colors.orange),file)
			print(pr_str)
			ui_update(color(count,Colors.blue)+" files were encrypted")
		except:
			print(color("Failed:  ",Colors.red),file)
	print(color("Encryption Process Completed",Colors.purple))
	print("---------------------")
	print(color(count,Colors.blue)," files were encrypted")

def dec_all(arr=os.listdir()):
	fernet=Crypto()
	print(color("Decrypting Files....",Colors.purple))
	count=0
	for file in arr:
		try:
			ds=decrypt(file,fernet)
			count+=1
			pr_str="{0} {1:<38} {2}".format(color("Decrypted:  ",Colors.green),color(f"δs=-{convert_size(ds)}",Colors.orange),file)
			print(pr_str)
			ui_update(color(count,Colors.blue)+" files were encrypted")
		except:
			print(color("Failed:  ",Colors.red),file)
	print(color("Decryption Process Completed",Colors.purple))
	print("---------------------")
	print(color(count,Colors.blue)," files were decrypted")



parser = argparse.ArgumentParser()
## arguments ##
parser.add_argument('--encrypt', '-e',action="store_true", dest='encrypt',help="encrypt file")
parser.add_argument('--file','-f',dest="file",help="file name")
parser.add_argument('--decrypt','-d',action="store_true", dest='decrypt',help="logging out of the google drive account")
parser.add_argument('--all',action="store_true", dest='allFiles',help="encrypt all the files")
parser.add_argument('--files','-fls',nargs='*', action='append',dest='files',help="name of file in as list:string")
parser.add_argument('--doc', '-i',action="store_true", dest='document',help="show documentation")
## argument ##
args=parser.parse_args()

if(args.document):
	show_doc()
elif(not args.allFiles and not args.files and args.encrypt and args.file):
	try:
		fernet=Crypto()
		encrypt(args.file,fernet,show_stats=True)
	except:
		print(color("UNKNOW ERROR:",Colors.orange))
		print(color("   » Encryption Failed",Colors.red),args.file)
elif(not args.allFiles and not args.files and args.decrypt and args.file):
	try:
		fernet=Crypto()
		decrypt(args.file,fernet,show_stats=True)
	except:
		print(color("Invalid Key Error:",Colors.orange))
		print("  » ",color("Decryption Failed",Colors.red),args.file)
elif(not args.files and not args.file and args.allFiles and args.encrypt):
	enc_all()
elif(not args.files and not args.file and args.allFiles and args.decrypt):
	dec_all()
elif(not args.allFiles and args.encrypt and args.files):
	enc_all(arr=args.files[0])
elif(not args.allFiles and args.decrypt and args.files):
	dec_all(arr=args.files[0])
else:
	show_doc()
