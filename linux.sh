#!/usr/bin/env python3
import argparse
import requests
import json
import os
import base64
from os.path import expanduser
import csv
#https://github.com/ricmoo/pyaes
import pyaes
import getpass
#https://github.com/ricmoo/pyscrypt
import pyscrypt
from datetime import date,datetime

now = datetime.now()

def cleanupFileList():
	home = expanduser("~")
	file = home + "/.linux.sh"
	lines=""
	try:
		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				expires = row[2]
				expires = datetime.strptime(expires,"%Y-%m-%d %H:%M:%S")
				if now > expires:
					print("File Expired: %s" % (row[1]))
				else:
					linux_sh_file = '"%s","%s","%s","%s","%s"\r\n'%(row[0],row[1],row[2],row[3],row[4])
					lines = lines + linux_sh_file
		file = open(file,"w");
		file.write(lines)
	except:
		print("No .linux.sh script")


parser = argparse.ArgumentParser(description='Send some files to Linux.sh for safe keeping')
parser.add_argument("--upload", help="Set File to Upload")
parser.add_argument("--ls", action="store_true",help="List Uploaded Files",default=False)
parser.add_argument("--cleanup", action="store_true",help="Cleanup The Upload File",default=False)
parser.add_argument("--encrypt", action="store_true",help="Perform Local File Encryption",default=False)
parser.add_argument("--meta", help="Fetch File Metadata (json Returned)")
parser.add_argument("--rm", help="Remove a File")
parser.add_argument("--download", help="Download a file")
parser.add_argument("--tor", action="store_true",help="Use Tor Proxy, See README.md",default=False);
parser.add_argument("--exportshare", help="Get A Filesharing code");
parser.add_argument("--importshare", help="Import A File Sharing Code");
parser.add_argument("--socksport", help="Socks Port For TOR Or Whatever (default 9050)");
parser.add_argument("--socksip", help="Socks IP Address (default 127.0.0.1)");
args = parser.parse_args()
proxies = {}
base_url="https://linux.sh/"
socksport=9050
socksip="127.0.0.1"

if args.socksip:
	socksip=args.socksip

if args.socksport:
	socksport=args.socksport

if args.tor:
	proxies={'http':'socks5h://'+socksip+':'+socksport}
	base_url="http://7b42twezybs23hrr.onion/"

if args.exportshare:
	cleanupFileList()
	home = expanduser("~")
	file = home + "/.linux.sh"
	with open(file, 'rt') as csvfile:
		csvreader = csv.reader(csvfile)
		for row in csvreader:
			if row[1] == args.exportshare:
				response = requests.post(base_url+'share.php',proxies=proxies,data={'filename':args.exportshare,'control':row[3],'encrypted':row[4]})
				parsed_json = json.loads(response.content)
				print ("Share Name: %s" % (parsed_json['share']))
				found=True
	if not found:
		print("File Not Found")

if args.importshare:
	cleanupFileList()
	home = expanduser("~")
	file = home + "/.linux.sh"
	base64 = base64.b64decode(args.importshare)
	line = base64.decode("utf-8")
	f = open(file, 'ab')
	f.write(line.encode())
	f.write("\r\n".encode())
	cleanupFileList()

if args.upload:
	if os.path.getsize(args.upload) > 10485760:
		print("File Size is too large, limit is 10MB")
		quit()
	home = expanduser("~")
	ufile = args.upload
	encrypt_file=""
	upload_filename = os.path.basename(args.upload)
	encrypted=0
	if args.encrypt:
		pass1 = getpass.getpass("Enter Password: ")
		pass2 = getpass.getpass("Reenter Password: ")
		if (pass1 != pass2):
			print("Password Mismatch")
			quit()
		key = pass1.encode()
		#key = b"1234"
		salt= b":&\WRdDv6'MvK{8C"
		N = 1024
		r = 1
		p = 1
		key_32 = pyscrypt.hash(key, salt, N, r, p, 32)
		mode = pyaes.AESModeOfOperationCTR(key_32)
		filename_w_ext = os.path.basename(ufile)
		ufile = home + "/" + filename_w_ext + ".aes"
		print(args.upload)
		file_in = open(args.upload,'rb')
		file_out = open(ufile, 'wb')
		print("Encrypting File: %s This will take awhile if the file is big"%(args.upload))
		pyaes.encrypt_stream(mode, file_in, file_out)
		print("Uploading File: %s "%(args.upload))
		file_in.close()
		file_out.close()
		encrypt_file=ufile
		encrypted=1
	response = requests.post(base_url+'upload.php', proxies=proxies, files={'file': (upload_filename, open(ufile, 'rb'), 'application/octet-stream', {'Expires': '0'})})
	if response.status_code != 200:
		print("Error Uploading File")
		quit()
	parsed_json = json.loads(response.content)
	print ("File Uploaded")
	print ("Original Filename: %s" % (parsed_json['filename']['OriginalFileName']))
	print ("Uploaded Filename: %s" % (parsed_json['filename']['UploadFilename']))
	print ("File Expires: %s" % (parsed_json['filename']['UploadExpires']))
	print ("File Hash: %s" % (parsed_json['filename']['UploadHash']))
	print ("File Hash After Upload: %s" % (parsed_json['filename']['UploadHashAfterEncryption']))
	home = expanduser("~")
	file = home + "/.linux.sh"
	linux_sh_file = '"%s","%s","%s","%s","%s"\r\n'%(parsed_json['filename']['OriginalFileName'],parsed_json['filename']['UploadFilename'],parsed_json['filename']['UploadExpires'],parsed_json['filename']['UploadControlKey'],encrypted)
	if encrypt_file != "":
		os.remove(encrypt_file)
	try:
		cleanupFileList()
	except:
		print("Linux.sh config file not found, creating it")

	f = open(file,"a")
	f.write(linux_sh_file)
if args.ls:
	cleanupFileList()
	print("Currently Uploaded Files")
	home = expanduser("~")
	file = home + "/.linux.sh"
	with open(file, 'rt') as csvfile:
		csvreader = csv.reader(csvfile)
		for row in csvreader:
			print("Filename: %s, Upload Filename: %s, File Expires: %s" % (row[0],row[1],row[2]))

if args.cleanup:
	cleanupFileList()
if args.meta:
	cleanupFileList()
	home = expanduser("~")
	file = home + "/.linux.sh"
	found = False
	try:
		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				if row[1] == args.meta:
					response = requests.post(base_url+'meta.php',proxies=proxies,data={'filename':args.meta,'control':row[3]})
					print(response.content)
					found=True
		if not found:
			print("File Not Found")

	except Exception as e:
		print(e)

if args.rm:
	cleanupFileList()
	home = expanduser("~")
	file = home + "/.linux.sh"
	found = False
	lines=""
	try:
		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				if row[1] == args.rm:
					response = requests.post(base_url+'rm.php',proxies=proxies,data={'filename':args.rm,'control':row[3]})
					found=True
		if not found:
			print("File Not Found")
		else:
			with open(file, 'rt') as csvfile:
				csvreader = csv.reader(csvfile)
				for row in csvreader:
					if row[1] != args.rm:
						linux_sh_file = '"%s","%s","%s","%s"\r\n'%(row[0],row[1],row[2],row[3],row[4])
						lines = lines + linux_sh_file

			file = open(file,"w");
			file.write(lines)
	except Exception as e:
		print(e)
if args.download:
	cleanupFileList()
	home = expanduser("~")
	file = home + "/.linux.sh"
	found = False
	content = ""
	password = ""
	encrypted = 0
	try:
		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				if row[1] == args.download:
					filename = row[0]
					if str(row[4]) == "1":
						password=getpass.getpass("Enter File Encryption Password: ")
						encrypted=1

		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				if row[1] == args.download:
					response = requests.post(base_url+'download.php',proxies=proxies, data={'filename':args.download,'control':row[3]})
					if encrypted:
						salt=b":&\WRdDv6'MvK{8C"
						N = 1024
						r = 1
						p = 1
						key_32 = pyscrypt.hash(password.encode(), salt, N, r, p, 32)
						mode = pyaes.AESModeOfOperationCTR(key_32)

						content = mode.decrypt(response.content)
					else:
						content = response.content

					file = open(filename,'wb')
					file.write(content)
					found=True
		if not found:
			print("File Not Found")

	except Exception as e:
		print(e)
