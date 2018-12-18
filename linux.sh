#!/usr/bin/env python2.7
import argparse
import requests
import json
import os
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


parser = argparse.ArgumentParser(description='Send some files to Linux.sh for safe keeping')
parser.add_argument("--upload", help="Set File to Upload")
parser.add_argument("--ls", action="store_true",help="List Uploaded Files",default=False)
parser.add_argument("--cleanup", action="store_true",help="Cleanup The Upload File",default=False)
parser.add_argument("--encrypt", action="store_true",help="Perform Local File Encryption",default=False)
parser.add_argument("--meta", help="Fetch File Metadata (json Returned)")
parser.add_argument("--rm", help="Remove a File")
parser.add_argument("--download", help="Download a file")
args = parser.parse_args()

if args.upload:
	home = expanduser("~")
	ufile = args.upload
	encrypt_file=""
	upload_filename = os.path.basename(args.upload)
	encrypted=0
	if args.encrypt:
		bufferSize = 64 * 1024
		pass1 = getpass.getpass("Enter Password: ")
		pass2 = getpass.getpass("Reenter Password: ")
		if (pass1 != pass2):
			print("Password Mismatch")
			quit()
		key = pass1
		salt=":&\WRdDv6'MvK{8C"
		N = 1024
		r = 1
		p = 1
		key_32 = pyscrypt.hash(key, salt, N, r, p, 32)
		mode = pyaes.AESModeOfOperationCTR(key_32)
		filename_w_ext = os.path.basename(ufile)
		ufile = home + "/" + filename_w_ext + ".aes"

		file_in = file(args.upload)
		file_out = file(ufile, 'wb')
		print("Encrypting File: %s This will take awhile if the file is big"%(args.upload))
		pyaes.encrypt_stream(mode, file_in, file_out)
		print("Uploading File: %s "%(args.upload))
		file_in.close()
		file_out.close()
		encrypt_file=ufile
		encrypted=1
	response = requests.post('https://linux.sh/upload.php', files={'file': (upload_filename, open(ufile, 'rb'), 'application/octet-stream', {'Expires': '0'})})
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
					response = requests.post('https://linux.sh/meta.php',data={'filename':args.meta,'control':row[3]})
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
					response = requests.post('https://linux.sh/rm.php',data={'filename':args.rm,'control':row[3]})
					found=True
		if not found:
			print("File Not Found")
		else:
			with open(file, 'rt') as csvfile:
				csvreader = csv.reader(csvfile)
				for row in csvreader:
					if row[1] != args.rm:
						linux_sh_file = '"%s","%s","%s","%s"\r\n'%(row[0],row[1],row[2],row[3])
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
	try:
		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				if row[1] == args.download:
					filename = row[0]
					if str(row[4]) == "1":
						password=getpass.getpass("Enter File Encryption Password: ")

		with open(file, 'rt') as csvfile:
			csvreader = csv.reader(csvfile)
			for row in csvreader:
				if row[1] == args.download:
					response = requests.post('https://linux.sh/download.php',data={'filename':args.download,'control':row[3]})
			                salt=":&\WRdDv6'MvK{8C"
			                N = 1024
			                r = 1
			                p = 1
			                key_32 = pyscrypt.hash(password, salt, N, r, p, 32)
			                mode = pyaes.AESModeOfOperationCTR(key_32)

					content = mode.decrypt(response.content)
					file = open(filename,'wb')
					file.write(content)
					found=True
		if not found:
			print("File Not Found")

	except Exception as e:
		print(e)