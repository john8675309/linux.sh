# linux.sh

## linux.sh is a program and domain that allow you to upload and encrypt small files, like config files for later downloading, Think of it as web cp file file.back They are stored for 24 hours

[linux.sh](https://linux.sh)

![Demo](https://github.com/john8675309/linux.sh/raw/master/img/linux_sh.gif)


In order to use AES encryption you have to install pyaes and pyscrypt

Both Python2 and Python3 are supported as well as the libraries and should be cross platform compatible

A file is created in your home directory called .linux.sh This is in essence a table of contents of all files that have been uploaded, but will probably be slow to use if you upload a lot of files, its a csv

File Layout:
```
filename,uploadfilename,expires,filecontrol,encrypted
```

**Don't confuse yourself, while the file on the server is encrypted by default, the keys are avalible on the same server!!! you should always --encrypt when you upload!!**

python2:
```
pip2 install pyaes
pip2 install pyscript
```
or python3:
```
pip3 install pyaes
pip3 install pyscript
```

Commands:

Upload (Not Encrypted):
```
linux.sh --upload <filename>
```
Upload (Encrypted):
```
linux.sh --upload <filename> --encrypt
```

List all valid uploaded files:
```
linux.sh --ls
```

List the metadata of the file:
```
linux.sh --meta <uploadfilename>
```

Remove the file:
```
linux.sh --rm <uploadfilename>
```

Download the file **Caution this WILL overwrite any file with the original filename**:
```
linux.sh --download <uploadfilename>
```

Share the file (Returns base64 to share with other people):
```
linux.sh --exportshare <uploadfilename>
```

Import the share
```
linux.sh --importshare <base64 from exportshare>
```
When you share a file the 24 hour clock does not reset and the person ONLY has the ability to download the file. --rm is non destructive to the remote file


For Tor assuming you have the client installed:
```
sudo pip2 install pysocks
sudo pip3 install pysocks
```

The software assumes that tor is running on 127.0.0.1:9050

Usage is just adding the --tor argument
```
linux.sh --upload <file> --encrypt --tor
```
