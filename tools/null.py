import os,sys

with open("payload.bin","wb") as f:
	for i in range(0,1024*1024*32):
		f.write(b"\x90");

