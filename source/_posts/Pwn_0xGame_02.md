---
title: Pwn_0xGame_02
categories: 
    - 比赛WriteUp
    - 0xGame
---
# Pwn_0xGame_02
<!--more-->
## 1.Pwn题滞销,帮帮我好吗?
### syscall
IDA打开

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201022204647356.png#pic_center)

发现是个syscall的题目
直接去看这个函数的汇编

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201022204851409.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

根据师傅们所说，我们需要让rax存入59，让syscall去调用execve函数 （ret2syscall？）

[syscall_64 GitHub查询](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl)

之后要构造出来  execve("/bin/sh",0,0) 拿取权限
找"/bin/sh"字符串
方法一：
在程序中有，找到它

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201022210119569.png#pic_center)

从'['数起到斜杠前面的空格' '，再加上前面的04个字符，一共是22个，换成16进制是16h
所以"/bin/sh"的地址为：0x402016

方法二：
构造ROP链来寻找（这是看官方WriteUp看到的方法

`ROPgadget --binary ./main --string '/bin/sh'`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201022210755704.png#pic_center)

找来找去，最后还是要用到csu init函数

```
 text:00000000004011D8 loc_4011D8:                             ; CODE XREF: init+4C↓j
.text:00000000004011D8                 mov     rdx, r14
.text:00000000004011DB                 mov     rsi, r13
.text:00000000004011DE                 mov     edi, r12d
.text:00000000004011E1                 call    qword ptr [r15+rbx*8]
.text:00000000004011E5                 add     rbx, 1
.text:00000000004011E9                 cmp     rbp, rbx
.text:00000000004011EC                 jnz     short loc_4011D8
.text:00000000004011EE
.text:00000000004011EE loc_4011EE:                             ; CODE XREF: init+31↑j
.text:00000000004011EE                 add     rsp, 8
.text:00000000004011F2                 pop     rbx
.text:00000000004011F3                 pop     rbp
.text:00000000004011F4                 pop     r12
.text:00000000004011F6                 pop     r13
.text:00000000004011F8                 pop     r14
.text:00000000004011FA                 pop     r15
.text:00000000004011FC                 retn
.text:00000000004011FC ; } // starts at 4011A0
.text:00000000004011FC init            endp
.text:00000000004011FC
```


咕咕咕~~~
