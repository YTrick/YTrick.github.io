checksec到底是用来干什么的？

它是用来检查可执行文件属性，例如PIE, RELRO, PaX, Canaries, ASLR, Fortify Source等等属性。

使用命令：

`checksec [filename]`

我们在ubuntu下使用它时，会显示有5行信息：


![在这里插入图片描述](https://img-blog.csdnimg.cn/2020111011454314.png#pic_center)




## 1.Arch
从这行信息可以知道程序是32bit还是64bit的

## 2.RELRO
Full Relro（重定位表只读）

Relocation Read Only， 重定位表只读。重定位表即.got 和 .plt 两个表。



## 3.Stack

显示Stack：No canary found则表示可以利用栈溢出

Canary在pwn中是什么呢？
Canary翻译金丝雀。金丝雀原来是石油工人用来判断气体是否有毒。
而应用于在栈保护上则是在初始化一个栈帧时在栈底（stack overflow 发生的高位区域的尾部）设置一个随机的 canary 值，当函数返回之时检测 canary 的值是否经过了改变，以此来判断 stack/buffer overflow 是否发生，若改变则说明栈溢出发生，程序走另一个流程结束，以免漏洞利用成功。 因此我们需要获取 Canary 的值，或者防止触发 stack_chk_fail 函数，或是利用此函数。



编译时控制是否开启栈保护以及程度：


```python
gcc -fno-stack-protector -o test test.c  //禁用栈保护
gcc -fstack-protector -o test test.c   //启用堆栈保护，不过只为局部变量中含有 char 数组的函数插入保护代码
gcc -fstack-protector-all -o test test.c //启用堆栈保护，为所有函数插入保护代码
```

## 4.NX
NX enable（不可执行内存）

最常见的方法为 ROP (Return-Oriented Programming 返回导向编程)，利用栈溢出在栈上布置地址，每个内存地址对应一个 gadget，利用 ret 等指令进行衔接来执行某项功能，最终达到 pwn 掉程序的目的。


gcc编译器默认开启了NX选项，如果需要关闭NX选项，可以给gcc编译器添加-z execstack参数。
例如：

```python
gcc -z execstack -o test test.c
```

## 5.PIE（ASLR）
称作 地址空间分布随机化（ASLR）
内存地址随机化机制（address space layout randomization)，有以下三种情况

```python
0 - 表示关闭进程地址空间随机化。
1 - 表示将mmap的基址，stack和vdso页面随机化。
2 - 表示在1的基础上增加栈（heap）的随机化。
```

liunx下关闭PIE的命令如下：

```python
sudo -s echo 0 > /proc/sys/kernel/randomize_va_space
```


## 转载

[Checksec](https://www.jianshu.com/p/31449fdfe35f)