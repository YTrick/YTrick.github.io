---
title: 湖湘杯hxb_Re
categories: 
    - 比赛WriteUp
    - 湖湘杯
---
# 湖湘杯hxb_Re
<!--more-->
## easy_c++
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020111417004942.png#pic_center)

长度32

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114170457298.png#pic_center)


关键字符串

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114170212320.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)
v11是一个个字符
下面异或
写脚本
over
python_exp:

```python
str = "7d21e<e3<:3;9;ji t r#w\"$*{*+*$|,"
v13 = ''
for i in range(32):
    v11 = ord(str[i:i+1])
    v13 += chr(i ^ v11)
    v11 ^= i
print(v13)
```


java_exp: 

```java
public class Test {
    public static void main(String[] args) {
        String a = "7d21e<e3<:3;9;ji t r#w\"$*{*+*$|,";
        char v11;
        int v13;
        for (int i =0; i<32; i++)
        {
            v11 = a.charAt(i);
            v13 = i ^ (int)v11;
            System.out.print((char)v13);
        }
    }
}
```

flag:
7e02a9c4439056df0e2a7b432b0069b3


## ReMe
python反编译项目
 先下载：
链接: [https://github.com/countercept/python-exe-unpacker](https://github.com/countercept/python-exe-unpacker)

之后把要反编译的exe放到目录下
再执行下面的命令
`python3 pyinstxtractor.py ReMe.exe`


![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114174957755.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)
成功之后如上图，并且在目录下会生成一个新的文件夹
进入被创建出来的文件夹，用winhex打开一个你软件名字的文件和一个名为struct的文件

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114175111142.png#pic_center)
我们需要把目标文件也就是ReMe的头添加上struct中的16进制头数据

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114175807232.png#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020111417582892.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)

选中，右键->Edit->Copy Block->Hex Values
总之就是复制为16进制的数据
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020111418030031.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)
到ReMe中Crtl+v粘贴上
一下就是最终的效果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114180437151.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)
保存之后添加pyc后缀名
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114180716119.png#pic_center)
然后在终端安装uncompyle
`pip install uncompyle`

安装好之后在ReMe.pyc文件目录下执行：

`uncompyle6 ReMe.pyc`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201114181521899.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1lhbmdaaVRyaWNr,size_16,color_FFFFFF,t_70#pic_center)
出现了源代码

可以用

`uncompyle6 ReMe.pyc > ReMe.py`

生成py文件

![在这里插入图片描述](https://img-blog.csdnimg.cn/2020111418165395.png#pic_center)

源码:
```python
import sys, hashlib
check = [
 'e5438e78ec1de10a2693f9cffb930d23',
 '08e8e8855af8ea652df54845d21b9d67',
 'a905095f0d801abd5865d649a646b397',
 'bac8510b0902185146c838cdf8ead8e0',
 'f26f009a6dc171e0ca7a4a770fecd326',
 'cffd0b9d37e7187483dc8dd19f4a8fa8',
 '4cb467175ab6763a9867b9ed694a2780',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'cffd0b9d37e7187483dc8dd19f4a8fa8',
 'fd311e9877c3db59027597352999e91f',
 '49733de19d912d4ad559736b1ae418a7',
 '7fb523b42413495cc4e610456d1f1c84',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'acb465dc618e6754de2193bf0410aafe',
 'bc52c927138231e29e0b05419e741902',
 '515b7eceeb8f22b53575afec4123e878',
 '451660d67c64da6de6fadc66079e1d8a',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'fe86104ce1853cb140b7ec0412d93837',
 'acb465dc618e6754de2193bf0410aafe',
 'c2bab7ea31577b955e2c2cac680fb2f4',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'f077b3a47c09b44d7077877a5aff3699',
 '620741f57e7fafe43216d6aa51666f1d',
 '9e3b206e50925792c3234036de6a25ab',
 '49733de19d912d4ad559736b1ae418a7',
 '874992ac91866ce1430687aa9f7121fc']

def func(num):
    result = []
    while num != 1:
        num = num * 3 + 1 if num % 2 else num // 2
        result.append(num)

    return result


if __name__ == '__main__':
    print('Your input is not the FLAG!')
    inp = input()
    if len(inp) != 27:
        print('length error!')
        sys.exit(-1)
    for i, ch in enumerate(inp):
        ret_list = func(ord(ch))
        s = ''
        for idx in range(len(ret_list)):
            s += str(ret_list[idx])
            s += str(ret_list[(len(ret_list) - idx - 1)])

        md5 = hashlib.md5()
        md5.update(s.encode('utf-8'))
        if md5.hexdigest() != check[i]:
            sys.exit(i)

    md5 = hashlib.md5()
    md5.update(inp.encode('utf-8'))
    print('You win!')
    print('flag{' + md5.hexdigest() + '}')
```

exp：

```python
import hashlib

check = [
 'e5438e78ec1de10a2693f9cffb930d23',
 '08e8e8855af8ea652df54845d21b9d67',
 'a905095f0d801abd5865d649a646b397',
 'bac8510b0902185146c838cdf8ead8e0',
 'f26f009a6dc171e0ca7a4a770fecd326',
 'cffd0b9d37e7187483dc8dd19f4a8fa8',
 '4cb467175ab6763a9867b9ed694a2780',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'cffd0b9d37e7187483dc8dd19f4a8fa8',
 'fd311e9877c3db59027597352999e91f',
 '49733de19d912d4ad559736b1ae418a7',
 '7fb523b42413495cc4e610456d1f1c84',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'acb465dc618e6754de2193bf0410aafe',
 'bc52c927138231e29e0b05419e741902',
 '515b7eceeb8f22b53575afec4123e878',
 '451660d67c64da6de6fadc66079e1d8a',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'fe86104ce1853cb140b7ec0412d93837',
 'acb465dc618e6754de2193bf0410aafe',
 'c2bab7ea31577b955e2c2cac680fb2f4',
 '8e50684ac9ef90dfdc6b2e75f2e23741',
 'f077b3a47c09b44d7077877a5aff3699',
 '620741f57e7fafe43216d6aa51666f1d',
 '9e3b206e50925792c3234036de6a25ab',
 '49733de19d912d4ad559736b1ae418a7',
 '874992ac91866ce1430687aa9f7121fc']
def func(num):
    result = []
    while num != 1:
        num = num * 3 + 1 if num % 2 else num // 2
        result.append(num)
    return result

for i in range(1,128):
	a = func(i)
	s = ''
	for idx in range(len(a)):
		s += str(a[idx])
		s += str(a[(len(a) - idx - 1)])
	md5 = hashlib.md5()
	md5.update(s.encode('utf-8'))
	b = md5.hexdigest()
	for j in range(27):
		if b == check[j]:
			print j,chr(i)
```

输出结果：

```python
15 +
16 1
13 3
19 3
24 5
9 @
5 M
8 M
18 R
22 T
14 X
7 _
12 _
17 _
21 _
2 a
23 e
0 f
3 g
11 h
1 l
10 t
25 t
20 v
6 y
4 {
26 }

```
手动操作一下就ok




