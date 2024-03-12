---
title: 调试并解决Python内存泄露问题
date: 2018-11-05 21:46:33
tags: Dev
---

0x00  问题引入
虽然Python本身有垃圾回收机制，但是也有内存泄露的可能。这里我对这次调试项目代码的经验作简单总结，予以参考。

一般来说，可能出现内存泄露的情况，有如下几种：
1.对象被全局变量所引用，而生命周期较长
2.gc被禁用，使用`gc.disabled()`和`gc.enable()`进行操作
3.变量的循环引用。一般来说，只要开启gc，即使存在变量的循环引用，也不会导致内存泄露。但如果对象属于不可回收的，就无法处理。不可回收的变量通过`gc.garbage`查看，实际上就是实现了`__del__()`方法的对象

python的官方文档中对garbage方法的说明如下：
>A list of objects which the collector found to be unreachable but could not be freed (uncollectable objects). By default, this list contains only objects with `__del__()` methods. [1] Objects that have `__del__()` methods and are part of a reference cycle cause the entire reference cycle to be uncollectable, including objects not necessarily in the cycle but reachable only from it. Python doesn’t collect such cycles automatically because, in general, it isn’t possible for Python to guess a safe order in which to run the `__del__()` methods. 

简单解释一下，垃圾回收器会将不可达但不能被释放的对象标识为garbage。默认garbage列表只包含实现了`__del__()`方法的对象，这些对象属于一个循环引用的话会导致整个循环引用变得不可被回收。Python不会自动地回收这些循环，因为基本上Python不可能猜到真正安全的执行`__del__()`方法的顺序。当然如果你自己知道如何处理，可以用类似`del gc.garbage[:]`的方法在循环结束后手动释放。

<!-- more -->

---

0x01  辅助工具

首先推荐安装第三方工具Pyrasite，它可以在Python进程动态运行时修改数据和代码等，这显然有利于我们调试内存泄漏问题。它的最新版安装需要gdb(7.3版本以上)和Python2.4以上的环境。
```
(sudo) pip install pyrasite pyrasite-gui
```
如果操作系统是Ubuntu10.10以上，需要首先执行
```
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```
也可以通过设置`/etc/sysctl.d/10-ptrace.conf`中ptrace_scope为0来永久修改

我们主要用到的是pyrasite-shell和pyrasite-memory-viewer。其中pyrasite-shell的用法如下
```
$ pyrasite-shell
Usage: pyrasite-shell <PID>
```
输入相应Python进程的pid，得到一个shell与其进行交互，这个shell类似ipython。我们首先让存在内存泄漏问题的Python脚本运行起来，然后用pyrasite-shell getshell，就可以输入一些命令观察结果，从而定位问题。
pyrasite-memory-viewer则需首先安装urwid和meliae：
```
(sudo) pip install urwid meliae

$ pyrasite-memory-viewer <PID>
```
界面会列出当前对象内存占用的统计，按占用大小排序，包含对象的数量、总大小、百分比、对象类型名等信息，点选单个对象后将打印出对象的内容

---



0x02  调试过程

首先将我们的Python程序运行起来，然后用pyrasite-shell注入。
首先用gc模块的相关方法查看是否是垃圾回收的问题
```
Connected to 'python xxx.py'
Python 2.7.12 (default, Dec  4 2017, 14:50:18) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
(DistantInteractiveConsole)

>>> import gc
>>> gc.isenabled()
True

>>> gc.garbage
[<PtraceProcess #15277>, <PtraceProcess #15282>, <PtraceProcess #15287>, <PtraceProcess #15292>, <PtraceProcess #15297>, <PtraceProcess #15302>, 
<PtraceProcess #15307>, <PtraceProcess #15312>, <PtraceProcess #15317>,  .......
```
说明垃圾回收已开启，但多执行几次gc.garbage，发现这个叫做PtraceProcess的对象的数量在不断增加。实际上，这个对象是第三方python-ptrace模块中所定义的，查看其源码。
```
def __del__(self):
        try:
            self.detach()
        except PtraceError:
            pass
```
果然定义了`__del__()`方法，这里可以使用objgraph模块作出此对象的循环引用图，从而直观的判断到底是哪里出现问题。具体安装和使用方法并不复杂，这里不再赘述，只给出样例图。
![]()

但是，在我将PtraceProcess的`__del__()`方法注释掉之后，问题仍然存在。这令我有些费解，这时想到去研究一下linux自带的top命令。
```
top - 13:24:30 up 2 days, 11:37,  1 user,  load average: 0.54, 0.82, 0.93
Tasks: 286 total,   1 running, 285 sleeping,   0 stopped,   0 zombie
%Cpu(s):  6.1 us,  5.8 sy,  0.0 ni, 87.7 id,  0.1 wa,  0.0 hi,  0.3 si,  0.0 st
KiB Mem :  4016440 total,   249140 free,  2123672 used,  1643628 buff/cache
KiB Swap:  4192252 total,  4175600 free,    16652 used.  1304868 avail Mem 

   PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND                                                                                           
 32514 liwc      20   0  247852  52012   7468 S  69.1  1.3   0:08.44 python                           
```
可以看到%MEM、VIRT、RES、SHR这几项都在不断地增大，其中%MEM顾名思义就是内存的占用量，而VIRT是进程使用的虚拟内存总量、RES是进程使用的、未被换出的物理内存大小，SHR是以共享方式使用的内存大小。因为项目代码使用了用shmget申请的共享内存，所以我格外关注SHR的含义。通过查找资料得知，SHR包括：
>程序的代码段
动态库的代码段
通过mmap做的文件映射
通过mmap做的匿名映射，但指明了MAP_SHARED属性
通过shmget申请的共享内存

在大佬的提示下，又发现内存增长的总量全部来自于SHR部分，这不禁使我怀疑是该部分代码有问题。使用pmap指令查看进程的内存映射关系:
```
97523:   python xxx.py
0000000000400000   2936K r-x-- python2.7
00000000008dd000      4K r---- python2.7
00000000008de000    476K rw--- python2.7
0000000000955000    140K rw---   [ anon ]
0000000000b7a000  33564K rw---   [ anon ]
00007f6465c10000     64K rw-s-   [ shmid=0x6aac8bca ]
00007f6465c20000     64K rw-s-   [ shmid=0x6aac8bca ]
00007f6465c30000     64K rw-s-   [ shmid=0x6aac8bca ]
...
00007f6479e93000     64K rw-s-   [ shmid=0x6aac8bca ]
00007f6479ea3000      4K -----   [ anon ]
00007f6479ea4000   8192K rw---   [ anon ]
...
 total           447084K
```
发现同一块用shmget申请的共享内存被映射到进程空间内数次，看来这个就是吃掉内存的元凶。事实上，就是shmat函数被错误地调用了多次，从而被映射了多次。修正代码后，问题解决。

---

0x03  问题总结

总之，感觉出现疑似内存泄漏时，应该首先用pyrasite-shell连上看一下，排除循环引用等垃圾回收的问题，同时注意观察pmap、top等命令的结果。