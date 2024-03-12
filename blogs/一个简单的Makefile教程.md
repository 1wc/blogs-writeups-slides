---
title: 一个简单的Makefile教程
date: 2018-11-19 22:31:41
tags: Dev
---



Makefile是一种组织代码编译的简单方法。这个教程将会指导你编写中小规模项目的makefile文件。

## 0x00  一个简单的例子



让我们首先引入下面这三个文件，hellomake.c，hellofunc.c，hellomake.h：三者组成一个标准的C程序。

`hellomake.c`

```c++
#include <hellomake.h>

int main() {
    // call a function in another file
    myPrintHelloMake();
    return(0);
}
```



`hellofunc.c`

```c++
#include <stdio.h>
#include <hellomake.h>

void myPrintHelloMake(void) {
    printf("Hello makefiles!\n");
    return;
}
```



`hellomake.h`

```c++
/*
example include file
*/

void myPrintHelloMake(void)
```



一般地，可以通过下面的指令编译这些代码

`gcc -o hellomake hellomake.c hellofunc.c -I.`

这将编译两个.c文件 hellomake.c、hellofunc.c，并且指定可执行文件的名字为hellomake。-I dir是指定搜索头文件的目录的路径为dir，而-I.是指定在当前目录下寻找。没有makefile的话，为了重复测试/修改/调试你的代码，常见的做法是用上方向键在终端中找到上一条指令，因而你就不用每次重新输入指令。

不幸的是，这种做法有两个弊端。第一，如果你弄丢了编译指令或者换了一台计算机，你将不得不重新输入，导致效率极低。第二，如果你只修改了一个.c文件，每次都重新编译所有的文件也是耗时且低效的。因此，我们需要学习如何使用makefile。



## 0x01  Makefile1

```bash
hellomake: hellomake.c hellofunc.c
	gcc -o hellomake hellomake.c hellofunc.c -I.
```



将上述规则（rule）写到文件Makefile或makefile中，放在同一路径下，然后键入make就可以执行相应的编译。另外，通过将指令所需要的文件列在第一行的冒号之后，make会知道规则hellomake在这些文件之一被修改时需要被执行。此时，你已经解决了问题1——不需要再使用上方向键了。

*gcc指令之前需要有一个tab，而且在任何指令之前必须有一个tab。(必须是tab不能是空格)*


<!-- more -->

## 0x02  Makefile2

```bash
CC=gcc
CFLAGS=-I.

hellomake: hellomake.o hellofunc.o
	$(CC) -o hellomake hellomake.o hellofunc.o
```



现在你已经定义了一些常量CC和CFLAGS。这些特殊的常量将告诉make指令我们将如何编译文件hellomake.c和hellofunc.c。特别地，CC表明所使用的C编译器，CFLAGS表明传递给编译器的参数。通过将目标文件——hellomake.o和hellofunc.o放在依赖列表和规则中，make知道它必须首先独立的编译.c为.o，然后将他们编译成一个可执行文件hellomake。



使用这个形式的makefile对大多数小规模的项目十分有效。然而，头文件的依赖被遗忘了。举例来说，如果我们修改了hellomake.h，make将不会重新编译.c文件，即使它需要这么做。为了解决这个问题，我们需要指明.c文件所依赖的.h文件。通过再编写一个简单的规则并且添加进makefile中可以达成目的。



## 0x03  Makefile3

```bash
CC=gcc
CFLAGS=-I.
DEPS=hellomake.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

hellomake: hellomake.o hellofunc.o
	$(CC) -o hellomake hellomake.o hellofunc.o
```



这个例子首先定义了一个叫DEPS的变量，表示.c文件所依赖的头文件的集合。然后定义了一个规则应用于所有.o后缀的文件。这个规则指定每个.o文件依赖于相应的.c文件和DEPS所表示的.h文件。-c参数指定产生.o文件，-o $@说明将编译结果输出在**冒号左边**的名字的文件中，$<是**依赖列表中的第一个文件**（即.c文件），最后加上其它编译参数。

make执行的命令序列如下：

```bash
gcc -c -o hellomake.o hellomake.c -I.
gcc -c -o hellofunc.o hellofunc.c -I.
gcc -o hellomake hellomake.o hellofunc.o
```



为了最终简化，我们使用特殊的宏$@和$^使得编译规则更加普适化。

$@表示冒号的左端、$^表示冒号的右端，$<表示依赖列表中第一个文件

## 0x04  Makefile4

```bash
CC=gcc
CFLAGS=-I.
DEPS=hellomake.h
OBJ=hellomake.o hellofunc.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
hellomake: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
```



那如果我们想将.h文件放到include目录中，将源文件放到src目录中，将一些库放在lib目录中呢？此外，我们可以采用某种方法隐藏（其实只是一种障眼法hhh）那些无处不在的讨厌的.o文件吗？答案当然是可以的。下面这个makefile定义了src和lib目录的路径，并且将目标文件集中放在src目录下的obj子目录中。它也定义了表示所要包含的库的变量，例如数学库-lm。这个makefile需要放在src目录下。最后，定义了make clean的规则。

## 0x05 Makefile5

```bash
IDIR=../include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR=../lib

LIBS=-lm

_DEP=hellomake.h
DEPS=$(patsubst %,$(IDIR)/%,$(_DEP))

_OBJ=hellomake.o hellofunc.o
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
hellomake: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	
.PHONY: clean

clean:
	rm -f $(ODIR)/*.o hellomake
```

.PHONY规则是为了避免二义性。

另外，patsubstd的定义如下： `$(patsubst pattern,replacement,text)`

从text中寻找按空格划分的单词中符合pattern的，然后用replacement替换掉它。pattern可能包含一个'%'作为通配符，匹配单词中任何数量的字符。如果replacement中也包含'%'，则这个'%'会被pattern的'%'所匹配的内容所替换。



##0x06  总结



总之，编写一个makefile重点就是定义一些变量和一些规则，规则格式如下：

```
targets : prerequisites
	recipe
	...
```

或者

```
targets : prerequisites ; recipe
	recipe
	...
```

大体上，先明确头文件，再写.o的生成规则，最后写二进制文件的生成规则即可。



当然，还包括一些导向(directive)指令，主要包括：

- 包含其它makefile文件
- 控制语句
- 定义多行变量



理解了这些，对于中小规模的项目来说，编写一个makefile文件是非常容易的。当然，如果使用CMAKE，可能会更加便利，但是也需要额外的学习成本。



>[参考链接](http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/)