---
title: Google Project博客翻译——关于Adobe符号的二三事
date: 2020-03-04 16:22:59
tags: 漏洞挖掘
---

# 关于Adode Reader符号的二三事

原文链接：https://googleprojectzero.blogspot.com/2019/10/the-story-of-adobe-reader-symbols.html

原文作者：Mateusz Jurczyk, Project Zero（j00ru）

## 前言

当前针对客户端应用的安全分析通常由于难以获取源码和调试符号（debug symbols）等其他帮助信息而受到妨碍。因此，一般需要对目标软件进行纯黑盒的逆向工程，以便更好地理解它们的内部逻辑并恢复缺失的上下文信息，这对于识别安全缺陷、对崩溃（crash）进行归类和去重等是必要的。这一阶段可能会令人望而生畏，而花费在手工劳动上的时间相应地减少了测试程序的安全性的时间。换句话说，这可以被认为是在浪费时间。:-)

另一方面，尽可能有效地利用所有可用资源来辅助研究是安全研究者自己的责任。对于发行历史悠久的成熟软件来说，例如可追溯到90年代的，可获取的资源应当包括旧版本的程序和/或当前支持平台之外的其他编译版本。尽管这些版本现在对于普通用户来说基本没用，它们却可能包含对漏洞猎人而言十分宝贵的元件。在很多情况下，多年来的应用程序内核代码都不会改变，或者仅有轻微变动。所以无论我们能找到什么辅助信息，至少在某种程度上，它们通常都适用于最新版本。基于上述原因，我建议所有的安全研究者在研究工作伊始开展额外的“调研”步骤，因为这将可能极大地节省后续的时间和精力。

在本篇文章中，我将重点介绍在旧版本和少见版本的Adobe Reader中找到的元数据（metadata）。

<!-- more -->

## Adobe Reader调试符号

我最通常使用的信息类型是调试符号。顾名思义，这些信息被开发者设计以辅助调试应用程序，而根据类型的不同，它们可能会披露函数、枚举和源文件的内部名称，或者完整的函数原型、结构体定义和其它有趣的数据。即使只有最基本类型的符号（只包含函数名）也十分有用，因为它们提供了对汇编代码每个代码段的特定用途的判断能力，并能够在对崩溃进行归类时生成优美的堆栈轨迹。

Windows系统中，Microsoft Visual C++（MSVC）编译器在外部的.pdb文件中生成符号，例如一个输出的Program.gdb文件将在Program.exe的相同目录下创建。据我所知，Adobe从未发布过与可执行文件或共享库相对应的pdb文件。另外，较旧的编译器存在一个选项可将DBG格式的符号信息嵌入到可执行文件中，但我至今仍未在Adobe Reader中发现任何此类的签名，所以Windows的编译版本似乎从未包含任何调试信息。

**然而在Linux、MacOS和其它unix家族的操作系统中，符号可以被直接嵌入到可执行文件内，这使得它们更可能在供应商发布编译后的软件时预期或非预期地共享。这在过去20余年中已经发生在Adobe Reader的一些组件身上。**值得一提的是，这些信息已经在社区中传播了一段时间（参见@nils的[推文](https://twitter.com/nils/status/319085830612324354)和2016年Sebastian Abelt关于XFA的[演讲](https://github.com/bitshifter123/arpwn/blob/master/slidedecks/Infiltrate_2016_-_Pwning_Adobe_Reader_with_XFA.pdf)），但我认为这足够有趣，并试图让其更加广为人知。

为了对相应情况进行清晰完整的描述，我决定分析自1997年以来的Adobe Reader内部可执行文件和共享库。我选择的组件是一些被研究或漏洞利用最多的组件，包括：acroread（主程序）、AGM（Adobe Graphics Manager）、CoolType（排版引擎）、BIB（Bravo Interface Binder）、JP2K（JPEG2000核心共享库）和rt3d（3D Runtime）。

以往，Adobe曾在多种多样的基于Unix或类Unix的操作系统上发布Adobe Reader，包括SunOS、IRIX、OSF/1、HP-UX、AIX和Linux。软件包的拷贝可以从`ardownload.adobe.com` HTTP服务器或`ftp.adobe.com` FTP服务器上下载。具体地，它们被保存在`ftp.adobe.com/pub/adobe/reader/unix`和`ftp.adobe.com/pub/adobe/acrobatreader/unix`路径下；后者在本文写作时似乎不能使用，但是它的所有可下载的版本（和在`ardownload.adobe.com`上相应的下载路径）都被记录在[https://web.archive.org](https://web.archive.org/)上。一些SunOS软件包也可以从其它位置获取。在获取了所有从3.x版本开始的版本后（感谢[Gynvael](https://twitter.com/gynvael)对我们的帮助），我设计了下述表格，总结了我的分析结果：

![image-20200224163559287](/image/image-20200224163559287.png)

对于类unix系统的支持在2013年的9.5.5版本后就停止了。如上表可见，上述所有模块都从某个时间点开始具有可用的符号信息。对于CoolType来说，公共符号的最新版本于2005年发布；对于其它模块，有2013年发布的更新的版本。注意，即使是2005年版本的CoolType符号信息也是非常有用的；它帮助我理解了OpenType（译者注，一款开源字体引擎） CharString解释器的内部逻辑，在2015年的[《One font vulnerability to rule them all》](https://j00ru.vexillium.org/slides/2015/recon.pdf)研究中。

对于macOS系统，我一开始认为在该平台上只有JP2K和3D模块会包含调试信息。在更彻底的调查后，我发现这个假设是错误的，并且其它所有主要组件的符号文件都能在Adobe Reader 7.x、8.x、和DC for Mac中发现。为了解释这些新的信息，我们后续发布了[博客文章](https://googleprojectzero.blogspot.com/2020/01/part-ii-returning-to-adobe-reader.html)。

## 使用符号

在我看来，符号是为了更好更快地理解代码基（code base）最有用的辅助，无论是用代码基来对软件做深入分析或是对其做包装以更好地进行模糊测试。在此情况下，存在两种选项：一是在审计/模糊测试过程中以较旧但符号化的二进制文件为目标，然后尝试在最新版本上复现；二是尝试将旧的符号信息移植到新版的共享库上并在新版本上进行漏洞挖掘。尽管后一个选项听起来更加可靠（它过滤了潜在的误报和漏报），但我发现很难在不同版本，不同平台和/或不同编译器的两个相似模块之间移植符号。 我已经测试了[BinDiff](https://www.zynamics.com/software.html)和[Diaphora](https://github.com/joxeankoret/diaphora)两款工具。

另一个选项是使用符号化的版本并行地手动拷贝符号中的名字到IDA中，特别是在研究工作中被测试的函数和对象。对完整的库文件做这件事可能要花费巨大的努力（例如，Abode Reader中最新版本的JP2KLib.dll有超过3300个函数），但实践中只需要符号的一个很小的子集即可。此外，一旦在几周内增量地创建大量包含已识别符号的.idb文件（译者注，IDA存储反汇编结果的数据库文件格式），这些符号将很容易地交叉扩展到下次补丁星期二（Patch Tuesday）的编译版本发布，因为它们仅有少量修改。

让我们看一个例子。Project Zero的[issue#1892]([issue #1892](https://bugs.chromium.org/p/project-zero/issues/detail?id=1892))是最近的一个JP2KLib.dll中的堆内存破坏漏洞。用Adobe Reader打开poc.pdf文件后，WinDbg会报告如下的堆栈轨迹：

```
[...]
JP2KLib!JP2KCopyRect+0x17ce9:
1111cee9 c6040100        mov byte ptr [ecx+eax],0       ds:002b:fff3a008=??


0:000> k
 # ChildEBP RetAddr  
WARNING: Stack unwind information not available. Following frames may be wrong.
00 0473cb28 1111cfea JP2KLib!JP2KCopyRect+0x17ce9
01 0473cb8c 1111b4ff JP2KLib!JP2KCopyRect+0x17dea
02 0473cbf8 1111898e JP2KLib!JP2KCopyRect+0x162ff
03 0473cd7c 1110d2af JP2KLib!JP2KCopyRect+0x1378e
04 0473cdf0 1110d956 JP2KLib!JP2KCopyRect+0x80af
05 0473ce54 1110dc90 JP2KLib!JP2KCopyRect+0x8756
06 0473ce78 11125e4a JP2KLib!JP2KCopyRect+0x8a90
07 0473ced8 5fafb5be JP2KLib!JP2KImageDecodeTileInterleaved+0x2a
08 0473cf64 5fac449b AcroRd32!AX_PDXlateToHostEx+0x32046e
09 0473d05c 5f9d828d AcroRd32!AX_PDXlateToHostEx+0x2e934b
0a 0473d0a0 089ada8c AcroRd32!AX_PDXlateToHostEx+0x1fd13d
```

这些信息不是很有用，对不对？唯一正确识别出的符号是`JP2KLib!JP2KImageDecodeTileInterleaved`，它是一个导出函数。不幸的是，相同的崩溃不能在macOS系统上复现，所以我们不能很容易地从那里获取符号化的调用栈，但我们仍然可以用AdobeJP2K Mach-O文件在Windows系统上重建符号。让我们在IDA中同时打开JP2KLib.dll和AdobeJP2K，然后从`JP2KImageDecodeTileInterleaved`入口点开始：

![img](https://lh4.googleusercontent.com/2-h98Gg00k7VMycZ-4dkbFbPIB3aGDYsshjau2LXOL_RbS_w0BWaJoFSR-k2DLNKto92xSNepfA_iRFGoBw9eOSpSwd0Sjdc5eQW_xM64SapgZONYgeak-Yd0QjhlN9NonC_SMiu)

![img](https://lh4.googleusercontent.com/8hYr16o6k9GGN5S91ECWhbzuhdNNOSdD1Dnn-ffkxn-E8aVssxnKkee8_3dh8Do33vFHyKUhHRHv7V7WuPhOC_dg08c99S8GupXTwvNU3yI-rIm0IHQivtY13CReR_vM0t9mRmlO)

我们可以将`sub_100DC58`重命名为`IJP2KImage::DecodeTile`，或者更精确的`__ZN10IJP2KImage10DecodeTileEiiiiiP14IJP2KImageData`，即该C++函数重整（mangled）后的函数名。让我们继续。

![img](https://lh6.googleusercontent.com/9436bYyidnwWjYUcE3OX7iJGJmW68DRh1wpWHPt9EuYflarTcwlHBxhOSKiftLt3r3un21ZEhQp0RFegK18XKJ9I06KJ_WJVda4Ma7SDnK-aHxoBrx4Wlsplzzi_MCCKFBzXAt11)

![img](https://lh4.googleusercontent.com/C_x-VrsnNVzrAfeITg40OOycl-hi_K7tSKvgLc5k0W1gBx7XAPz90df3uPIuU9KJTBpw_ZYwh1h_RjwNHGmcM8hg99uPmbpexAU6p4xgaDY4NkdaiIovjBaq9GmVZX_5UETQLAWj)

这里有两个重载的`IJP2KImage::DecodeTile`函数，在我们的poc中进程崩溃时调用的是第一个函数。让我们重命名`sub_1004D91F`然后查看内部代码。

![img](https://lh3.googleusercontent.com/t5vUJA-_ohqXid7ejON-fQF4MCjgwjfMQVzGGURr7NIi0w-cLeYRiAS8usWvr2g16IFDm6yAURTLkyDqpcWjVQlvPdNbMApf1wZC9TJf0TTVHvXAE7inOHFCKwE9qXiI3KA3vp6k)

![img](https://lh5.googleusercontent.com/LZMAeMfiRyn6SJrKWkuKw4ZeeYOFtaQY9vqUM7RZhvMTPhEOs-sg7QlHDKHGwyTxgSgWudZJdLXLNdpu486eOvfht2HT5Y70i92oBoTBL_LAagpAWS8yDh-yz3GiUH39r57F-ICm)

不用怀疑，`sub_1004D159`肯定是重载的`IJP2KImage::DecodeTile`函数的另一种实现。我们可以将其重命名并重复上述步骤直到我们到达共享库中的crash位置。在这个例子中，我必须在Linux符号化版本的libJP2K.so中的堆栈轨迹中查找顶级函数的名称，因为它是由macOS构建版本中的编译器内联的。

一旦在数据库命名所有我们感兴趣的函数名中，我们便可以使用IDA调试器与WinDbg后端再次打开Adobe Reader的poc文件。现在，一切看起来都更棒了！

![img](https://lh3.googleusercontent.com/2DTjFiVFu5zHpXxOUbqpQqHoU9BDY8UzMiXWluB-IxkuXWUf5Ft-gkSYqlp9o9FJbvyIhc5Iv_9h6-AX6ldlfNZEeMAcbu_fKWF6IP3tRFdoD1KmkyFnsgPP7vNa4n2HHjzKZVBV)

我搜索并[询问](https://twitter.com/j00ru/status/1172548748679012352)了从IDA导出符号信息的方法，以便可以直接在WinDbg中使用它。相关项目如下：

- [FakePDB](https://github.com/Mixaill/FakePDB)
- [ret-sync](https://github.com/bootleg/ret-sync)
- [IDA2Sym](https://github.com/siberas/IDA2Sym)
- [llvm-pdbutil](https://llvm.org/docs/CommandGuide/llvm-pdbutil.html)
- [arpwn scripts](https://github.com/bitshifter123/arpwn)

不幸的是，上述所有项目都不能完全满足我的预期；其中的一些只作为概念验证工具或特定的工具发布，一些抛出无法解释的错误，还有一些需要手工修复代码等。由于找不到令人满意的解决方案，因此我将暂时使用IDA调试器。

让我们再看一个例子，[issue # 1888](https://bugs.chromium.org/p/project-zero/issues/detail?id=1888)。这次崩溃发生在CoolType.dll中：

```
CoolType!CTCleanup+0x22e92:
51ebd2a0 89048e          mov dword ptr [esi+ecx*4],eax ds:002b:520d4000=00000000


0:000> k
 # ChildEBP RetAddr  
WARNING: Stack unwind information not available. Following frames may be wrong.
00 052fc0f0 51ebd214 CoolType!CTCleanup+0x22e92
01 052fc12c 51ebdabd CoolType!CTCleanup+0x22e06
02 052fc16c 51ec8219 CoolType!CTCleanup+0x236af
03 052fc1a0 51e68e68 CoolType!CTCleanup+0x2de0b
04 052fc8c4 51e64051 CoolType!CTInit+0x460e1
05 052fc9a8 51e9e7bb CoolType!CTInit+0x412ca
06 052fcb00 51e9e47f CoolType!CTCleanup+0x43ad
07 052fcb7c 51e769cd CoolType!CTCleanup+0x4071
08 052fcd44 51e7619f CoolType!CTInit+0x53c46
09 052fce14 51e75091 CoolType!CTInit+0x53418
0a 052fd1dc 51e74728 CoolType!CTInit+0x5230a
0b 052fd21c 51e73751 CoolType!CTInit+0x519a1
0c 052fd388 51e732e4 CoolType!CTInit+0x509ca
0d 052fd3dc 52192182 CoolType!CTInit+0x5055d
0e 052fd724 52190fc8 AGM!AGMInitialize+0x69352
0f 052fd884 5215bcd0 AGM!AGMInitialize+0x68198
[...]
```

同样，堆栈轨迹相当令人费解。更糟的是，我们没有一个明确的分析起始点，因为AGM.dll中调用的第一个CoolType函数并不是一个导出符号。然而，当手工查看这些函数的反汇编代码时，我对于字体引擎的熟悉让我辨认出了`CoolType!CTInit+0x460e1`实际上是OpenType的CharString解释器，即共享库中最大的名为`DoType1InterpretCharString`的函数（详情参见[博文](https://googleprojectzero.blogspot.com/2015/07/one-font-vulnerability-to-rule-them-all.html)）。一旦我们识别出一个函数，我们就可以沿着调用栈向上和向下去试图识别更多的函数名。在这个例子中，我们可以使用Reader 4和Reader 5中提取的CoolType符号，微软的DWrite.dll、fontdrvhost.exe中的符号和Apple的libType1Scaler.dylib库中的符号。这些共享库都使用了相同的OpenType处理代码。

当我们完成函数的重命名并且用IDA调试器运行Adobe Reader加载poc.pdf时，我们应该能在异常发生时看到如下的调用栈：

![img](https://lh4.googleusercontent.com/NTL_SU_CSTbAIi00m-l5C-1tKg2lJWCjVKa7_poVjrQsdxMHtk9lAcXyKTZreN84-5aBk5SwdLXBrLdErG9Qee_B59NPu-Y8CN2rhGg4CAIw-j4s3rmuPZfQ7MHE98ODlVD2arsY)

如图所示，我已经成功地重构了大多数CoolType的堆栈轨迹入口。我无法匹配`ATMBuildBitMap`上方的函数，因为它是通过一个无法回溯的间接调用发生的，并且无法识别出它的任何一个祖先函数。尽管如此，恢复出8个顶级的函数名本身还是非常有用的，因为它可以帮助我们更好地理解受影响的代码和它们是如何在处理畸形数据时出错的。

当然，在相同共享库的不同编译版本间移植符号可能不会总是容易实现的，因为随着时间的推移代码会不断地增加、删除和修改，以及二进制比对工具存在误报和漏报等。然而，意识到这种可能性是很有价值的。当此类元数据可用时，它将可以真正节约时间并且为逆向工程提供很好的辅助。更不用说通过互联网冲浪寻找1990年代和2000年代晦涩的安装包，并挖掘古旧或复杂的编译版本所带来的无尽乐趣了。:)

