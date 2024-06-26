---
title: 模糊测试与程序分析
date: 2020-04-09 01:05:58
tags: fuzzing
---

## 前言

本文基于笔者对模糊测试和程序分析的粗浅理解，如有谬误，欢迎斧正。另外，如转载、引用本文，请注明出处，谢谢！

## 模糊测试概述

模糊测试（Fuzzing test）是当前工业界和学术界公认最有效的漏洞挖掘方法。维基百科上的定义如下：模糊测试是一种软件测试技术。其核心思想是将自动或半自动生成的随机数据输入到一个程序中，并监视程序异常，如崩溃，断言（assertion）失败，以发现可能的程序错误，比如内存泄漏等。

模糊测试有多种分类指标，按照产生针对目标系统的输入的方式不同，可分为基于生成的模糊测试和基于变异的模糊测试。前者适用于目标输入格式已知或逆向可得的场景，需要使用者构建一个模版，模糊测试器基于模版不断生成测试用例；后者则要求使用者提供一个或数个种子文件，然后模糊测试器利用内置的算法逻辑对种子进行变异，从而快速生成大量测试用例。按照对目标程序或计算机系统的所掌握的信息量区分，可分为黑盒模糊测试、白盒模糊测试和灰盒模糊测试。黑盒模糊测试在是目标程序的源代码难以获取，或者可获取但不对源代码进行分析时，只对二进制程序进行测试的一类方法。白盒模糊测试需要借助重量级的程序分析方法，例如符号执行和约束求解，从而降低模糊测试的盲目性并提高覆盖率。灰盒模糊测试介于两者之间，一般采用在编译时插装的方法对源代码进行轻量级的分析，同时保持运行时的性能以期发现更多的安全漏洞。

## 典型模糊测试工具

Michal Zalewski于2014年发布了开源项目AFL，公认为模糊测试领域的一大里程碑。AFL是一款基于变异的灰盒模糊测试器，在用GCC/LLVM对目标程序源代码编译时进行插装，使插装后的程序在动态运行时将路径覆盖信息加载到共享内存，最终模糊测试器可以获取每个变异后种子的边覆盖信息。AFL以边覆盖为反馈信息，基于遗传算法维护一个种子队列，只将标记为有趣的种子放入种子队列。通过上述策略，AFL能够在保持高运行速率的前提下充分提高覆盖率，提高漏洞挖掘的效率与几率。另外，AFL还有基于QEMU的二进制插装解决方案，能够对闭源软件进行覆盖引导的模糊测试 。目前为止，AFL已经发现了开源软件和部分闭源软件中的成千上百个漏洞，包括广泛使用的开源库ffmpeg、curl等和应用程序IE、Firefox等。

Google后来推出了集成在LLVM框架中的覆盖反馈模糊测试组件LibFuzzer，它与AFL的主体算法相似，但是模糊测试的目标不是待测程序，而是可局部执行的代码片段，这提高了模糊测试的可扩展性，也避免运行非攻击面的代码所造成的额外开销。Google基于LibFuzzer构建了OSS-Fuzz模糊测试系统，对托管在该系统上的开源软件进行持续性的模糊测试，在五个月内从47个开源项目中发现了1000多个bug。

## AFL的改进面

以AFL、honggfuzz、LibFuzzer为代表的基于变异的灰盒模糊测试器由于其实用性被安全研究人员广泛应用于漏洞挖掘的真实场景中，而在各大安全与软工顶会中也涌现出一批以AFL为基线的工作。这些工作大都对AFL已有的算法与机制进行改进，以适配不同的应用场景。一般来说，模糊测试的目的是为了发现更多的缺陷与安全漏洞，而通常人们用提高覆盖率来近似拟合增加漏洞发现几率。原始的AFL代码整理出一套可行的解决方案，但在其运转的各个环节仍有许多改进面可以提高代码覆盖率。具体来说，主要有如下两点：

### 1. 种子排序、种子打分等种子队列循环调度机制

AFLfast（CCS'16）中证明了覆盖反馈的灰盒模糊测试可以建模为**马尔可夫链**。**设状态i是程序中的某条分支路径，从状态i到状态j的转移概率pij由模糊测试由执行路径i的种子变异产生执行路径j的种子的概率给出**。该工作通过调整种子打分（得分越高，变异次数越多）机制，在原始得分上增加能量调度，将模糊测试过程引向低频路径，从而在短时间内获得高覆盖率。

另外，由于AFL内部维护一个种子队列，而该队列中的元素按照优先级排序。如果能够合理调整种子的优先级，使得应当具有高优先级的种子被优先处理，那么也能显著的提高模糊测试效率。

### 2. 变异位置，变异策略等种子变异机制

原始的AFL具有丰富的变异策略，又保持了很强的随机性，这在漏洞挖掘实践中被证明是有效的。但是，对于路径较深、触发较难的漏洞，这种随机变异为主的方法可能看起来是在赌博。如果我们能针对目标问题增加一些启发式算法，甚至用白盒方法获取一些知识指导变异，从而控制变异的位置和变异的策略，那么自然能提高代码覆盖率，增加模糊测试器的漏洞挖掘能力。

<!-- more -->

## 程序分析的应用面

程序分析技术在模糊测试中有广泛的应用面，因为模糊测试归根结底是一种动态测试技术。动态分析的优势是误报率低，劣势则是搜索空间过大，容易产生盲目性。为了避免随机性太强引起测试覆盖率低，安全研究人员通常采用不同粒度的程序分析方法辅助模糊测试，从而进行所谓的“智能”模糊测试。主要应用场景有：

### 1. 符号执行

符号执行和约束求解技术已经被广泛应用于漏洞挖掘领域，因为它能够精准的求解路径约束条件，从而触发一些难以通过纯黑盒变异触发的路径。诚然，符号执行存在路径爆炸和开销过大的显著缺点，而执行效率可能是模糊测试过程能否发现漏洞的命门，但通过Concolic执行或局部执行等手段可以规避其弱点，和模糊测试结合起来实现`1+1>2`的效果。

典型工作有Driller（NDSS '16）、kleeFL（USENIX '2017）等。Driller是UCSB的shellphish团队为了参加16年的Cyber Grand Challenge（CGC）而开发的漏洞挖掘工具。Driller的核心设计思想是在AFL探索程序的路径分支发生困难时（get stuck）切换到Concolic执行（基于Angr），当成功求解难解约束后再次将控制交还AFL。这种方法主要考虑到两种漏洞挖掘方法的瓶颈不同：灰盒模糊测试处理连续字节比较、数学计算等难解约束比较困难，而符号执行容易求解这种约束，但存在路径爆炸的问题。Driller发挥两种方法的长处，最终取到了较好的漏洞挖掘效果。kleeFL也是相似的思路，它首先将初始的路径探索任务交给符号执行引擎KLEE，然后将生成的种子交给AFL进行fuzz。总的来说，上述两篇文章中对模糊测试和符号执行的结合过于粗暴，此研究方向还有较大的发展空间。

实际上，符号执行一并解决了变异位置、变异策略的问题，通过求解约束将符号化的输入转化为符合路径约束的值。

### 2. 污点分析

污点分析技术是信息流分析的一种实践技术，通过对带污点标记的数据的传播实施分析来达到保护数据完整性和保密性的目的，当前被广泛应用在系统隐私数据泄露检测、系统安全漏洞挖掘等实际领域。在模糊测试中应用污点分析，**主要目的是求解合理的变异位置。**通过在输入字节上打标记，可以追溯某个位置的字节变异对程序行为的影响，从而针对的进行变异，甚至进行特异性的输入长度扩展。

最典型的工作是Angora（S&P '18）。Angora的核心思路是希望不利用笨重的符号执行技术却仍能提高边覆盖率：他认为AFL的随机变异没有考虑数据流信息，而符号执行的开销太大，所以如何在求解复杂约束和减小开销之间寻找一个平衡是很有必要的。Angora采用动态污点分析技术和所谓的“梯度下降算法”求解约束，具体做法是针对某个未触发的特定分支语句，通过动态污点分析判断哪些输入字节与该分支约束相关，同时通过类型推断判断字节是否组合形成常见类型，然后对这些字节按类型进行变异。在变异时，Angora遵循“梯度下降算法”，即首先将分支约束看作黑盒函数，然后对待变异字节正方向或负方向+1从而近似求偏导，最后根据导数方向不断逼近一个局部最优解。只要能求得一个局部最优解，模糊测试就能继续进行下去。Angora在LAVA-M测试集和部分实际程序上取得了state-of-art的成果，充分发挥了污点分析技术的优势，是模糊测试与程序分析结合的一个很好的用例。

### 3. 指针分析

指针分析，也叫别名分析，是数据流分析中的经典问题之一。通过指针分析，可以求解间接调用可能的被调用函数，从而构建更加“精确”的函数调用图，在程序分析中考虑控制流信息。

在模糊测试领域中有一类应用，叫做导向的模糊测试（directed fuzzer）。导向的模糊测试通常用于补丁测试、崩溃复现、漏洞自动利用等场景。一般的，导向模糊测试给定一个目标基本块（或源码行号）序列，通过反馈的模糊测试变异得到触发目标基本块序列的样本。AFLGo（CCS '17）引入"距离"作为反馈信息，所谓"距离"是由当前基本块和目标基本块在CG（函数调用图）和CFG（控制流图）上相对"距离"计算得到的值，近似衡量两个基本块在iCTF上的距离。值得关注的是，在根据某个崩溃调用栈进行导向模糊测试时，如果它包含很多间接调用和间接跳转，那么简单的静态分析无法找到这条路径。Hawkeye（CCS '18）用SVF工具进行指针分析，求解包含间接调用的CG和CFG图，并以此为基础计算目标基本块的"距离"，避免了简单的静态分析所导致的路径缺失，极大地增加了导向模糊测试的成功率。

## 总结

模糊测试是漏洞挖掘的可靠手段，而程序分析也在源码、二进制安全审计中展现出自己的优势。通过程序分析的手段，对目标程序的控制流和数据流进行分析，会对基于随机性的模糊测试技术带来另一个维度的帮助。另一方面，动态和静态结合的分析可以帮助安全研究人员提高漏洞挖掘的效率，保证软件系统的安全性。

## 参考文献

1. AFL http://lcamtuf.coredump.cx/afl/
2. LibFuzzer https://llvm.org/docs/LibFuzzer.html
3. Wiki [https://zh.wikipedia.org/wiki/%E6%A8%A1%E7%B3%8A%E6%B5%8B%E8%AF%95](https://zh.wikipedia.org/wiki/模糊测试)
4. OSS-Fuzz https://github.com/google/oss-fuzz
5. 王蕾, et al. "污点分析技术的原理和实践应用." *软件学报* 28.4 (2017): 860-882.
6. Stephens, Nick, et al. "Driller: Augmenting Fuzzing Through Selective Symbolic Execution." NDSS. Vol. 16. No. 2016. 2016.
7. Fietkau, Julian, Bhargava Shastry, and J. P. Seifert. "KleeFL-seeding fuzzers with symbolic execution." Poster presented at USENIX Security 17 (2017).
8. Chen Peng, and Hao Chen. "Angora: Efficient fuzzing by principled search." 2018 IEEE Symposium on Security and Privacy (SP). IEEE, 2018.
9. Chen, Hongxu, et al. "Hawkeye: Towards a desired directed grey-box fuzzer." *Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security*. ACM, 2018.
10. Böhme, Marcel, Van-Thuan Pham, and Abhik Roychoudhury. "Coverage-based greybox fuzzing as markov chain." *IEEE Transactions on Software Engineering* 45.5 (2017): 489-506.
11. Böhme, Marcel, et al. "Directed greybox fuzzing." Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security. ACM, 2017.