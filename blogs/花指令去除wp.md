---
title: 花指令去除wp
date: 2018-12-05 21:50:11
tags: RE
---

​	这学期《恶意代码分析》这门课的作业留了一道RE题，其中包含大量批量插入的花指令。在这里简单记录一下分析过程。

## 0x00  基本分析

首先动态执行程序看一下

```shell
D:\UCAS\malware_analyse>Anti.exe
The encypted flag in hex is:
3A3B3138233B3C3437300B3730073228393523062E2B242A
Please input cipher character:3
Hex result for encrypt string 'thisisasimplesamplestring' is:
7A6D6B7E63756C706D61766661796B62756067787271656B6B
```

输入点只有一个，要求输入一个加密字符，然后就会输出对`thisisasimplesamplestring`字符串的加密结果。那么显然，只要我们能够分析并逆向出加密算法，就能把加密后的flag解密得到原flag，当然这个加密算法应该是可逆的，否则就有点难办了。

首先用IDA加载Anti.exe，并加载题目所给的pdb文件——应该说出题人还是很好的（谢谢师兄~_~）。之后粗略浏览反汇编代码，主要有两点发现：
- 该程序应该由C++语言编写，因为有虚表和类层次关系
- 代码中添加了大量花指令



## 0x01  花指令分析

下面对代码中涉及到的花指令作基本分析

1.

```assembly
.text:00401A1B loc_401A1B:                             ; CODE XREF: .text:loc_401A1B↑j
.text:00401A1B                 jmp     short near ptr loc_401A1B+1
.text:00401A1D ; ---------------------------------------------------------------------------
.text:00401A1D                 ror     byte ptr [eax-73h], 45h
```

这是因为两条顺序执行的指令使用了一个公共byte，而IDA在反汇编完一条指令后，会从这条指令的下一个地址处开始反汇编，所以无法表示这种情况。具体来说，0x401a1b处是`0xeb`,0x401a1c处是`0xff`，IDA首先把0xeb翻译成jmp指令，然后往下找操作数，是短跳转+1；之后，就会顺序反汇编0x401a1d处的内容。但是程序在执行时实际上跳转到0x1a1c处执行，这就导致一个矛盾。

手工去掉花指令还原即可，暂时不用管那个垃圾字节，在脚本批量去除阶段可以Patch为NOP指令。

```assembly
.text:00401A14 ; ---------------------------------------------------------------------------
.text:00401A1B                 db 0EBh
.text:00401A1C ; ---------------------------------------------------------------------------
.text:00401A1C                 inc     eax
.text:00401A1E                 dec     eax
.text:00401A1F                 lea     eax, [ebp-34h]
```

2.

```assembly
.text:004019E5                 push    offset __ehhandler$?enc2@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@D@Z
.text:004019EA                 mov     eax, large fs:0
.text:004019F0                 push    eax
.text:004019F1                 mov     large fs:0, esp
......
.text:00401A4E                 xor     eax, eax
.text:00401A50                 idiv    eax
.text:00401A52                 retn
.text:00401A53                 db 8Bh
.text:00401A54                 dd 64082464h, 0A1h, 8B008B00h, 0A36400h, 83000000h, 5D5808C4h
......
```

这算是第二种花指令。0x4019e5处的四条指令首先将fs[0]压入堆栈，从而使得执行完成后，fs[0]指向栈顶。之后，构造一个err结构。在0x401a4e处，故意触发一个除零异常，然后就会进入异常处理流程。

同时，由于除零后是一条retn指令，IDA在反汇编时不会将retn的下一个地址识别为指令，直到找到一个函数头`push	ebp; mov	ebp, esp` ，这又使得反汇编出错。

详细的异常处理流程我们在静态分析阶段不好分析，如读者感兴趣可以详细查阅资料。但我们通过OD调试可以大体了解程序的控制流。

在0x401a50处下断，并在调试选项中去掉所有忽略异常的勾选，点击确定后F9断到断点处，然后F8单步调试，到达如下位置

```assembly
7C92E460    8B1C24          mov ebx,dword ptr ss:[esp]
7C92E463    51              push ecx
7C92E464    53              push ebx
7C92E465    E8 E6C40100     call ntdll.7C94A950
```

F7步入函数调用，然后继续单步跟，看到一个可疑位置，会将0x401a53的地址作为参数压栈，然后调用一个函数，步入函数。

```assembly
7C923261    FF7424 20       push dword ptr ss:[esp+0x20]             ; Anti.00401A53
7C923265    FF7424 20       push dword ptr ss:[esp+0x20]             ; Anti.00401A53
7C923269    FF7424 20       push dword ptr ss:[esp+0x20]             ; Anti.00401A53
7C92326D    FF7424 20       push dword ptr ss:[esp+0x20]             ; Anti.00401A53
7C923271    FF7424 20       push dword ptr ss:[esp+0x20]             ; Anti.00401A53
7C923275    E8 08000000     call ntdll.7C923282

```

果然，此处最终`call ecx`，使得eip跳转到0x401a53处执行。所以我们应该在0x401a53处按C识别为代码，修复反汇编。

```assembly
7C923289    64:FF35 0000000>push dword ptr fs:[0]
7C923290    64:8925 0000000>mov dword ptr fs:[0],esp
7C923297    FF75 14         push dword ptr ss:[ebp+0x14]
7C92329A    FF75 10         push dword ptr ss:[ebp+0x10]
7C92329D    FF75 0C         push dword ptr ss:[ebp+0xC]
7C9232A0    FF75 08         push dword ptr ss:[ebp+0x8]
7C9232A3    8B4D 18         mov ecx,dword ptr ss:[ebp+0x18]          ; Anti.00401A53
7C9232A6    FFD1            call ecx                                 ; Anti.00401A53
```

3.

```assembly
.text:00401A8A                 jz      near ptr loc_401A96+4
.text:00401A90                 jnz     near ptr loc_401A96+4
.text:00401A96
.text:00401A96 loc_401A96:                             ; CODE XREF: .text:00401A8A↑j
.text:00401A96                                         ; .text:00401A90↑j
.text:00401A96                 call    near ptr 0F733CACh
```

比起上面两种花指令，这一种都算小菜啦。构造连续两个互补的条件跳转到同一位置。因为条件跳转为基本块出口，诱导IDA反汇编基本块邻接地址为新的基本块入口。实际上只是几个字节的垃圾数据。简单修复即可。

```assembly
.text:00401A8A                 jz      loc_401A9A
.text:00401A90                 jnz     loc_401A9A
.text:00401A90 ; ---------------------------------------------------------------------------
.text:00401A96                 db 0E8h
.text:00401A97                 db  11h
.text:00401A98                 db  22h ; "
.text:00401A99                 db  33h ; 3
.text:00401A9A ; ---------------------------------------------------------------------------
.text:00401A9A
.text:00401A9A loc_401A9A:                             ; CODE XREF: .text:00401A8A↑j
.text:00401A9A                                         ; .text:00401A90↑j
```

4.

```assembly
.text:00401ACA                 xor     eax, eax
.text:00401ACC                 jz      near ptr loc_401AD2+1
.text:00401AD2
.text:00401AD2 loc_401AD2:                             ; CODE XREF: .text:00401ACC↑j
.text:00401AD2                 call    near ptr 0D085A62Fh
```

这种是构造一个恒真的条件跳转，再加上一个垃圾字节，很好理解。简单修复即可。

```assembly
.text:00401ACA                 xor     eax, eax
.text:00401ACC                 jz      loc_401AD3
.text:00401ACC ; ---------------------------------------------------------------------------
.text:00401AD2                 db 0E8h
.text:00401AD3 ; ---------------------------------------------------------------------------
.text:00401AD3
.text:00401AD3 loc_401AD3:                             ; CODE XREF: .text:00401ACC↑j
.text:00401AD3                 pop     eax
.text:00401AD4                 mov     eax, [ebp-30h]
```

分析到这里，第一个函数enc1的花指令我们已经完全去除了，在IDA中按F5可以进行反编译。不过在手动分析下一个函数后，按F5无法进行反编译。这是因为IDA没有将其识别为函数，我们在已修复的函数入口点处按P MakeProc即可。


<!-- more -->


## 0x02 脚本批量去除花指令

到这里相信手工去除花指令已经难不倒大家了，但是程序中显然有大量批量插入的花指令，如果一一通过手工去除，不太可行。这时候，我们可以借助IDAPython这个工具编写一个去除花指令的插件。[官方文档](https://www.hex-rays.com/products/ida/support/idapython_docs/)对于IDAPython的API有一定程度的讲解，但是这个东西还是有一定的学习成本的，如果感觉上手困难可以看一下Hex-Rays官方每年举办的IDA插件大赛的获奖作品（[链接在这](https://hex-rays.com/contests/)），学习一下。

这里先直接给出脚本。其实写的很不好，主要思路就是逐指令或逐字节遍历，然后对这几种花指令予以识别和去除。同时由于比较懒，直接设置remove函数执行5次，暴力解决递归问题。不过多执行几次是没有副作用的。

另外，执行脚本后，可能还会有极少量代码反汇编出错，在分析到相应函数后手工按C识别为代码即可。

```python
from ida_auto import *
from ida_bytes import *
from ida_ua import *

change = 0
startea = 0x4019e0
endea = 0x405230

def preprocess(curea = startea):
	while curea <= endea:
		auto_make_code(curea)
		curea = next_head(curea, endea)

def remove(curea = startea):
	while curea <= endea:
		# print hex(curea)
		if GetDisasm(curea) == "retn":
			MakeCode(curea + 1)
		if GetDisasm(curea).startswith("db") is True and GetDisasm(curea + 1).startswith("db") is False and GetDisasm(curea).endswith(")") is False:
			do_unknown(curea + 1)
			MakeCode(curea)
		for xref in XrefsFrom(curea, 1):
			# print hex(xref.frm), hex(xref.to)
			if xref.to - xref.frm == 1:
				if get_byte(xref.frm) == 0xeb:
					# print "yes"
					ea = xref.frm
					for i in range(20):
						do_unknown(ea)
						ea += 1
					ea = xref.to
					for i in range(20):
						MakeCode(ea)
						ea += 1

					patch_byte(xref.frm, 0x90)
					change = MakeCode(xref.frm)
			elif xref.to == next_head(curea, endea) + 1:
				if get_byte(xref.to - 1) == 0xe8:
					# print "yess"
					do_unknown(xref.to - 1)
					ea = xref.to
					for i in range(20):
						MakeCode(ea)
						ea += 1
					patch_byte(xref.to - 1, 0x90)
					MakeCode(xref.to - 1)
			elif xref.to == next_head(next_head(curea, endea), endea) + 4:
				tar_ea = next_head(next_head(curea, endea), endea)
				ea = tar_ea
				for i in range(20):
					do_unknown(ea)
					ea += 1
				ea = xref.to
				for i in range(20):
					MakeCode(ea)
					ea += 1
				ea = tar_ea
				for i in range(4):
					patch_byte(ea, 0x90)
					ea += 1
				ea = tar_ea
				for i in range(4):
					MakeCode(ea)
					ea += 1
		curea = next_head(curea, endea)
	AnalyseRange(startea,endea)

def recognize(curea = startea):
	while curea <= endea:
		if GetDisasm(curea) == "push    ebp" and GetDisasm(curea+1) == "mov     ebp, esp":
			print "should be make"
			auto_make_proc(curea)
		curea = next_head(curea, endea)
if __name__ == "__main__":
	preprocess()
	for i in range(5):
		remove()
	recognize()
```



## 0x03  加密算法分析与逆向

至此，我们已经解决了花指令问题，可以开始分析具体算法了。main函数中会调用encrypt函数加密，最后调用hexencode函数输出结果。

直接查看encrypt函数的F5代码，但是由于是C++程序，伪C代码比较乱，看不出所以然。不过我们可以明确encrypt函数中首先调用了enc2函数。其核心代码如下：

```assembly
.text:00401ABF                 call    j_?length@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBEIXZ ; std::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(void)
.text:00401AC4                 cmp     [ebp-30h], eax  ; cnt < 源字符串长度时
.text:00401AC7                 jnb     short loc_401B18
.text:00401AC9                 push    eax             ; 先push eax
.text:00401ACA                 xor     eax, eax        ; 花指令
.text:00401ACC                 jz      loc_401AD3      ; pop eax，恢复
.text:00401AD2                 nop
.text:00401AD3
.text:00401AD3 loc_401AD3:                             ; CODE XREF: .text:00401ACC↑j
.text:00401AD3                 pop     eax             ; pop eax，恢复
.text:00401AD4                 mov     eax, [ebp-30h]  ; eax = cnt
.text:00401AD7                 push    eax
.text:00401AD8                 lea     ecx, [ebp+0Ch]
.text:00401ADB                 call    j_??A?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAADI@Z ; 取源字符串中下标cnt处字符
.text:00401AE0                 movsx   ebx, byte ptr [eax] ; 放到ebx中
.text:00401AE3                 lea     ecx, [ebp-1Ch]
.text:00401AE6                 call    j_?length@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBEIXZ ; std::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(void)
.text:00401AEB                 mov     ecx, eax        ; 取字符串"2"的长度放到ecx中
.text:00401AED                 mov     eax, [ebp-30h]  ; eax = cnt
.text:00401AF0                 xor     edx, edx        ; 高位置0
.text:00401AF2                 div     ecx             ; cnt / "2"的长度
.text:00401AF4                 push    edx             ; 余数压栈
.text:00401AF5                 lea     ecx, [ebp-1Ch]
.text:00401AF8                 call    j_??A?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAADI@Z ; 取key[cnt%len(cip)]
.text:00401AFD                 movsx   edx, byte ptr [eax] ; 放在edx中
.text:00401B00                 xor     ebx, edx        ; ord[cnt] ^ key[cnt%len(cip)]
.text:00401B02                 movsx   eax, byte ptr [ebp+1Ch]
.text:00401B06                 xor     ebx, eax		   ; 再次与输入的密钥字符异或
.text:00401B08                 mov     ecx, [ebp-30h]
.text:00401B0B                 push    ecx
.text:00401B0C                 lea     ecx, [ebp-2Ch]
.text:00401B0F                 call    j_??A?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAADI@Z ; std::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](uint)
.text:00401B14                 mov     [eax], bl
```

这里0x401aeb处的操作比较有趣，这个字符串为什么是2呢？猜想到可能与函数名enc2的2有关，于是用OD调试enc3、enc5函数，发现这个串变成"3"和"5"，这说明果然与函数名有关。

调用enc2并在两次按位异或后，将结果存储并回到encrpyt函数体调用enc3，然后通过异常处理链调用enc5、enc8......，最后调用enc28657，最后得到加密结果。因此，加密算法的逻辑已经很清楚了，给出Python实现

```python
def encrypt(key):
	res = "thisisasimplesamplestring"
	for n in [2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,4181,6765,10946,17711,28657]:
		num = list(str(n))
		tmp = ""
		for i,b in enumerate(res):
			tmp += chr((((ord(b) ^ ord(num[i % len(num)]) & 0xff) ^ key) & 0xff))
		res = tmp
	flag = res
	return flag
```

为了求解flag，需要求解这个算法的逆算法。因为都是按位异或，很容易得到逆算法，并爆破所有可见字符即可catch flag。

最终脚本如下：

```python
def decrypt(key):
	encrypted = "\x3A\x3B\x31\x38\x23\x3B\x3C\x34\x37\x30\x0B\x37\x30\x07\x32\x28\x39\x35\x23\x06\x2E\x2B\x24\x2A"[::-1]
	for n in [2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,4181,6765,10946,17711,28657][::-1]:
		# print n
		num = list(str(n))
		tmp = ""
		for i,b in enumerate(encrypted):
			i = len(encrypted) - i - 1
			# print i
			tmp += chr((((ord(b) ^ key & 0xff) ^ ord(num[(i % len(num))])) & 0xff))
		encrypted = tmp
	flag = encrypted
	return flag
if __name__ == "__main__":
	for i in range(32, 126):
		print chr(i)
		res = decrypt(i)
		print res[::-1]
```

flag如下：

```
a
flag{ocean_of_junks_zzz}
```















