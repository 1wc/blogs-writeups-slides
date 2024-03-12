---
title: contribute_to_Apache
date: 2019-10-16 15:52:42
tags: [Dev,Big Data]
---

## 前言

由于实验室里项目需求等原因，笔者的硕士开题方向将会偏向大数据平台的安全。前些日子在调研历史CVE和issue过程中发现了一个有趣的访问控制问题，一开始尝试联系Apache安全团队但杳无音讯，最终考虑到问题的严重性比较低，于是决定提一个issue，成为contributer👋。

整个流程还是比较麻烦的，而且网上没有找到比较好的中文资料，在此整理一下自己的思路，如有错误，欢迎斧正。

p.s.: 本文所述的步骤主要基于Apache Sentry 的Wiki中的说明，其他项目或者会有少许不同。

<!-- more -->

##概述

成为contributer的主要方式有如下几种：

- 参与讨论：你可以订阅相应的mailing list，然后参与其中的讨论。
- 报告bug：如果你确定你发现了一个bug，那么可以直接在相应项目的JIRA提交（JIRA是一款项目与事务追踪的工具）；不过如果你不确定的话，可以先在mailing list中提出这个issue，并与开发者们一齐讨论
- Review Code：如果你看到一个JIRA ticket变成了`Patch Available`状态，你可以去review相应的代码。
- 提供补丁：你可以将assginee设置为自己，并且为解决此issue提供一个patch。这里的patch可以是代码、文档甚至编译的修改。
- 文档：最后，你也可以帮忙维护项目的Wiki

不过，我的目标主要是发现和解决安全问题，所以主要参与的是报告bug、编写补丁的工作。对开发和业务感兴趣的童鞋可以多关注下`mailing list`和`review board`。

## 一般流程

### 提交issue

首先，当我们发现了一个bug或者缺陷时，我们需要在JIRA提交issue。当然了，首先需要注册一个账号并登录。

![image-20191016170814599](/image/image-20191016170814599.png)

如图，需要设置所属的项目，issue的类型，还要用一句话做一个summary，然后设置优先级、影响版本等等内容。**其中Assignee需要特别注意，它指的是这个issue的credit是属于谁的，也就是哪个开发者最终修复了这个issue。**其实在开源社区中issue的reporter有时并不如assignee的“贡献”大：当你发现一个问题时，即使是严重的导致安全问题的缺陷，如果不给出patch，也不会获取像CVE编号那样具有效力的credit，因为issue是谁都可以提的。

如果你有信心或者说想自己解决这个问题，不妨勾选Assign to me，这样别的开发者就不会抢着提供patch。

然后，最好详细的描述问题和复现的步骤，也可以提供附件。最后点击Create就可以成功创建issue了。

### 提交patch和review请求

当你开发完成issue的patch后，你就可以上传patch并请求review了。

#### 本地测试

首先要在本地测试编译是否通过

```bash
mvn clean install --DskipTests
```

提示`BUILD SUCCESS`则表示成功

然后跑单元测试，注意如果patch提供了新特性或者修复了bug的话，最好要添加一个单元测试。

```
mvn test 
```

如果没有错误的话，说明你的代码已通过测试。

#### 创建patch

一般来说，Apache的JIRA要求patch的命名规则如下：

```
ISSUE ID.补丁编号.patch
```

例如我所提交的patch命名为：`SENTRY-2533.001.patch`。

```
git diff > /path/to/SENTRY-2533.001.patch
```

#### 提交patch

现在你可以在JIRA上将issue设置为`PATCH AVAILABLE`，并上传你的patch。上传成功后，将会在Jenkins上自动进行PreCommit的测试，也就是执行一次远程的build。整个过程无需手动操作，构建的结果会通过邮件发给你。这里我比较惨：我提交了好几次patch才远程编译成功，而报错并不是我的原因，是其他的单元测试没有通过。

成功后的截图如下：

![image-20191016184817438](/image/image-20191016184817438.png)

#### 提交review请求

此时我们需要在Apache的Review Board上提交review请求，只有开源社区内一个以上的reviewer给你ship it（也就是通过），我们才能够最终commit，并resolve issue。

建议大家使用rbt工具来提交review请求，步骤如下：

pip安装即可

```
sudo pip install -U RBTools
```

配置

```
vim ~/.reviewboardrc

REVIEWBOARD_URL = "https://reviews.apache.org/"
REPOSITORY = 'Sentry' # 根据项目改
TARGET_GROUPS = 'sentry' # 同上
```

然后git clone拉取代码仓库，再用rbt工具进行初始化（用你Review Board页面上的用户名和密码登录）：

```
rbt setup-repo --username=xx --password=xx

```

将自己的修改commit到本地仓库，注意添加相应的message。

```
git add .（或者指定路径）
git commit -m “SENTRY-2533: The UDF in_file should be blacked default"
```

然后运行rbt工具即可：

```
1wc@1wcsdeMacBook-Pro ./rbt post -g
Review request #71532 posted.
https://reviews.apache.org/r/71532/
https://reviews.apache.org/r/71532/diff/

```

这样就生成了相应的web链接，只需要手工访问上述链接，修改description、summary等条目。

#### 链接

最后一步，将rb的链接放在JIRA里，而将issue的链接放在rb里，即可。

## 总结

时间线主要是

19/9/20：创建issue

19/9/21：第一次上传patch

19/9/22：PreCommit成功

19/10/3：被Cloudera团队成员assign

19/10/15: review通过

19/12/13: 团队成员提交commit到master分支（https://github.com/apache/sentry/commit/f5dbc69b5c0ff6cae2606e58efd204df754e5232）

20/1/3    : 在新发行的Sentry 2.2中修复

继续努力！