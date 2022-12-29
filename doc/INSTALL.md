# ly_probe 探针部署手册

​	**ly_probe 探针** 是一款用于解析网络流量、提取关键信息的探针软件，能够将流量或pcap文件解析后，提取并匹配指定数据内容后，以netflow格式传输至采集器。



​	**探针部署流量节点位置及检测能力**

| 流量节点位置          | 危险程度 | 威胁倾向                                                     |
| --------------------- | -------- | ------------------------------------------------------------ |
| 互联网-终端用户       | 高危     | 关注终端用户的上网安全问题，通过此节点流量识别用户与威胁来源的通信、判断是否受到远程控制，检测主机是否失陷。 |
| 互联网-DMZ区域        | 高危     | 关注互联网中面向企业对外服务器的威胁行为。                   |
| 互联网-内部服务器     | 高危     | 关注内部服务器对外暴露情况，关注内部服务器数据流出情况，检测服务器是否失陷 |
| 内部服务器-终端用户   | 危险     | 关注终端用户对服务器的攻击行为，检测异常终端用户，检测服务器所受到的威胁。 |
| 内部服务器-内部服务器 | 危险     | 关注服务器间横向攻击行为，检测失陷服务器与服务器所受到的威胁。 |





## 安装部署

### 文件结构

```
lyprobe.v1.0.0
├─ lyprobe              --主程序可执行文件
├─ liblyprobe-1.0.0.so  --主程序库文件
├─ liblyprobe.so        --主程序库文件
├─ liblyprobe.la        --主程序库文件
├─ plugins/             --插件相关文件
   ├─ fp-patterns            --匹配规则
   ├─ l7-patterns            --匹配规则
   ├─ libxxxPlugin-1.0.0.so  --插件库文件
   ├─ libxxxPlugin.so        --插件库文件
   ├─ libxxxPlugin.la        --插件库文件
```



### 运行环境

```
libpcap
PF_RING (可选)
```



### 部署程序

```
# 进入文件目录
cd lyprobe.v1.0.0

# 将主程序文件置于系统路径
cp ./lyprobe /usr/local/bin/

# 将依赖库文件置于系统路径
cp -d ./liblyprobe* /usr/local/lib/

# 将插件相关依赖库文件目录整体置于系统路径
cp -rd ./plugins /usr/local/lib/lyprobe/

```



## 验证运行

执行 ```lyprobe --version``` 成功返回版本信息，则部署成功。

```
# lyprobe --version

Welcome to lyprobe v.1.0.0 ($Revision: 2212 $) for x86_64-unknown-linux-gnu

Built on 12/27/22 10:07:54 AM
Copyright 2002-10 by Luca Deri <deri@ntop.org>

```
