# sdn-lab

labs of Software Defined Network

## lab1

2层自学习交换机实现

## lab2

动态转发规则的改变和链路故障恢复

## lab3

不同类型的最短路生成，完整的控制器

network_awareness.py：负责调用 api，发现网络中的交换机、链路消息，建立网络拓扑。

delay_detector.py：负责通过发送、接收 echo 报文和 lldp 报文，获取网络各链路的时延信息。

Shortest_path.py：负责阻止 arp 洪泛、生成最短路并下发流表。

## lab4

veriflow

TODO: ...
