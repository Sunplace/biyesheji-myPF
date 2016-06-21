# biyesheji - personal firewall based on packet filter
## develope kit (开发工具)
gcc 编译器,GNU make工具,python环境,qt5-designer工具，iptables工具
## develope language (开发语言)
c,python,shell脚本
## environment (运行环境)
linux
## dependencies (运行时需要)
libnetfilter_queue.x86_64,iptables,python,PyQt4,python-psutil
## download and installation(下载与安装)
    git clone https://github.com/Sunplace/biyesheji-myPF.git
    cd biyesheji-myPF
    make
## usage（使用方法）
read help information for more information
(查看帮助获取更多信息)
start the pf as daemon mode (运行防火墙)
~~~~
# ./pf.out -D
~~~~
help information (帮助信息)
~~~~
    $ ./pf.out --help
~~~~
add rule (添加过滤规则)
~~~~
    $ ./pf.out -a [direction] [local port] [remote address] [remote port] [protocol] [target]
~~~~
direction : IN,OUT 连接方向：IN,OUT  
local port : >0 and <65536 本地端口：大于0,并且小于65536  

remote address : xxx.xxx.xxx.xxx/xx 远程地址：点分十进制地址，或者子网    
remote port : >0 and <65536 本地端口：大于0,并且小于65536  
protocol : TCP,UDP 协议：TCP或者UDP  
target : DROP,ACCEPT 去向：DROP或者ACCEPT
for example (例如：)
~~~~
    $ ./pf.out -a OUT - 8.8.8.8 53 UDP DROP
~~~~
‘-’ represent all port or address
## GUI for pf (用户图形界面)
cd biyesheji-myPF/gui-cn
python my-gui.py
## configuration
the out_rule_file and the in_rule_file must be the same directory with pf.out.  
配置文件out_rule_file和in_rule_file必须和pf.out可执行文件处于同一个文件夹。
