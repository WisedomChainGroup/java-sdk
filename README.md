# APPSDK方法说明

APPSDK是提供给APP调用的方法，主要是提供给实现普通转账事务的构造，签名，发送以及孵化器相关的操作，对于RPC来说，提供若干的接口，对于客户端来说，需要提供若干的实现方法，如下所示：

1.0 基本说明

1）、事务类型

|编号	|交易类型	|说明	|
|---	|---	|---	|
|1	|0x01	|WDC转账	|
|---	|---	|---	|
|2	|0x09	|申请孵化	|
|3	|0x0a	|获取利息收益	|
|4	|0x0b	|获取分享收益	|
|5	|0x0c	|停止孵化	|

2）、区块确认完成
通过事务的哈希值查询确认区块数，并且确认是否已经完成，
我们认为往后确定2区块即可表示已经完成。
无论什么事务，都要等待至少2个区块确认才算完成

1.1 生成keystore文件

WalletUtility.generateKeystore()
参数：
* 1）、密码（String),
* 2）、路径（String)选填
* 返回类型：String
* 返回值：address

1.2 地址校验

WalletUtility.verifyAddress()
* 参数：
* 1）、地址字符串（String)
* 返回类型：int
* 返回值：
* 0（正常）

* -1（出错）地址前缀错误
* -2（出错）校验错误

1.3 通过地址获得公钥哈希

WalletUtility.addressToPubkeyHash()
* 参数：
* 1）、地址字符串（String)
* 返回类型：String（十六进制字符串）
* 返回值：pubkeyHash

1.4 通过公钥哈希获得地址

WalletUtility. pubkeyHashToAddress()
* 参数：
* 1）、公钥哈希（String)
* 返回类型：String
* 返回值：Address

1.5 通过keystore获得地址

WalletUtility.keystoreToAddress()
* 参数：
* 1）、keystore（String)
* 2）、密码（String)
* 返回类型：String
* 返回值：Address

1.6 通过keystore获得公钥哈希

WalletUtility. keystoreToPubkeyHash()
* 参数：
* 1）、keystore（String)
* 2）、密码（String)
* 返回类型：String
* 返回值：PubkeyHash

1.7 通过keystore获得私钥

WalletUtility. obtainPrikey()
* 参数：
* 1）、keystore（String)
* 2）、密码（String)
* 返回类型：String（十六进制字符串）
* 返回值：Prikey

1.8 通过keystore获得公钥

WalletUtility.keystoreToPubkey()
* 参数：
* 1）、keystore（String)
* 2）、密码（String)
* 返回类型：String（十六进制字符串）
* 返回值：Pubkey

1.9 导入keystore

WalletUtility. importKeystore()
* 参数：
* 1）、keystore（String)
* 2）、路径（String)选填
* 返回类型：String
* 返回值：Address

1.10 修改KeyStore密码方法

WalletUtility.modifyPassword()
* 参数：
* 1）、keystore（String)
* 2）、旧密码（String)
* 3）、新密码（String)
* 返回类型：json
* 返回值：Keystore

1.11 SHA3-256哈希方法

* SHA3Utility.HexStringkeccak256*()*
* 参数：
* 1）、哈希原文（字节数组)
* 返回类型：十六进制字符串
* 返回值：哈希值

1.12 Ripemd-160哈希方法

RipemdUtility.HexStringRipemd160*()*
* 参数：
* 1）、哈希原文（字节数组)
* 返回类型：十六进制字符串
* 返回值：哈希值

1.13 base58编码方法

Base58Utility.*encode ()*
* 参数：
* 1）、哈希原文（字节数组)
* 返回类型：String
* 返回值：哈希值

1.14 获得地址余额

WalletUtility. getBalance()
* 参数：
* 1）、地址（String)
* 返回类型：json
* 返回值：
* {
* data :null;
* (int)statusCode:0
* (String)message:余额（BigDecimal)
* }

1.15 根据事务哈希获得所在区块哈希以及高度

WalletUtility. getTransactioninfo ()
参数：
* 1）、事务哈希（十六进制字符串)
* 返回类型：json
* 返回值：
* {
* data :定义如下;
* (int)statusCode:0
* (String)message:null
* }
* data:
* {
* "blockHash":区块哈希(十六进制字符串), 
* "height":区块高度(Long)
* }

1.16 根据事务哈希获得确认区块数

WalletUtility. confirmedBlockNumber()
* 参数：
* 1）、事务哈希（十六进制字符串)
* 返回类型：json
* 返回值：
* {
* data :null;
* (int)statusCode:0
* (String)message:确认区块数（Long)
* }

1.17 创建原生转账事务

* TxUtility.CreateRawTransaction*()*
* 参数：
* 1）、发送者公钥（十六进制字符串)
* 2）、接收者公钥哈希（十六进制字符串)
* 3）、转账金额（BigDecimal)
* 返回类型：十六进制字符串
* 返回值：事务哈希

1.18 签名转账事务事务

TxUtility.signRawBasicTransaction*()*
* 参数：
* 1）、事务（十六进制字符串)
* 2）、私钥（十六进制字符串)
* 返回类型：十六进制字符串
* 返回值：事务哈希
* 返回事务十六进制字符串

1.19 广播转账事务

## 广播转账事务可以与1.20的封装方法合并

返回事务十六进制字符串
以下的三条事务，孵化申请、提取利息以及提取分享收益
补充下原生事务创建、签名以及发送的方法

1.20 发起转账申请-连接服务

本方法需要连接服务端
包含了三个连续的步骤：构造原声事务、签名以及发送

## 方法名修改为ClientToTransferAccount()

TxUtility. ClientToTransferAccount*()*
* 参数：
* 1）、发送者公钥（十六进制字符串)
* 2）、接收者公钥哈希（十六进制字符串)
* 3）、转账金额（BigDecimal)
* 4）、私钥（十六进制字符串)
* 返回类型：Json
* 返回值：
* {
* data :null;
* (int)statusCode:
* 1(成功)
* -1（失败）
* (String)message:返回事务哈希（十六进制字符串)
* }
* 注意，这里的成功或者失败，仅仅是指动作本身，真正看事务有没有最终成功，还需要通过事务哈希查询确认区块数

1.21 发起孵化申请

* 方法名修改为ClientToIncubateAccount()
* TxUtility. ClientToIncubateAccount*()*
* 参数：
* 1）、发送者公钥（十六进制字符串)
* 2）、接收者公钥哈希（十六进制字符串)
* 3）、金额（BigDecimal)
* 4）、私钥（十六进制字符串)
* 5）、分享者公钥哈希（十六进制字符串)
* 6）、孵化类型（int)
* 返回类型：Json
* 返回值：
* {
* data :null;
* (int)statusCode:
* 1(成功)
* -1（失败）
* (String)message:返回事务哈希（十六进制字符串）
* }
* 无论成功与否，都返回事务哈希

1.22 提取收益

TxUtility. ClientToIncubateProfit *()*
参数：
* 1）、发送者公钥（十六进制字符串)
* 2）、接收者公钥哈希（十六进制字符串)
* 3）、收益（BigDecimal)
* 4）、私钥（十六进制字符串)
* 5）、孵化的事务哈希（十六进制字符串)
* 返回类型：Json
* 返回值：
* {
* data :null;
* (int)statusCode:
* 1(成功)
* -1（失败）
* (String)message:事务哈希（十六进制字符串）
* }

1.23 提取分享收益

TxUtility.ClientToIncubateShareProfit ()
* 参数：
* 1）、发送者公钥（十六进制字符串)
* 2）、接收者公钥哈希（十六进制字符串)
* 3）、分享收益（BigDecimal)
* 4）、私钥（十六进制字符串)
* 5）、孵化的事务哈希（十六进制字符串)
* 返回类型：Json
* 返回值：
* {
* data :null;
* (int)statusCode:
* 1(成功)
* -1（失败）
* (String)message:事务哈希（十六进制字符串）
* }

1.24 提取本金

TxUtility. ClientToIncubatePrincipal()
* 参数：
* 1）、发送者公钥（十六进制字符串)
* 2）、接收者公钥哈希（十六进制字符串)
* 3）、本金（BigDecimal)
* 4）、私钥（十六进制字符串)
* 5）、孵化的事务哈希（十六进制字符串)
* 返回类型：Json
* 返回值：
* {
* data :null;
* (int)statusCode:
* 1(成功)
* -1（失败）
* (String)message:事务哈希（十六进制字符串）
* }

1.25 获取事务对象

TxUtility. byteToTransaction()
* 参数：
* 1）、事务哈希（十六进制字符串)
* 返回类型：Json
* 返回值：
* {
* data : Transaction;
* (int)statusCode:0
* (String)message:null
* }

1.26 本地参数配置

最低手续费，默认为0.002wdc
余额可见区块确认数：2

1.27 注意点

* 1）、与服务端之间的参数传递，采用JSON格式
并且使用protobuf字节传递
* 2）、第一版使用客户端主动调用服务端API进行数据的更新，后续再更换为消息事件的方式
* 3）、只要是调用RPC-API的，返回格式都是
* {
*     “data” :,
*     “statusCode”:int,
*     “message”:String
* }

1.28 命令行实现

假设SDK编译后的程序名为wcli
* [Image: image.png]在main方法中调用一个CLIInterface.call传入的参数为main方法中的args参数数组
CLIInterface类中定义若干的参数处理方法
我们实现几个命令行操作
* 1）、wcli -accountnew
* –password <password> -path<path>(选填) –batch<batch>(数量,选填)
* 在程序所在目录下自动创建一个wisdo m_keystore文件夹，并且创建相应的keystore
* 2）、wcli -addresstopubkeyhash  
* -address <address>传入参数为地址字符串
返回公钥哈希
* 3）、wcli -keystoretoaddress
* path<keystore-file path>-password<password>
* 传入keystore路径返回address
* 4）、wcli -keystoretopubkeyhash
* -path<keystore-filepath>-password<password>
返回公钥哈希
* 5）、wcli–connect
* -ip<ip> -port<port>
* 连接rpc
传入参数为IP地址、端口号
返回值为true/false
