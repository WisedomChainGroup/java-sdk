# APPSDK方法说明

APPSDK是提供给APP调用的方法，主要是提供给实现普通转账事务的构造，签名，发送以及孵化器相关的操作，对于RPC来说，提供若干的接口，对于客户端来说，需要提供若干的实现方法，如下所示：

## 1.0 基本说明

1）、区块确认完成

通过事务的哈希值查询确认区块数，并且确认是否已经完成，
我们认为往后确定2区块即可表示已经完成。
无论什么事务，都要等待至少2个区块确认才算完成

2）、返回格式
##### {"message":"","data":[],"statusCode":int}
* message：描述
* data   ：数据
* statusCode：      

## 2.0 JAVA-SDK文档

1.1 生成keystore文件
```
 WalletUtility.fromPassword()
参数：
 1）、密码（String)
 返回类型：json
 返回值：keystore
```

1.2 地址校验
```
 WalletUtility.verifyAddress()
 参数：
 1）、地址字符串（String)
 返回类型：int
 返回值：
 0（正常）
 -1（出错）地址前缀错误
 -2（出错）校验错误
```

1.3 通过地址获得公钥哈希
```
 WalletUtility.addressToPubkeyHash()
 参数：
 1）、地址字符串（String)
 返回类型：String（十六进制字符串）
 返回值：pubkeyHash
```
1.4 通过公钥哈希获得地址
```
 WalletUtility. pubkeyHashToAddress()
 参数：
 1）、公钥哈希（String)
 返回类型：String
 返回值：Address
```
1.5 通过keystore获得地址
```
 WalletUtility.keystoreToAddress()
 参数：
 1）、keystore（String)
 2）、密码（String)
 返回类型：String
 返回值：Address
```
1.6 通过keystore获得公钥哈希
```
 WalletUtility. keystoreToPubkeyHash()
 参数：
 1）、keystore（String)
 2）、密码（String)
 返回类型：String
 返回值：PubkeyHash
```
1.7 通过keystore获得私钥
```
 WalletUtility. obtainPrikey()
 参数：
 1）、keystore（String)
 2）、密码（String)
 返回类型：String（十六进制字符串）
 返回值：Prikey
```
1.8 通过keystore获得公钥
```
 WalletUtility.keystoreToPubkey()
 参数：
 1）、keystore（String)
 2）、密码（String)
 返回类型：String（十六进制字符串）
 返回值：Pubkey
```
1.9 导入keystore
```
WalletUtility. importKeystore()
 参数：
 1）、keystore（String)
 2）、路径（String)选填
 返回类型：String
 返回值：Address
```
1.10 修改KeyStore密码方法
```
 WalletUtility.modifyPassword()
 参数：
 1）、keystore（String)
 2）、旧密码（String)
 3）、新密码（String)
 返回类型：json
 返回值：Keystore
```
1.11 SHA3-256哈希方法
```
 SHA3Utility.HexStringkeccak256()
 参数：
 1）、哈希原文（字节数组)
 返回类型：十六进制字符串
 返回值：哈希值
```
1.12 Ripemd-160哈希方法
```
 RipemdUtility.HexStringRipemd160()
 参数：
 1）、哈希原文（字节数组)
 返回类型：十六进制字符串
 返回值：哈希值
```
1.13 base58编码方法
```
 Base58Utility.encode ()
 参数：
 1）、哈希原文（字节数组)
 返回类型：String
 返回值：哈希值
``` 
1.14 创建原生转账事务
```
 TxUtility.CreateRawTransaction()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、接收者公钥哈希（十六进制字符串)
 3）、转账金额(BigDecimal)
 4）、Nonce(Long)
 返回类型：十六进制字符串
 返回值：未签名的事务哈希
```
1.15 签名事务
```
 TxUtility.signRawBasicTransaction()
 参数：
 1）、事务（十六进制字符串)
 2）、私钥（十六进制字符串)
 返回类型：十六进制字符串
 返回值：已签名事务哈希
```
1.16 发起转账申请
```
 TxUtility. ClientToTransferAccount()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、接收者公钥哈希(十六进制字符串)
 3）、转账金额（BigDecimal)
 4）、私钥（十六进制字符串)
 5）、Nonce(Long)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
 ```
 1.18 发起存证事务
 ```
 TxUtility. ClientToTransferProve()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、存证内容（字节数组）
 3）、Nonce(Long)
 4）、发送者私钥（十六进制字符串）
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
 ```
 
 1.19 发起投票事务
 ```
 TxUtility.ClientToTransferVote()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、接收者公钥哈希(十六进制字符串)
 3）、票数（Long）
 4）、Nonce(Long)
 5）、发送者私钥（十六进制字符串）
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```

1.20 发起投票撤回事务
 ```
 TxUtility.ClientToTransferVoteWithdraw()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、接收者公钥哈希(十六进制字符串)
 3）、票数（Long，必须与投票数保持一致）
 4）、Nonce(Long)
 5）、发送者私钥（十六进制字符串）
 6）、投票事务哈希（十六进制字符串）
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```

1.21 发起抵押事务（只能给自己抵押）
 ```
 TxUtility.ClientToTransferMortgage()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、接收者公钥哈希(十六进制字符串)
 3）、金额（Long）
 4）、nonce（Long）
 5）、发送者私钥(十六进制字符串)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```

1.22 发起抵押撤回事务
 ```
 TxUtility.ClientToTransferMortgageWithdraw()
 参数：
 1）、发送者公钥(十六进制字符串)
 2）、接收者公钥哈希(十六进制字符串)
 3）、金额（Long，金额必须与抵押的保持一致）
 4）、nonce（Long）
 5）、抵押事务哈希(十六进制字符串)
 6）、发送者私钥(十六进制字符串)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```


* 注意，这里的成功或者失败，仅仅是指动作本身，真正看事务有没有最终成功，还需要通过事务哈希查询确认区块数

1.23 发起孵化申请(孵化器)
```
 TxUtility. ClientToIncubateAccount()
 参数：
 1）、发送者公钥（十六进制字符串)
 2）、接收者公钥哈希（十六进制字符串)
 3）、金额（BigDecimal)
 4）、私钥（十六进制字符串)
 5）、分享者公钥哈希（十六进制字符串)
 6）、孵化类型（int)
 7）、Nonce(Long)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```
1.24 提取收益(孵化器)
```
 TxUtility. ClientToIncubateProfit()
参数：
 1）、发送者公钥（十六进制字符串)
 2）、接收者公钥哈希（十六进制字符串)
 3）、收益（BigDecimal)
 4）、私钥（十六进制字符串)
 5）、孵化的事务哈希（十六进制字符串)
 6）、Nonce(Long)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```
1.25 提取分享收益(孵化器)
```
 TxUtility.ClientToIncubateShareProfit ()
 参数：
 1）、发送者公钥（十六进制字符串)
 2）、接收者公钥哈希（十六进制字符串)
 3）、分享收益（BigDecimal)
 4）、私钥（十六进制字符串)
 5）、孵化的事务哈希（十六进制字符串)
 6）、Nonce(Long)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```
1.26 提取本金(孵化器)
```
 TxUtility. ClientToIncubatePrincipal()
 参数：
 1）、发送者公钥（十六进制字符串)
 2）、接收者公钥哈希（十六进制字符串)
 3）、本金（BigDecimal)
 4）、私钥（十六进制字符串)
 5）、孵化的事务哈希（十六进制字符串)
 6）、Nonce(Long)
 返回类型：Json
 返回值：
 {
 data :txHash(事务哈希，十六进制字符串)
 (int)statusCode:0
 (String)message:traninfo（已签名事务，十六进制字符串)
 }
```
1.27 获取事务对象
```
 TxUtility. byteToTransaction()
 参数：
 1）、事务哈希（十六进制字符串)
 返回类型：Json
 返回值：
 {
 data : Transaction;
 (int)statusCode:0
 (String)message:null
 }
```
### 节点rpc
1.0 获取Nonce
```
*   方法：sendNonce(POST)     
*	参数：pubkeyhash(String)  
*	返回：
*	{"message":"","data":[],"statusCode":int}
*	data:Nonce(Long)
```

1.1 获取余额
```
*   方法：sendBalance(POST)   
*	参数：pubkeyhash(十六进制字符串) 	
* 	返回:
* 	{"message":"","data":[],"statusCode":int}
*	data:balance(Long)
```

1.2 广播事务
```
*   方法： sendTransaction(POST)	
*	参数：traninfo(String)
*	返回：
* 	{"message":"","data":[],"statusCode":int}
```
        
1.3 查询当前区块高度
```
*   方法：height(GET)
*	返回：
*	{"message":"","data":0,"statusCode":int}
*	data:height(Long)
```
		
1.4 根据事务哈希获得所在区块哈希以及高度
```
*   方法：blockHash(GET)
*	参数：txHash(String)
*	返回：
*	{
*	data :定义如下;
*   statusCode(int):int
*	message(String):""
*    }
*    data:
*   {
*   "blockHash":区块哈希(十六进制字符串), 
*   "height":区块高度(Long)
*   }
```

1.5 根据事务哈希获得区块确认状态(GET)
```
*   方法：transactionConfirmed
*	参数：txHash(String)
*	返回： 
*   {"message":"","data":[],"statusCode":int}
*   statusCode: status(int)
```

1.6 根据区块高度获取事务列表
```
*   方法: getTransactionHeight(POST) 
*   参数: int height 区块高度
*   返回格式:{"message":"SUCCESS","data":[],"statusCode":1}
*   data格式:
*	String block_hash; 区块哈希16进制字符串
*	long height; 区块高度
*	int version; 版本号
*	String tx_hash; 事务哈希16进制字符串
*	int type;  事务类型
*	long nonce;nonce
*	String from;  发起者公钥16进制字符串
*	long gas_price; 事务手续费单价
*	long amount; 金额
*	String payload; payload数据
*	String signature; 签名16进制字符串
*	String to;  接受者公钥哈希16进制字符串
```

1.7 通过事务哈希获取事务
```
    方法：transaction\(事务哈希) (GET)
    返回:{"message":"SUCCESS","data":[],"statusCode":1}
    data格式:
    {
      "transactionHash": "e75d61e1b872f67cccc37c4a5b354d21dd90a20f04a41a8536b9b6a1b30ccf41", // 事务哈希
      "version": 1, // 事务版本 默认为 0
      "type": 0,  // 事务类型 0 是 coinbase 1 是 转账
      "nonce": 5916, // nonce 值，用于防止重放攻击
      "from": "0000000000000000000000000000000000000000000000000000000000000000", // 发送者的公钥， 用于验证签名
      "gasPrice": 0, // gasPrice 用于计算手续费
      "amount": 2000000000, // 交易数量，单位是 brain
      "payload": null, // payload 用于数据存证，一般填null
      "to": "08f74cb61f41f692011a5e66e3c038969eb0ec75", // 接收者的地址
      "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", // 签名
      "blockHash": "e2ccac56f58adb3f2f77edd96645931fac93dd058e7da21421d95f2ac9cc44ac", // 事务所在区块的哈希
      "fee": 0,  // 手续费
      "blockHeight": 13026 // 事务所在区块高度
}
```

1.8 通过区块哈希获取事务列表
```
*   方法：getTransactionBlcok(POST)
*   参数 String blockhash 区块哈希16进制字符串
*   返回格式:{"message":"SUCCESS","data":[],"statusCode":1}
*   data格式:
*	String block_hash; 区块哈希16进制字符串
*	long height; 区块高度
*	int version; 版本号
*	String tx_hash; 事务哈希16进制字符串
*	int type;  事务类型
*	long nonce;nonce
*	String from;  发起者公钥16进制字符串
*	long gas_price; 事务手续费单价
*	long amount; 金额
*	String payload; payload数据
*	String signature; 签名16进制字符串
*	String to;  接受者公钥哈希16进制字符串
```

1.28 连接孵化器节点(孵化器)
* token http连接中，headers上加token字段，参数为NUMtD0dEXungVX7eLuXkEurH5BCJzw  String类型
* 所有同步节点都传 int类型 高度字段：height
URL http://XXXX:19585/WisdomCore/+对应同步后缀

1.29 转账同步(孵化器)
```
 sendTransferList
 返回：Json格式
 {"message":"SUCCESS","data":[],"statusCode":1}
 statusCode：1是正常，-1是不正常
 message：返回成功或错误信息
 data：返回json格式的信息
 data信息如下：
 private java.lang.String coinAddress;//   钱包地址
 private java.lang.String fromAddress;//   出账钱包地址
 private BigDecimal amount;//   领取金额
 private java.lang.String tranHash;//   区块hash
 private java.lang.Long coinHeigth;//   区块高度
 private BigDecimal fee;//   手续费
 ```
1.30 孵化同步(孵化器)
```
 sendHatchList
 返回：json格式，参数同上
 data信息如下:
 private java.lang.String coinAddress;//   钱包地址
 private BigDecimal coinAccount;//   孵化资产
 private java.lang.String inviteAddress;//   邀请人地址
 private java.lang.String coinHash;//   孵化事务hash
 private java.lang.Long blockHeight;//   孵化事务区块高度
 private java.lang.Integer blockType;//   孵化类型（120：120天，365：365天）
```
1.31 利息同步(孵化器)
```
 sendInterestList
 返回：json格式，参数同上
 data信息如下:
 private java.lang.String coinHash;//   孵化事务hash
 private java.lang.String coinAddress;//   钱包地址
 private BigDecimal amount;//   领取金额
 private java.lang.String tranHash;//   区块Hash
 private java.lang.Long coinHeigth;//   区块高度
 private String inviteAddress;     //   分享者地址
``` 
1.32 分享同步(孵化器)
```
 sendShareList
 返回：json格式，参数同上
 data信息如下:
 private java.lang.String coinAddress;//   钱包地址
 private java.lang.String inviteAddress;//   推荐人钱包地址
 private java.lang.String coinHash;//   区块事务hash
 private BigDecimal amount;//   领取金额
 private java.lang.String tranHash;//   推荐孵化单的事务hash
 private java.lang.Long coinHeigth;//   区块高度
```

1.33 获取当前可提取利息(孵化器)
```
getNowInterest（POST）
参数：coinHash（孵化的事务哈希）
返回：json格式，参数同上
data信息如下:
dueinAmount：可提取利息（不计算是否到期）
capitalAmount:当前利息总余额
```

1.34 获取当前可提取分享收益(孵化器)
```
getNowShare（POST）
参数：coinHash（孵化的事务哈希）
返回：json格式，参数同上
data信息如下:
dueinAmount：可提取利息（不计算是否到期）
capitalAmount:当前利息总余额
```

1.35 本地参数配置

最低手续费，默认为0.002wdc
余额可见区块确认数：2

1.36 注意点

* 1）、与服务端之间的参数传递，采用JSON格式
并且使用protobuf字节传递
* 2）、第一版使用客户端主动调用服务端API进行数据的更新，后续再更换为消息事件的方式
* 3）、只要是调用RPC-API的，返回格式都是
```
 {
 “data” :,
 “statusCode”:int,
 “message”:String
 }
```

1.37 浏览器信息
```
方法：WisdomCore\ExplorerInfo（GET）
参数：无
返回：{"message": "SUCCESS","data": {},"code": 2000}
data格式: 
	{
        "blocksCount": 8547,//24小时内的出块数量
        "target": "000019b936ba20a901082aca448779aaf1ed4c03204ea6cec85e5cd851c5e956",//难度值
        "averageBlockInterval": 10.44,//最近十个区块的平均出块时间
        "averageFee": 0,//平均手续费
        "pendingTransactions": 0,//在pending中的事务数
        "queuedTransactions": 0,//在queued中的事务数
        "lastConfirmedHeight": 15002,//已经写入库的区块数
        "bestHeight": 15005//forkDB中的区块数
    },
    "code": 2000
```
1.38 地址的投票信息
```
方法：votes\（地址）（GET）
参数：token=NUMtD0dEXungVX7eLuXkEurH5BCJzw（放在header里面）
返回："0000000000000000000000000000": {}
data格式:
    "1DjBbTrnf3jiDp4z8zucZc8E8rxhGmFXVz": {
        "address": "1DjBbTrnf3jiDp4z8zucZc8E8rxhGmFXVz",//投票地址
        "amount": 205000000000,//投票数量
        "accumulated": 3475608//衰减后的投票权益
    }
```

2. 命令行实现

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




