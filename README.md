# 接口说明

### 1.

### 生成keystore。
方法：

WalletUtility. fromPassword()

### 参数：

密码：
password（String类型）

### 返回值：

{
"StatusCode": 0,
"Message":"",
"Content"：json格式keystore
}


### 2.

### 通过公钥哈希获取地址。
方法：

WalletUtility.pubkeyHashToAddress()

### 参数：

公钥哈希：
pubkeyHash（String类型）

### 返回值：

{

"StatusCode": 0,

"Message":address

"Content"：null

}

### 3.

### 通过地址获取公钥哈希。
方法：

WalletUtility.addressToPubkeyHash()

### 参数：

地址：
address（String类型）

### 返回值：

{

"StatusCode": 0,

"Message":pubkeyHash

"Content"：null

}

### 

### 4.

### 通过私钥获取公钥。
方法：

WalletUtility.prikeyToPubkey()

### 参数：


私钥：

prikey（String类型）

### 返回值：


{

"StatusCode": 0,

"Message":Pubkey

"Content"：null

}

### 

### 5.

### 地址有效性校验。
方法：

WalletUtility.verifyAddress()

### 参数：

地址：

address（String类型）

### 返回值：

{

"StatusCode": StatusCode,

"Message": Message，

"Content"：null

}

### 返回值说明：

{

StatusCode：返回数据状态:
                         0（正常）
                         -1（出错）

                         -2（出错）

Message：错误提示。
Content：null

}

### 

### 6.

### 更新地址。
方法：

WalletUtility.oldaddtonewadd()

### 参数：

需要更新的地址：

oldAddress（String类型）

### 返回值：

{

"StatusCode": 0,

"Message":newAddress

"Content"：null

}
