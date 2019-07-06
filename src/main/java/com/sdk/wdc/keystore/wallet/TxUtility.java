package com.sdk.wdc.keystore.wallet;

import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.sdk.wdc.ApiResult.APIResult;
import com.sdk.wdc.account.Transaction;
import com.sdk.wdc.encoding.BigEndian;
import com.sdk.wdc.keystore.crypto.RipemdUtility;
import com.sdk.wdc.keystore.crypto.SHA3Utility;
import com.sdk.wdc.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.sdk.wdc.keystore.util.ByteUtil;
import com.sdk.wdc.protobuf.HatchModel;
import com.sdk.wdc.protobuf.ProtocolModel;
import net.sf.json.JSONObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import sun.tools.jar.resources.jar;

import java.io.*;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;

public class TxUtility {
    private static final Long rate= 100000000L;
    public static final String node = "http://192.168.0.101:19585/sendTransaction";
    public static final String node2 = "http://localhost:19585/block";
    private static final Long serviceCharge= 200000L;

    /**
     * 构造交易事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @return
     * @throws DecoderException
     */
    public static String CreateRawTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount) throws DecoderException {
        //版本号
        byte[] version=new byte[1];
        version[0]=0x01;
        //类型：WDC转账
        byte[] type=new byte[1];
        type[0]=0x01;
        //Nonce 无符号64位
        byte[] nonece= BigEndian.encodeUint64(1);
//        byte[] nonce=ByteUtil.encodeUint64(100000000);
        //签发者公钥哈希 20字节
        byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
        //gas单价
        byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(50000L,serviceCharge));
        //转账金额 无符号64位
        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
        byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
        //为签名留白
        byte[] signull=new byte[64];
        //接收者公钥哈希
        byte[] toPubkeyHash=Hex.decodeHex(toPubkeyHashStr.toCharArray());
        //长度
        byte[] allPayload= BigEndian.encodeUint32(0);
        byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
        String RawTransactionStr = Hex.encodeHexString(RawTransaction);
        return  RawTransactionStr;
    }

    /**
     * 构造申请孵化事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param sharepubkeyhash
     * @param hatchType
     * @return
     * @throws DecoderException
     */
    public static String CreateRawHatchTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String sharepubkeyhash, Integer hatchType) throws DecoderException {
        //版本号
        byte[] version=new byte[1];
        version[0]=0x01;
        //类型：申请孵化
        byte[] type=new byte[1];
        type[0]=0x09;
        //Nonce 无符号64位
        byte[] nonece=BigEndian.encodeUint64(1);
//        byte[] nonce=ByteUtil.encodeUint64(100000000);
        //签发者公钥哈希 20字节
        byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
        //gas单价
        byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(80000L,serviceCharge));
        //孵化本金 无符号64位
        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
        byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
        //为签名留白
        byte[] signull=new byte[64];
        //接收者公钥哈希
        byte[] toPubkeyHash=Hex.decodeHex(toPubkeyHashStr.toCharArray());

        //构造payload
        HatchModel.Payload.Builder payloads = HatchModel.Payload.newBuilder();
        payloads.setTxId(ByteString.copyFrom(BigEndian.encodeUint32(0)));
        if (sharepubkeyhash != null){
            payloads.setSharePubkeyHash(sharepubkeyhash);
        }else{
            byte[] nullPubkeyHash = new byte[20];
            payloads.setSharePubkeyHash(Hex.encodeHexString(nullPubkeyHash));
        }
        payloads.setType(hatchType);
        byte[] payload = payloads.build().toByteArray();
        //长度
        byte[] payloadleng= BigEndian.encodeUint32(payload.length);
        byte[] allPayload=ByteUtil.merge(payloadleng,payload);
        byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
        String RawTransactionStr = Hex.encodeHexString(RawTransaction);
        return  RawTransactionStr;
    }

    /**
     *构造利息收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     * @throws DecoderException
     */
    public static String CreateRawProfitTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid) throws DecoderException {
        //版本号
        byte[] version=new byte[1];
        version[0]=0x01;
        //类型：申请孵化
        byte[] type=new byte[1];
        type[0]=0x0a;
        //Nonce 无符号64位
        byte[] nonece=BigEndian.encodeUint64(1);
//        byte[] nonce=ByteUtil.encodeUint64(100000000);
        //签发者公钥哈希 20字节
        byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
        //gas单价
        byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(80000L,serviceCharge));
        //收益 无符号64位
        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
        byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
        //为签名留白
        byte[] signull=new byte[64];
        //接收者公钥哈希
        byte[] toPubkeyHash=Hex.decodeHex(toPubkeyHashStr.toCharArray());

        //构造payload
        byte[] payload = Hex.decodeHex(txid.toCharArray());
        //长度
        byte[] payloadleng= BigEndian.encodeUint32(payload.length);
        byte[] allPayload=ByteUtil.merge(payloadleng,payload);
        byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
        String RawTransactionStr = Hex.encodeHexString(RawTransaction);
        return  RawTransactionStr;
    }

    /**
     *构造分享收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     * @throws DecoderException
     */
    public static String CreateRawShareProfitTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid) throws DecoderException {
        //版本号
        byte[] version=new byte[1];
        version[0]=0x01;
        //类型：申请孵化
        byte[] type=new byte[1];
        type[0]=0x0b;
        //Nonce 无符号64位
        byte[] nonece=BigEndian.encodeUint64(1);
//        byte[] nonce=ByteUtil.encodeUint64(100000000);
        //签发者公钥哈希 20字节
        byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
        //gas单价
        byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(80000L,serviceCharge));
        //分享收益 无符号64位
        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
        byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
        //为签名留白
        byte[] signull=new byte[64];
        //接收者公钥哈希
        byte[] toPubkeyHash=Hex.decodeHex(toPubkeyHashStr.toCharArray());
        //构造payload
        byte[] payload = Hex.decodeHex(txid.toCharArray());
        //长度
        byte[] payloadleng= BigEndian.encodeUint32(payload.length);
        byte[] allPayload=ByteUtil.merge(payloadleng,payload);
        byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
        String RawTransactionStr = Hex.encodeHexString(RawTransaction);
        return  RawTransactionStr;
    }

    /**
     * 构造提取本金
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     * @throws DecoderException
     */
    public static String CreateRawHatchPrincipalTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid) throws DecoderException {
        //版本号
        byte[] version=new byte[1];
        version[0]=0x01;
        //类型：申请孵化
        byte[] type=new byte[1];
        type[0]=0x0c;
        //Nonce 无符号64位
        byte[] nonece=BigEndian.encodeUint64(1);
//        byte[] nonce=ByteUtil.encodeUint64(100000000);
        //签发者公钥哈希 20字节
        byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
        //gas单价
        byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(80000L,serviceCharge));
        //本金 无符号64位
        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
        byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
        //为签名留白
        byte[] signull=new byte[64];
        //接收者公钥哈希
        byte[] toPubkeyHash=Hex.decodeHex(toPubkeyHashStr.toCharArray());
        //构造payload
        byte[] payload = Hex.decodeHex(txid.toCharArray());
        //长度
        byte[] payloadleng= BigEndian.encodeUint32(payload.length);
        byte[] allPayload=ByteUtil.merge(payloadleng,payload);
        byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
        String RawTransactionStr = Hex.encodeHexString(RawTransaction);
        return  RawTransactionStr;
    }

    /**
     * 构建签名事务
     * @param RawTransactionHex
     * @param prikeyStr
     * @return
     * @throws Exception
     */
    public static String signRawBasicTransaction(String RawTransactionHex, String prikeyStr) throws Exception {
//        //接收者公钥哈希
//        byte[] toPubkeyHash = (byte[]) map.get("toPubkeyHash");

//        //签名原文数据
//        byte[] RawTransaction = (byte[]) map.get("RawTransaction");
//        byte[] start = (byte[]) map.get("start");
//        byte[] end = (byte[]) map.get("end");
//        byte[] RawTransactionNoSig = (byte[])map.get("RawTransactionNoSig");
//        byte[] allPayload = (byte[])map.get("allPayload");
        ////签名原文
        //        byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
//        byte[] RawTransactionNoSig=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount);

        byte[] RawTransaction = Hex.decodeHex(RawTransactionHex.toCharArray());
        //私钥字节数组
        byte[] privkey = Hex.decodeHex(prikeyStr.toCharArray());
        //version
        byte[] version = ByteUtil.bytearraycopy(RawTransaction, 0, 1);
        //hash
//        byte[] hash = ByteUtil.bytearraycopy(msg, 0, 32);
        //type
        byte[] type = ByteUtil.bytearraycopy(RawTransaction, 1, 1);
        //nonce
        byte[] nonce = ByteUtil.bytearraycopy(RawTransaction, 2, 8);
        //from
        byte[] from = ByteUtil.bytearraycopy(RawTransaction, 10, 32);
        //gasprice
        byte[] gasprice = ByteUtil.bytearraycopy(RawTransaction, 42, 8);
        //amount
        byte[] amount = ByteUtil.bytearraycopy(RawTransaction, 50, 8);
        //signo
        byte[] signo = ByteUtil.bytearraycopy(RawTransaction, 58, 64);
        //to
        byte[] to = ByteUtil.bytearraycopy(RawTransaction, 122, 20);;
        //payloadlen
        byte[] payloadlen = ByteUtil.bytearraycopy(RawTransaction, 142, 4);
        //payload
        byte[] payload = ByteUtil.bytearraycopy(RawTransaction, 144, (int)BigEndian.decodeUint32(payloadlen));
        byte[] RawTransactionNoSign=ByteUtil.merge(version,type,nonce,from,gasprice,amount,signo,to,payloadlen,payload);
        byte[] RawTransactionNoSig=ByteUtil.merge(version,type,nonce,from,gasprice,amount);
        //签名数据
        byte[] sig=new Ed25519PrivateKey(privkey).sign(RawTransactionNoSign);
        byte[] transha= SHA3Utility.sha3256(ByteUtil.merge(RawTransactionNoSig,sig,to,payloadlen,payload));
        byte[] signRawBasicTransaction = ByteUtil.merge(version,transha,type,nonce,from,gasprice,amount,sig,to,payloadlen,payload);
        String signRawBasicTransactionHex = Hex.encodeHexString(signRawBasicTransaction);
        return signRawBasicTransactionHex;
    }


    /**
     * 构造签名的交易事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @return
     * @throws Exception
     */
    public static JSONObject ClientToTransferAccount(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr) throws Exception {
//        HashMap map = CreateRawTransaction(fromPubkeyStr, toPubkeyHashStr, amount,GasPrice);
//        HashMap map2 = signRawBasicTransaction(map,prikeyStr);
//        byte[] transha= (byte[]) map2.get("transha");
//        String txHash = Hex.encodeHexString(transha);
//        return  txHash;
        String RawTransactionHex = CreateRawTransaction(fromPubkeyStr, toPubkeyHashStr, amount);
        byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
        byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
        String txHash = Hex.encodeHexString(hash);
        String traninfo = Hex.encodeHexString(signRawBasicTransaction);
        String msg = sendTransac(node,"traninfo="+traninfo);
        JSONObject jsonObject = JSONObject.fromObject(msg);
        APIResult ar = (APIResult) JSONObject.toBean(jsonObject,APIResult.class);
        ar.setMessage(txHash);
        JSONObject json = JSONObject.fromObject(ar);
        return  json;
    }

    /**
     * 构造签名的孵化申请事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @return
     * @throws Exception
     */
    public static JSONObject ClientToIncubateAccount(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String sharepubkeyhash, Integer hatchType) throws Exception {
        String RawTransactionHex = CreateRawHatchTransaction(fromPubkeyStr, toPubkeyHashStr, amount,sharepubkeyhash,hatchType);
        byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
        byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
        String txHash = Hex.encodeHexString(hash);
        String traninfo = Hex.encodeHexString(signRawBasicTransaction);
        String msg = sendTransac(node,"traninfo="+traninfo);
        JSONObject jsonObject = JSONObject.fromObject(msg);
        APIResult ar = (APIResult) JSONObject.toBean(jsonObject,APIResult.class);
        ar.setMessage(txHash);
        JSONObject json = JSONObject.fromObject(ar);
        return  json;
    }

    /**
     * 构造签名的收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     * @throws Exception
     */
    public static JSONObject ClientToIncubateProfit (String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid) throws Exception {
        String RawTransactionHex = CreateRawProfitTransaction(fromPubkeyStr, toPubkeyHashStr, amount,txid);
        byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
        byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
        String txHash = Hex.encodeHexString(hash);
        String traninfo = Hex.encodeHexString(signRawBasicTransaction);
        String msg = sendTransac(node,"traninfo="+traninfo);
        JSONObject jsonObject = JSONObject.fromObject(msg);
        APIResult ar = (APIResult) JSONObject.toBean(jsonObject,APIResult.class);
        ar.setMessage(txHash);
        JSONObject json = JSONObject.fromObject(ar);
        return  json;

    }

    /**
     * 构造签名的分享收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     * @throws Exception
     */
    public static JSONObject ClientToIncubateShareProfit (String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid) throws Exception {
        String RawTransactionHex =CreateRawShareProfitTransaction(fromPubkeyStr, toPubkeyHashStr, amount,txid);
        byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
        byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
        String txHash = Hex.encodeHexString(hash);
        String traninfo = Hex.encodeHexString(signRawBasicTransaction);
        String msg = sendTransac(node,"traninfo="+traninfo);
        JSONObject jsonObject = JSONObject.fromObject(msg);
        APIResult ar = (APIResult) JSONObject.toBean(jsonObject,APIResult.class);
        ar.setMessage(txHash);
        JSONObject json = JSONObject.fromObject(ar);
        return  json;
    }

    /**
     * 构造签名的收取本金事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     * @throws Exception
     */
    public static JSONObject ClientToIncubatePrincipal (String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid) throws Exception {
        String RawTransactionHex =CreateRawHatchPrincipalTransaction(fromPubkeyStr, toPubkeyHashStr, amount,txid);
        byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
        byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
        String txHash = Hex.encodeHexString(hash);
        String traninfo = Hex.encodeHexString(signRawBasicTransaction);
        String msg = sendTransac(node,"traninfo="+traninfo);
        JSONObject jsonObject = JSONObject.fromObject(msg);
        APIResult ar = (APIResult) JSONObject.toBean(jsonObject,APIResult.class);
        ar.setMessage(txHash);
        JSONObject json = JSONObject.fromObject(ar);
        return  json;
    }

    /**
     * 通过事务十六进制字符串获取Transaction
     * @param transactionHexStr
     * @return
     * @throws DecoderException
     */
    public static JSONObject byteToTransaction(String transactionHexStr) throws DecoderException {
        byte[] transaction = Hex.decodeHex(transactionHexStr.toCharArray());
        ProtocolModel.Transaction tranproto=Transaction.changeProtobuf(transaction);
        Transaction tran=Transaction.fromProto(tranproto);
        APIResult apiResult = new APIResult();
        apiResult.setData(tran);
        JSONObject result = JSONObject.fromObject(apiResult);
        return  result;
    }

    /**
     * 根据事务哈希获得所在区块哈希以及高度
     * @param txid
     * @return
     */
    public static JSONObject getTransactioninfo(String txid){
        APIResult apiResult = new APIResult();
        JSONObject dataresult = new JSONObject();
        dataresult.put("blockHash","");
        dataresult.put("height","");
        apiResult.setData(dataresult);
        JSONObject result = JSONObject.fromObject(apiResult);
        return  result;
    }

    /**
     * 根据事务哈希获得确认区块数
     * @param txid
     * @return
     */
    public static JSONObject confirmedBlockNumber(String txid){
        APIResult apiResult = new APIResult();
        JSONObject result = JSONObject.fromObject(apiResult);
        return  result;
    }

    public static String sendTransac(String path,String data) {
        String str = "";
        try {
            URL url = new URL(path);
            //打开和url之间的连接
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            PrintWriter out = null;
            //请求方式
//            conn.setRequestMethod("POST");
//           //设置通用的请求属性
            conn.setRequestProperty("accept", "*/*");
            conn.setRequestProperty("connection", "Keep-Alive");
            conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)");
            //设置是否向httpUrlConnection输出，设置是否从httpUrlConnection读入，此外发送post请求必须设置这两个
            //最常用的Http请求无非是get和post，get请求可以获取静态页面，也可以把参数放在URL字串后面，传递给servlet，
            //post与get的 不同之处在于post的参数不是放在URL字串里面，而是放在http请求的正文内。
            conn.setDoOutput(true);
            conn.setDoInput(true);
            //获取URLConnection对象对应的输出流
            out = new PrintWriter(conn.getOutputStream());
            //发送请求参数即数据
            out.print(data);
            //缓冲数据
            out.flush();
            //获取URLConnection对象对应的输入流
            InputStream is = conn.getInputStream();
            //构造一个字符流缓存
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            while ((str = br.readLine()) != null) {
                System.out.println(str);
            }
            //关闭流
            is.close();
            //断开连接，最好写上，disconnect是在底层tcp socket链接空闲时才切断。如果正在被其他线程使用就不切断。
            //固定多线程的话，如果不disconnect，链接会增多，直到收发不出信息。写上disconnect后正常一些。
            conn.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    public static String connect(String ip,String port,String data) {
        String str = "";
        try {
            String path = "http://192.168.0.116:19585/block/-1";

            URL url = new URL(path);
            //打开和url之间的连接
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            PrintWriter out = null;
            //请求方式
            conn.setRequestMethod("GET");
//           //设置通用的请求属性
            conn.setRequestProperty("accept", "*/*");
            conn.setRequestProperty("connection", "Keep-Alive");
            conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)");
            //设置是否向httpUrlConnection输出，设置是否从httpUrlConnection读入，此外发送post请求必须设置这两个
            //最常用的Http请求无非是get和post，get请求可以获取静态页面，也可以把参数放在URL字串后面，传递给servlet，
            //post与get的 不同之处在于post的参数不是放在URL字串里面，而是放在http请求的正文内。
            conn.setDoOutput(true);
            conn.setDoInput(true);
            //获取URLConnection对象对应的输出流
            out = new PrintWriter(conn.getOutputStream());
            //发送请求参数即数据
            out.print(data);
            //缓冲数据
            out.flush();
            //获取URLConnection对象对应的输入流
            InputStream is = conn.getInputStream();
            //构造一个字符流缓存
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            while ((str = br.readLine()) != null) {
                System.out.println(str);
            }
            //关闭流
            is.close();
            //断开连接，最好写上，disconnect是在底层tcp socket链接空闲时才切断。如果正在被其他线程使用就不切断。
            //固定多线程的话，如果不disconnect，链接会增多，直到收发不出信息。写上disconnect后正常一些。
            conn.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    public static void connect(String ip, String port) {
        HttpClient client = new HttpClient();
        String url = "http://"+ip+":"+port;
        GetMethod getMethod = new GetMethod(url);
        int code = 0;
        try {
            code = client.executeMethod(getMethod);
            if (code == 200) {
                String res = getMethod.getResponseBodyAsString();
                System.out.println(res);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 计算gas单价
     * @param gas
     * @param total
     * @return
     */
    public static Long obtainServiceCharge(Long gas,Long total){
        BigDecimal a = new BigDecimal(gas.toString());
        BigDecimal b = new BigDecimal(total.toString());
        BigDecimal divide = b.divide(a, 0, RoundingMode.HALF_UP);
        Long gasPrice = divide.longValue();
        return gasPrice;
    }


    public static void main(String[] args) throws Exception {
//        connect("192.168.0.116","19585/block/-1");
//        WalletUtility.generateKeystore("12345678","E:\\test1\\rpcsdk-J\\classes\\artifacts\\wcli_jar");


//        System.out.println(obtainServiceCharge(50000L,serviceCharge));
//        BigDecimal bi1 = new BigDecimal(a.toString());
//        BigDecimal bi2 = new BigDecimal(b.toString());
//        BigDecimal divide = bi1.divide(bi2, 0, RoundingMode.HALF_UP);
//
//        System.out.println(divide.longValue());
        APIResult a = new APIResult();
        JSONObject j = JSONObject.fromObject(a);
        System.out.println(j);

    }
    //java -
    //jar com.example.wdc.main.jar -connet -ip 192.168.0.116 -port 19585/block/-1


}
