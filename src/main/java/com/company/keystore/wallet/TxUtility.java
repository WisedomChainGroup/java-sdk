package com.company.keystore.wallet;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.company.ApiResult.APIResult;
import com.company.account.Transaction;
import com.company.encoding.BigEndian;
import com.company.keystore.crypto.SHA3Utility;
import com.company.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.company.keystore.util.ByteUtil;
import com.company.protobuf.HatchModel;
import com.company.protobuf.ProtocolModel;
import com.google.protobuf.ByteString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;


import java.io.*;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.concurrent.*;

public class TxUtility extends Thread{
    private static final Long rate= 100000000L;
    private static final Long serviceCharge= 200000L;
    public static final String node = "http://192.168.0.101:19585/sendTransaction";
    public static final String node2 = "http://192.168.0.101:19585/sendBalance";
    public static final String node3 = "http://192.168.0.101:19585/sendNonce";


    /**
     * 构造交易事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @return
     */
    public static String CreateRawTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount,Long nonce){
        try {
            //版本号
            byte[] version=new byte[1];
            version[0]=0x01;
            //类型：WDC转账
            byte[] type=new byte[1];
            type[0]=0x01;
            //Nonce 无符号64位
            byte[] nonece= BigEndian.encodeUint64(nonce+1);
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
            String RawTransactionStr =new String(Hex.encodeHex(RawTransaction));
        return  RawTransactionStr;
        }catch (Exception e){
            return "";
        }
    }

    /**
     * 构造申请孵化事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param sharepubkeyhash
     * @param hatchType
     * @return
     */
    public static String CreateRawHatchTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String sharepubkeyhash, Integer hatchType,Long nonce){
        try {
            //版本号
            byte[] version=new byte[1];
            version[0]=0x01;
            //类型：申请孵化
            byte[] type=new byte[1];
            type[0]=0x09;
            //Nonce 无符号64位
            byte[] nonece=BigEndian.encodeUint64(nonce+1);
    //        byte[] nonce=ByteUtil.encodeUint64(100000000);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L,serviceCharge));
            //孵化本金 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull=new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash=Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            HatchModel.Payload.Builder payloads = HatchModel.Payload.newBuilder();
            byte[] nullTxid = new byte[32];
            payloads.setTxId(ByteString.copyFrom(nullTxid));
            if (sharepubkeyhash != null){
                payloads.setSharePubkeyHash(sharepubkeyhash);
            }
            payloads.setType(hatchType);
            byte[] payload = payloads.build().toByteArray();
            //长度
    //        byte[] payloadleng= BigEndian.encodeUint32(payload.length);
            byte[] payloadleng= ByteUtil.intToBytes(payload.length);
            byte[] allPayload=ByteUtil.merge(payloadleng,payload);
    //        byte[] allPayload= BigEndian.encodeUint32(0);
            byte[] RawTransaction=ByteUtil.merge(version,type,nonece,fromPubkeyHash,gasPrice,Amount,signull,toPubkeyHash,allPayload);
            String RawTransactionStr =new String(Hex.encodeHex(RawTransaction));
            return  RawTransactionStr;
        }catch (Exception e){
            return "";
        }
    }

    /**
     *构造利息收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     */
    public static String CreateRawProfitTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid, Long nonce){
        try {
            //版本号
            byte[] version=new byte[1];
            version[0]=0x01;
            //类型：利息收益
            byte[] type=new byte[1];
            type[0]=0x0a;
            //Nonce 无符号64位
            byte[] nonece=BigEndian.encodeUint64(nonce+1);
    //        byte[] nonce=ByteUtil.encodeUint64(100000000);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L,serviceCharge));
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
            String RawTransactionStr =new String(Hex.encodeHex(RawTransaction));
            return  RawTransactionStr;
        }catch (Exception e){
            return "";
        }
    }

    /**
     *构造分享收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     */
    public static String CreateRawShareProfitTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid,Long nonce){
        try {
            //版本号
            byte[] version=new byte[1];
            version[0]=0x01;
            //类型：申请孵化
            byte[] type=new byte[1];
            type[0]=0x0b;
            //Nonce 无符号64位
            byte[] nonece=BigEndian.encodeUint64(nonce+1);
    //        byte[] nonce=ByteUtil.encodeUint64(100000000);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L,serviceCharge));
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
            String RawTransactionStr =new String(Hex.encodeHex(RawTransaction));
            return  RawTransactionStr;
        }catch (Exception e){
            return "";
        }
    }

    /**
     * 构造提取本金
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     */
    public static String CreateRawHatchPrincipalTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid,Long nonce){
        try {
            //版本号
            byte[] version=new byte[1];
            version[0]=0x01;
            //类型：提取本金
            byte[] type=new byte[1];
            type[0]=0x0c;
            //Nonce 无符号64位
            byte[] nonece=BigEndian.encodeUint64(nonce+1);
    //        byte[] nonce=ByteUtil.encodeUint64(100000000);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L,serviceCharge));
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
            String RawTransactionStr =new String(Hex.encodeHex(RawTransaction));
            return  RawTransactionStr;
        }catch (Exception e){
            return "";
        }
    }

    /**
     * 构建签名事务
     * @param RawTransactionHex
     * @param prikeyStr
     * @return
     */
    public static String signRawBasicTransaction(String RawTransactionHex, String prikeyStr){
        try {
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
            byte[] payload = ByteUtil.bytearraycopy(RawTransaction, 146, (int)BigEndian.decodeUint32(payloadlen));
            byte[] RawTransactionNoSign=ByteUtil.merge(version,type,nonce,from,gasprice,amount,signo,to,payloadlen,payload);
            byte[] RawTransactionNoSig=ByteUtil.merge(version,type,nonce,from,gasprice,amount);
            //签名数据
            byte[] sig=new Ed25519PrivateKey(privkey).sign(RawTransactionNoSign);
            byte[] transha= SHA3Utility.keccak256(ByteUtil.merge(RawTransactionNoSig,sig,to,payloadlen,payload));
            byte[] signRawBasicTransaction = ByteUtil.merge(version,transha,type,nonce,from,gasprice,amount,sig,to,payloadlen,payload);
            String signRawBasicTransactionHex =new String(Hex.encodeHex(signRawBasicTransaction));
            return signRawBasicTransactionHex;
        }catch (Exception e){
            return "";
        }
    }


    /**
     * 构造签名的交易事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferAccount(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr,Long nonce){
        try {
            String RawTransactionHex = CreateRawTransaction(fromPubkeyStr, toPubkeyHashStr, amount,nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo =new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
    }

    /**
     * 构造签名的孵化申请事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     */
    public static JSONObject ClientToIncubateAccount(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String sharepubkeyhash, Integer hatchType,Long nonce){
        try {
            String RawTransactionHex = CreateRawHatchTransaction(fromPubkeyStr, toPubkeyHashStr, amount,sharepubkeyhash,hatchType,nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash =new String(Hex.encodeHex(hash)) ;
            String traninfo =new String(Hex.encodeHex(signRawBasicTransaction)) ;
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
    }

    /**
     * 构造签名的收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     */
    public static JSONObject ClientToIncubateProfit (String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid, Long nonce){
        try {
            String RawTransactionHex = CreateRawProfitTransaction(fromPubkeyStr, toPubkeyHashStr, amount,txid, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash =new String(Hex.encodeHex(hash));
            String traninfo =new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
    }

    /**
     * 构造签名的分享收益事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     */
    public static JSONObject ClientToIncubateShareProfit (String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid,Long nonce){
        try {
            String RawTransactionHex =CreateRawShareProfitTransaction(fromPubkeyStr, toPubkeyHashStr, amount,txid,nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash =new String(Hex.encodeHex(hash));
            String traninfo =new String(Hex.encodeHex(signRawBasicTransaction)) ;
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
    }

    /**
     * 构造签名的收取本金事务
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     */
    public static JSONObject ClientToIncubatePrincipal (String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid,Long nonce){
        try{
            String RawTransactionHex =CreateRawHatchPrincipalTransaction(fromPubkeyStr, toPubkeyHashStr, amount,txid,nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex,prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash =new String(Hex.encodeHex(hash)) ;
            String traninfo =new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
    }

    /**
     * 通过事务十六进制字符串获取Transaction
     * @param transactionHexStr
     * @return
     */
    public static JSONObject byteToTransaction(String transactionHexStr){
        try {
            byte[] transaction = Hex.decodeHex(transactionHexStr.toCharArray());
            ProtocolModel.Transaction tranproto= Transaction.changeProtobuf(transaction);
            Transaction tran=Transaction.fromProto(tranproto);
            APIResult apiResult = new APIResult();
            apiResult.setData(tran);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
    }

    /**
     * 根据事务哈希获得所在区块哈希以及高度
     * @param txid
     * @return
     */
    public static JSONObject getTransactioninfo(String txid){
        try {
            APIResult apiResult = new APIResult();
            JSONObject dataresult = new JSONObject();
            dataresult.put("blockHash","");
            dataresult.put("height","");
            apiResult.setData(dataresult);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return  json;
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return  json;
        }
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

    public static void connect(String ip, String port) {
        org.apache.commons.httpclient.HttpClient client = new HttpClient();
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

    @SuppressWarnings("unchecked")

    static class MyCallable implements Callable {
        private String str;


        MyCallable(String path,String data) {
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
                    this.str = str;
                }
                //关闭流
                is.close();
                //断开连接，最好写上，disconnect是在底层tcp socket链接空闲时才切断。如果正在被其他线程使用就不切断。
                //固定多线程的话，如果不disconnect，链接会增多，直到收发不出信息。写上disconnect后正常一些。
                conn.disconnect();
            } catch (Exception e) {
                e.printStackTrace();
//                this.str  = "false";
            }
        }

        public Object call() throws Exception {
            return str;
        }
    }

    @SuppressWarnings("unchecked")

    static class MyCallable2 implements Callable {
        private String str;


        MyCallable2(String path,String data) {
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
                    this.str = str;
                }
                //关闭流
                is.close();
                //断开连接，最好写上，disconnect是在底层tcp socket链接空闲时才切断。如果正在被其他线程使用就不切断。
                //固定多线程的话，如果不disconnect，链接会增多，直到收发不出信息。写上disconnect后正常一些。
                conn.disconnect();
            } catch (Exception e) {
                e.printStackTrace();
//                this.str  = "false";
            }
        }

        public Object call() throws Exception {
            return str;
        }
    }

    public static void main(String[] args) throws DecoderException {
        byte[] privkey = new byte[32];
        byte[] a = new byte[8];
        System.out.println(Hex.encodeHexString(a));
        byte[] RawTransactionNoSign = Hex.decodeHex("a1c2".toCharArray());
        byte[] sig=new Ed25519PrivateKey(privkey).sign(RawTransactionNoSign);
        System.out.println(Hex.encodeHexString(sig));

//        转账事务
//        JSONObject transaction  = ClientToTransferAccount("4d7cc1778608deac44601eaf927e75b819f9e05ed4da680767fad5379dd3a990","e64069b4fbc63331f9d59a6e40e1052524ee56bd", BigDecimal.valueOf(11),"ea22341d3f875d9aaf7619ca3fa513b6b00f0a690cb8458c808d2a0a0ba0d578",1L);
//        System.out.println(transaction);
//        E/com.zsgeek.wisechain.xxx:TransferActivity$1.onClick(Line:237): fromAddress===1MzTacKdyPZ7n1sRP4xqkcygt2DDy3w4bS
//        E/com.zsgeek.wisechain.xxx:TransferActivity$1.onClick(Line:242): keystore==={"address":"1MzTacKdyPZ7n1sRP4xqkcygt2DDy3w4bS","kdfparams":{"salt":"da1abde60331b24a1b6490cd9f3c96c9d34c5a68c8e92e1c99c0bd38b00a0642","memoryCost":20480,"parallelism":2,"timeCost":4},"id":"abf6b2e6-e7dd-4a88-92b7-dbf072ca99f4","kdf":"argon2id","version":"1","mac":"9fa48f74973fbd3e2f50bce814059f3e50b83df77ec713c07d5b0bd906421f35","crypto":{"cipher":"aes-256-ctr","ciphertext":"b36573c815b40cfa54a0f930c3e3464235680bee726db4a2b93849a2318e8ee8","cipherparams":{"iv":"05426b556918a3a3dc5316e638463ff2"}}}
//        E/com.zsgeek.wisechain.xxx:TransferActivity$1.onClick(Line:247): publickey===4d7cc1778608deac44601eaf927e75b819f9e05ed4da680767fad5379dd3a990
//        E/com.zsgeek.wisechain.xxx:TransferActivity$1.onClick(Line:265):   fromPubkeyStr:4d7cc1778608deac44601eaf927e75b819f9e05ed4da680767fad5379dd3a990  toPubkeyHashStr:e64069b4fbc63331f9d59a6e40e1052524ee56bd  amount:11  prikeyStr:ea22341d3f875d9aaf7619ca3fa513b6b00f0a690cb8458c808d2a0a0ba0d578





    }
}
