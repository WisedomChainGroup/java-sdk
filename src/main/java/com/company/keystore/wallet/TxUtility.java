package com.company.keystore.wallet;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.company.ApiResult.APIResult;
import com.company.account.Transaction;
import com.company.contract.AssetDefinition.Asset;
import com.company.contract.AssetDefinition.AssetChangeowner;
import com.company.contract.AssetDefinition.AssetIncreased;
import com.company.contract.AssetDefinition.AssetTransfer;
import com.company.encoding.BigEndian;
import com.company.keystore.crypto.RipemdUtility;
import com.company.keystore.crypto.SHA3Utility;
import com.company.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.company.keystore.util.ByteUtil;
import com.company.protobuf.HatchModel;
import com.company.protobuf.ProtocolModel;
import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.*;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.Callable;

public class TxUtility extends Thread {
    private static final Long rate = 100000000L;
    private static final Long serviceCharge = 200000L;


    /**
     * 构造交易事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @return
     */
    public static String CreateRawTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：WDC转账
            byte[] type = new byte[1];
            type[0] = 0x01;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(50000L, serviceCharge));
            //转账金额 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //长度
            byte[] allPayload = BigEndian.encodeUint32(0);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造申请孵化事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param sharepubkeyhash
     * @param hatchType
     * @return
     */
    public static String CreateRawHatchTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String sharepubkeyhash, Integer hatchType, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：申请孵化
            byte[] type = new byte[1];
            type[0] = 0x09;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //孵化本金 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            HatchModel.Payload.Builder payloads = HatchModel.Payload.newBuilder();
            byte[] nullTxid = new byte[32];
            payloads.setTxId(ByteString.copyFrom(nullTxid));
            if (sharepubkeyhash != null) {
                payloads.setSharePubkeyHash(sharepubkeyhash);
            }
            payloads.setType(hatchType);
            byte[] payload = payloads.build().toByteArray();
            //长度
            //        byte[] payloadleng= BigEndian.encodeUint32(payload.length);
            byte[] payloadleng = ByteUtil.intToBytes(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            //        byte[] allPayload= BigEndian.encodeUint32(0);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造利息收益事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     */
    public static String CreateRawProfitTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：利息收益
            byte[] type = new byte[1];
            type[0] = 0x0a;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //收益 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = Hex.decodeHex(txid.toCharArray());
            //长度
            byte[] payloadleng = BigEndian.encodeUint32(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造分享收益事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     */
    public static String CreateRawShareProfitTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：申请孵化
            byte[] type = new byte[1];
            type[0] = 0x0b;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //分享收益 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = Hex.decodeHex(txid.toCharArray());
            //长度
            byte[] payloadleng = BigEndian.encodeUint32(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造提取本金
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @return
     */
    public static String CreateRawHatchPrincipalTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：提取本金
            byte[] type = new byte[1];
            type[0] = 0x0c;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //本金 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = Hex.decodeHex(txid.toCharArray());
            //长度
            byte[] payloadleng = BigEndian.encodeUint32(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造投票事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @return
     */
    public static String CreateRawVoteTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：投票
            byte[] type = new byte[1];
            type[0] = 0x02;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(20000L, serviceCharge));
            //转账金额 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //长度
            byte[] allPayload = BigEndian.encodeUint32(0);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造投票撤回事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @return
     */
    public static String CreateRawVoteWithdrawTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce, String txid) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：投票撤回
            byte[] type = new byte[1];
            type[0] = 0x0d;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(20000L, serviceCharge));
            //转账金额 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //payload
            byte[] payload = Hex.decodeHex(txid.toCharArray());
            //长度
            byte[] payloadleng = BigEndian.encodeUint32(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造抵押事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @return
     */
    public static String CreateRawMortgageTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：抵押
            byte[] type = new byte[1];
            type[0] = 0x0e;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(20000L, serviceCharge));
            //本金 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            byte[] allPayload = BigEndian.encodeUint32(0);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造抵押撤回事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param txid
     * @param nonce
     * @return
     */
    public static String CreateRawMortgageWithdrawTransaction(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String txid, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：抵押撤回
            byte[] type = new byte[1];
            type[0] = 0x0f;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(20000L, serviceCharge));
            //本金 无符号64位
            BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //payload
            byte[] payload = Hex.decodeHex(txid.toCharArray());
            //长度
            byte[] payloadleng = BigEndian.encodeUint32(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造存证事务
     *
     * @param fromPubkeyStr
     * @param payload
     * @param nonce
     * @return
     */
    public static String CreateRawProveTransaction(String fromPubkeyStr, byte[] payload, Long nonce) {
        try {
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型：抵押撤回
            byte[] type = new byte[1];
            type[0] = 0x03;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //本金 无符号64位
            byte[] Amount = ByteUtil.longToBytes(0);
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] toPubkeyHash = new byte[20];
            //构造payload
//            byte[] payload = Hex.decodeHex(txid.toCharArray());
            //长度
            byte[] payloadleng = BigEndian.encodeUint32(payload.length);
            byte[] allPayload = ByteUtil.merge(payloadleng, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }


    /**
     * 构建签名事务
     *
     * @param RawTransactionHex
     * @param prikeyStr
     * @return
     */
    public static String signRawBasicTransaction(String RawTransactionHex, String prikeyStr) {
        try {
            byte[] RawTransaction = Hex.decodeHex(RawTransactionHex.toCharArray());
            //私钥字节数组
            byte[] privkey = Hex.decodeHex(prikeyStr.toCharArray());
            //version
            byte[] version = ByteUtil.bytearraycopy(RawTransaction, 0, 1);
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
            byte[] to = ByteUtil.bytearraycopy(RawTransaction, 122, 20);
            ;
            //payloadlen
            byte[] payloadlen = ByteUtil.bytearraycopy(RawTransaction, 142, 4);
            //payload
            byte[] payload = ByteUtil.bytearraycopy(RawTransaction, 146, (int) BigEndian.decodeUint32(payloadlen));
            byte[] RawTransactionNoSign = ByteUtil.merge(version, type, nonce, from, gasprice, amount, signo, to, payloadlen, payload);
            byte[] RawTransactionNoSig = ByteUtil.merge(version, type, nonce, from, gasprice, amount);
            //签名数据
            byte[] sig = new Ed25519PrivateKey(privkey).sign(RawTransactionNoSign);
            byte[] transha = SHA3Utility.keccak256(ByteUtil.merge(RawTransactionNoSig, sig, to, payloadlen, payload));
            byte[] signRawBasicTransaction = ByteUtil.merge(version, transha, type, nonce, from, gasprice, amount, sig, to, payloadlen, payload);
            String signRawBasicTransactionHex = new String(Hex.encodeHex(signRawBasicTransaction));
            return signRawBasicTransactionHex;
        } catch (Exception e) {
            return "";
        }
    }


    /**
     * 构造签名的交易事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferAccount(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, Long nonce) {
        try {
            String RawTransactionHex = CreateRawTransaction(fromPubkeyStr, toPubkeyHashStr, amount, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            e.printStackTrace();
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的孵化申请事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     */
    public static JSONObject ClientToIncubateAccount(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String sharepubkeyhash, Integer hatchType, Long nonce) {
        try {
            String RawTransactionHex = CreateRawHatchTransaction(fromPubkeyStr, toPubkeyHashStr, amount, sharepubkeyhash, hatchType, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的收益事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     */
    public static JSONObject ClientToIncubateProfit(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid, Long nonce) {
        try {
            String RawTransactionHex = CreateRawProfitTransaction(fromPubkeyStr, toPubkeyHashStr, amount, txid, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的分享收益事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     */
    public static JSONObject ClientToIncubateShareProfit(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid, Long nonce) {
        try {
            String RawTransactionHex = CreateRawShareProfitTransaction(fromPubkeyStr, toPubkeyHashStr, amount, txid, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的收取本金事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param prikeyStr
     * @param txid
     * @return
     */
    public static JSONObject ClientToIncubatePrincipal(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, String prikeyStr, String txid, Long nonce) {
        try {
            String RawTransactionHex = CreateRawHatchPrincipalTransaction(fromPubkeyStr, toPubkeyHashStr, amount, txid, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的投票事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferVote(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce, String prikeyStr) {
        try {
            String RawTransactionHex = CreateRawVoteTransaction(fromPubkeyStr, toPubkeyHashStr, amount, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的投票撤回事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferVoteWithdraw(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce, String prikeyStr, String txid) {
        try {
            String RawTransactionHex = CreateRawVoteWithdrawTransaction(fromPubkeyStr, toPubkeyHashStr, amount, nonce, txid);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }


    /**
     * 构造签名的抵押事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferMortgage(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce, String prikeyStr) {
        try {
            String RawTransactionHex = CreateRawMortgageTransaction(fromPubkeyStr, toPubkeyHashStr, amount, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造签名的抵押撤回事务
     *
     * @param fromPubkeyStr
     * @param toPubkeyHashStr
     * @param amount
     * @param nonce
     * @param txid
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferMortgageWithdraw(String fromPubkeyStr, String toPubkeyHashStr, BigDecimal amount, Long nonce, String txid, String prikeyStr) {
        try {
            String RawTransactionHex = CreateRawMortgageWithdrawTransaction(fromPubkeyStr, toPubkeyHashStr, amount, txid, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }


    /**
     * 构造签名的存证事务
     *
     * @param fromPubkeyStr
     * @param nonce
     * @param payload
     * @param prikeyStr
     * @return
     */
    public static JSONObject ClientToTransferProve(String fromPubkeyStr, Long nonce, byte[] payload, String prikeyStr) {
        try {
            String RawTransactionHex = CreateRawProveTransaction(fromPubkeyStr, payload, nonce);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult ar = new APIResult();
            ar.setData(txHash);
            ar.setMessage(traninfo);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 通过事务十六进制字符串获取Transaction
     *
     * @param transactionHexStr
     * @return
     */
    public static JSONObject byteToTransaction(String transactionHexStr) {
        try {
            byte[] transaction = Hex.decodeHex(transactionHexStr.toCharArray());
            ProtocolModel.Transaction tranproto = Transaction.changeProtobuf(transaction);
            Transaction tran = Transaction.fromProto(tranproto);
            APIResult apiResult = new APIResult();
            apiResult.setData(tran);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 根据事务哈希获得所在区块哈希以及高度
     *
     * @param txid
     * @return
     */
    public static JSONObject getTransactioninfo(String txid) {
        try {
            APIResult apiResult = new APIResult();
            JSONObject dataresult = new JSONObject();
            dataresult.put("blockHash", "");
            dataresult.put("height", "");
            apiResult.setData(dataresult);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    public static String sendTransac(String path, String data) {
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
     *
     * @param gas
     * @param total
     * @return
     */
    public static Long obtainServiceCharge(Long gas, Long total) {
        BigDecimal a = new BigDecimal(gas.toString());
        BigDecimal b = new BigDecimal(total.toString());
        BigDecimal divide = b.divide(a, 0, RoundingMode.HALF_UP);
        Long gasPrice = divide.longValue();
        return gasPrice;
    }

    public static void connect(String ip, String port) {
        HttpClient client = new HttpClient();
        String url = "http://" + ip + ":" + port;
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


    public static void test(String path, String data) throws IOException {
        LocalDateTime beginTime = LocalDateTime.now();


        URL url = new URL(path);
        String str = "";
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
            System.out.println("1111");
            System.out.println(str);
            Long timeConsuming = Duration.between(beginTime, LocalDateTime.now()).toMillis();
            System.out.println(timeConsuming);
        }
        //关闭流
        is.close();
        //断开连接，最好写上，disconnect是在底层tcp socket链接空闲时才切断。如果正在被其他线程使用就不切断。
        //固定多线程的话，如果不disconnect，链接会增多，直到收发不出信息。写上disconnect后正常一些。
        conn.disconnect();
    }

    @SuppressWarnings("unchecked")

    static class MyCallable implements Callable {
        private String str;


        MyCallable(String path, String data) {
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


    /**
     * 构造规则部署的资产定义事务
     *
     * @param fromPubkeyStr
     * @param nonce
     * @param code
     * @param offering
     * @param totalamount
     * @param createuser
     * @param owner
     * @param allowincrease
     * @return
     */
    public static String CreateDeployforRuleAsset(String fromPubkeyStr, Long nonce, String code, BigDecimal offering, BigDecimal totalamount, byte[] createuser, byte[] owner, int allowincrease,byte[] info) {
        try {
            offering = offering.multiply(BigDecimal.valueOf(rate));
            long offeringNew = Long.parseLong(isHave(offering));
            totalamount = totalamount.multiply(BigDecimal.valueOf(rate));
            long totalamountNew = Long.parseLong(isHave(totalamount));
            Asset asset = new Asset(code, offeringNew, totalamountNew, createuser, owner, allowincrease,info);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x07;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 32字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //分享收益 无符号64位
            BigDecimal bdAmount = BigDecimal.valueOf(0);
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            String toPubkeyHashStr = "0000000000000000000000000000000000000000";
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = asset.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x00}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的规则部署的资产定义事务
     *
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleAsset(String fromPubkeyStr, String prikeyStr, Long nonce, String code, BigDecimal offering, byte[] createuser, byte[] owner, int allowincrease,byte[] info){
        try {
            BigDecimal totalamount = offering;
            String RawTransactionHex = CreateDeployforRuleAsset(fromPubkeyStr, nonce, code, offering, totalamount, createuser, owner, allowincrease,info);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造资产定义的规则调用事务
     *
     * @param fromPubkeyStr
     * @param nonce
     * @param newowner
     * @return
     */
    public static String CreateCallforRuleAssetChangeowner(String fromPubkeyStr, String txHash, Long nonce, byte[] newowner) {
        try {
            AssetChangeowner assetChangeowner = new AssetChangeowner(newowner);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = (byte) 0X88;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //分享收益 无符号64位
            BigDecimal bdAmount = BigDecimal.valueOf(0);
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = assetChangeowner.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x01}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的资产定义的规则调用事务
     *
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @return
     */
    public static JSONObject CreateSignToDeployforAssetChangeowner(String fromPubkeyStr, String txHash1, String prikeyStr, Long nonce, byte[] newowner) {
        try {
            String RawTransactionHex = CreateCallforRuleAssetChangeowner(fromPubkeyStr, txHash1, nonce, newowner);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造规则部署事务
     *
     * @param fromPubkeyStr
     * @param nonce
     * @param amount
     * @return
     */
    public static String CreateCallforRuleAssetIncreased(String fromPubkeyStr, String txHash, Long nonce, BigDecimal amount) {
        try {
            amount = amount.multiply(BigDecimal.valueOf(rate));
            long amountNew = Long.parseLong(isHave(amount));
            AssetIncreased assetIncreased = new AssetIncreased(amountNew);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x08;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //分享收益 无符号64位
            BigDecimal bdAmount = BigDecimal.valueOf(0);
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = assetIncreased.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x02}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的规则部署事务
     *
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleAssetIncreased(String fromPubkeyStr, String txHash1, String prikeyStr, Long nonce, BigDecimal amount) {
        try {
            String RawTransactionHex = CreateCallforRuleAssetIncreased(fromPubkeyStr, txHash1, nonce, amount);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 构造规则部署事务
     *
     * @param fromPubkeyStr
     * @param nonce
     * @return
     */
    public static String CreateDeployforRuleAssetTransfer(String fromPubkeyStr, String txHash, Long nonce, byte[] from, byte[] to, BigDecimal value) {
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            long valueNew = Long.parseLong(isHave(value));
            AssetTransfer assetTransfer = new AssetTransfer(from, to, valueNew);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x08;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce + 1);
            //签发者公钥哈希 20字节
            byte[] fromPubkeyHash = Hex.decodeHex(fromPubkeyStr.toCharArray());
            //gas单价
            byte[] gasPrice = ByteUtil.longToBytes(obtainServiceCharge(100000L, serviceCharge));
            //分享收益 无符号64位
            BigDecimal bdAmount = BigDecimal.valueOf(0);
            byte[] Amount = ByteUtil.longToBytes(bdAmount.longValue());
            //为签名留白
            byte[] signull = new byte[64];
            //接收者公钥哈希
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = assetTransfer.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x01}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的规则部署事务
     *
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleTransfer(String fromPubkeyStr, String txHash1, String prikeyStr, Long nonce, byte[] from, byte[] to, BigDecimal value) {
        try {
            String RawTransactionHex = CreateDeployforRuleAssetTransfer(fromPubkeyStr, txHash1, nonce, from, to, value);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * 判断BigDecimal值是否有小数点或者超过long的最大值
     *
     * @param number
     * @return
     * @throws Exception
     */
    public static String isHave(BigDecimal number) throws Exception {
        String numberNew = number.toString();
        BigDecimal numberMax = new BigDecimal(Long.MAX_VALUE);
        if (numberNew.contains(".")) {
            throw new Exception("");
        } else if (numberMax.compareTo(number) == -1) {
            throw new Exception("");
        }
        {
            return numberNew;
        }
    }

    /**
     * 获取Asset
     * @param payload
     * @return
     */
    public static Asset getAsset(byte[] payload) {
        Asset asset = new Asset();
        asset = asset.RLPdeserialization(payload);
        return asset;
    }

    /**
     * 获取AssetChangeowner
     * @param payload
     * @return
     */
    public static AssetIncreased getAssetIncreased(byte[] payload) {
        AssetIncreased assetIncreased = new AssetIncreased();
        assetIncreased = assetIncreased.RLPdeserialization(payload);
        return assetIncreased;
    }

    /**
     * 获取AssetIncreased
     * @param payload
     * @return
     */
    public static AssetChangeowner getAssetChangeowner(byte[] payload) {
        AssetChangeowner assetChangeowner = new AssetChangeowner();
        assetChangeowner = assetChangeowner.RLPdeserialization(payload);
        return assetChangeowner;
    }

    /**
     * 获取AssetTransfer
     * @param payload
     * @return
     */
    public static AssetTransfer getAssetTransfer(byte[] payload) {
        AssetTransfer assetTransfer = new AssetTransfer();
        assetTransfer = assetTransfer.RLPdeserialization(payload);
        return assetTransfer;
    }
}
