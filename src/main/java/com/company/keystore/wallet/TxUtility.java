package com.company.keystore.wallet;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.company.ApiResult.APIResult;
import com.company.account.Transaction;
import com.company.contract.AssetDefinition.Asset;
import com.company.contract.AssetDefinition.AssetChangeowner;
import com.company.contract.AssetDefinition.AssetIncreased;
import com.company.contract.AssetDefinition.AssetTransfer;
import com.company.contract.HashheightblockDefinition.Hashheightblock;
import com.company.contract.HashheightblockDefinition.HashheightblockGet;
import com.company.contract.HashheightblockDefinition.HashheightblockTransfer;
import com.company.contract.HashtimeblockDefinition.Hashtimeblock;
import com.company.contract.HashtimeblockDefinition.HashtimeblockGet;
import com.company.contract.HashtimeblockDefinition.HashtimeblockTransfer;
import com.company.contract.MultipleDefinition.MultTransfer;
import com.company.contract.MultipleDefinition.Multiple;
import com.company.contract.RateheightlockDefinition.Rateheightlock;
import com.company.contract.RateheightlockDefinition.RateheightlockDeposit;
import com.company.contract.RateheightlockDefinition.RateheightlockWithdraw;
import com.company.encoding.BigEndian;
import com.company.keystore.crypto.RipemdUtility;
import com.company.keystore.crypto.SHA3Utility;
import com.company.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.company.keystore.crypto.ed25519.Ed25519PublicKey;
import com.company.keystore.util.ByteUtil;
import com.company.protobuf.HatchModel;
import com.company.protobuf.ProtocolModel;
import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Hex;
import org.tdf.rlp.RLPElement;
import java.math.BigDecimal;
import java.math.RoundingMode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TxUtility extends Thread {
    private static final Long rate = 100000000L;
    private static final Long serviceCharge = 200000L;
    static final BigDecimal MAXIMUM_LONG = new BigDecimal(Long.MAX_VALUE);

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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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
            ar.setStatusCode(2000);
            String jsonString = JSON.toJSONString(ar);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
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

    /**
     * 部署资产定义事务
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
    public static JSONObject CreateDeployforRuleAsset(String fromPubkeyStr, Long nonce, String code, BigDecimal offering, BigDecimal totalamount, byte[] createuser, byte[] owner, int allowincrease,byte[] info) {
        try {
            offering = offering.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectOffering = new JSONObject();
            jsonObjectOffering  = isValidPositiveLong(offering);
            if(jsonObjectOffering.getInteger("code") == 5000){
                return jsonObjectOffering;
            }
            totalamount = totalamount.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectTotal = new JSONObject();
            jsonObjectTotal = isValidPositiveLong(totalamount);
            if(jsonObjectTotal.getInteger("code") == 5000){
                return jsonObjectTotal;
            }
            Asset asset = new Asset(code, offering.longValue(), totalamount.longValue(), createuser, owner, allowincrease,info);
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
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的部署资产定义事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @param code
     * @param offering
     * @param createuser
     * @param owner
     * @param allowincrease
     * @param info
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleAsset(String fromPubkeyStr, String prikeyStr, Long nonce, String code, BigDecimal offering, String createuser, String owner, int allowincrease,String info){
        try {
            if(info == null){
                APIResult apiResult = new APIResult();
                apiResult.setMessage("info can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] info_utf8 = info.getBytes(StandardCharsets.UTF_8);
            byte[] createuserBy = Hex.decodeHex(createuser.toCharArray());
            byte[] ownerBy = Hex.decodeHex(WalletUtility.addressToPubkeyHash(owner).toCharArray());
            BigDecimal totalamount = offering;
            JSONObject jsonObject = CreateDeployforRuleAsset(fromPubkeyStr, nonce, code, offering, totalamount, createuserBy, ownerBy, allowincrease,info_utf8);
            if(jsonObject.getInteger("code") == 5000){
                return  jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造资产定义的更换所有者事务
     * @param fromPubkeyStr
     * @param txHash
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
            type[0] = 0X08;
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
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x00}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的资产定义的更换所有者事务
     * @param fromPubkeyStr
     * @param txHash1
     * @param prikeyStr
     * @param nonce
     * @param newowner
     * @return
     */
    public static JSONObject CreateSignToDeployforAssetChangeowner(String fromPubkeyStr, String txHash1, String prikeyStr, Long nonce, String newowner) {
        try {
            byte[] newownerBy;
            if(newowner.equals("0000000000000000000000000000000000000000") || newowner == "0000000000000000000000000000000000000000"){
                newownerBy = Hex.decodeHex(newowner.toCharArray());
            }else{
                newownerBy = Hex.decodeHex(WalletUtility.addressToPubkeyHash(newowner).toCharArray());
            }
            String RawTransactionHex = CreateCallforRuleAssetChangeowner(fromPubkeyStr, txHash1, nonce, newownerBy);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造资产定义的更换所有者事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param newowner
     * @return
     */
    public static String CreateCallforRuleAssetChangeownerAsHash160(String fromPubkeyStr, String txHash160, Long nonce, byte[] newowner) {
        try {
            AssetChangeowner assetChangeowner = new AssetChangeowner(newowner);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = assetChangeowner.RLPdeserialization();
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
     * 构造签名的资产定义的更换所有者事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param prikeyStr
     * @param nonce
     * @param newowner
     * @return
     */
    public static JSONObject CreateSignToDeployforAssetChangeownerAsHash160(String fromPubkeyStr, String txHash160, String prikeyStr, Long nonce, String newowner) {
        try {
            byte[] newownerBy;
            if(newowner.equals("0000000000000000000000000000000000000000") || newowner == "0000000000000000000000000000000000000000"){
                newownerBy = Hex.decodeHex(newowner.toCharArray());
            }else{
                newownerBy = Hex.decodeHex(WalletUtility.addressToPubkeyHash(newowner).toCharArray());
            }
            String RawTransactionHex = CreateCallforRuleAssetChangeownerAsHash160(fromPubkeyStr, txHash160, nonce, newownerBy);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造资产定义的增发事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param amount
     * @return
     */
    public static JSONObject CreateCallforRuleAssetIncreased(String fromPubkeyStr, String txHash, Long nonce, BigDecimal amount) {
        try {
            amount = amount.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectAmount = new JSONObject();
            jsonObjectAmount = isValidPositiveLong(amount);
            if(jsonObjectAmount.getInteger("code") == 5000){
                return jsonObjectAmount;
            }
            AssetIncreased assetIncreased = new AssetIncreased(amount.longValue());
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
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的资产定义的增发事务
     * @param fromPubkeyStr
     * @param txHash1
     * @param prikeyStr
     * @param nonce
     * @param amount
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleAssetIncreased(String fromPubkeyStr, String txHash1, String prikeyStr, Long nonce, BigDecimal amount) {
        try {
            JSONObject jsonObject = CreateCallforRuleAssetIncreased(fromPubkeyStr, txHash1, nonce, amount);
            if(jsonObject.getInteger("code") == 5000){
                return  jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造资产定义的增发事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param amount
     * @return
     */
    public static JSONObject CreateCallforRuleAssetIncreasedAsHash160(String fromPubkeyStr, String txHash160, Long nonce, BigDecimal amount) {
        try {
            amount = amount.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectAmount = new JSONObject();
            jsonObjectAmount = isValidPositiveLong(amount);
            if(jsonObjectAmount.getInteger("code") == 5000){
                return jsonObjectAmount;
            }
            AssetIncreased assetIncreased = new AssetIncreased(amount.longValue());
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
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = assetIncreased.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x02}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的资产定义的增发事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param prikeyStr
     * @param nonce
     * @param amount
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleAssetIncreasedAsHash160(String fromPubkeyStr, String txHash160, String prikeyStr, Long nonce, BigDecimal amount) {
        try {
            JSONObject jsonObject = CreateCallforRuleAssetIncreasedAsHash160(fromPubkeyStr, txHash160, nonce, amount);
            if(jsonObject.getInteger("code") == 5000){
                return  jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }


    /**
     * 构造资产定义的转账事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param from
     * @param to
     * @param value
     * @return
     */
    public static JSONObject CreateDeployforRuleAssetTransfer(String fromPubkeyStr, String txHash, Long nonce, byte[] from, byte[] to, BigDecimal value) {
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            AssetTransfer assetTransfer = new AssetTransfer(from, to, value.longValue());
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
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的资产定义的转账事务
     * @param fromPubkeyStr
     * @param txHash1
     * @param prikeyStr
     * @param nonce
     * @param from
     * @param to
     * @param value
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleTransfer(String fromPubkeyStr, String txHash1, String prikeyStr, Long nonce, String from, String to, BigDecimal value) {
        try {
            byte[] fromBy = Hex.decodeHex(from.toCharArray());
            byte[] toBy = Hex.decodeHex(to.toCharArray());
            JSONObject jsonObject = CreateDeployforRuleAssetTransfer(fromPubkeyStr, txHash1, nonce, fromBy, toBy, value);
            if(jsonObject.getInteger("code") == 5000){
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造资产定义的转账事务(160哈希)
     * @param fromPubkeyStr
     * @param hash160
     * @param nonce
     * @param from
     * @param to
     * @param value
     * @return
     */
    public static JSONObject CreateDeployforRuleAssetTransferAsHash160(String fromPubkeyStr, String hash160, Long nonce, byte[] from, byte[] to, BigDecimal value) {
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            AssetTransfer assetTransfer = new AssetTransfer(from, to, value.longValue());
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
            byte[] toPubkeyHash = Hex.decodeHex(hash160.toCharArray());
            //构造payload
            byte[] payload = assetTransfer.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x01}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的资产定义的转账事务(160哈希)
     * @param fromPubkeyStr
     * @param hash160
     * @param prikeyStr
     * @param nonce
     * @param from
     * @param to
     * @param value
     * @return
     */
    public static JSONObject CreateSignToDeployforRuleTransferAsHash160(String fromPubkeyStr, String hash160, String prikeyStr, Long nonce, String from, String to, BigDecimal value) {
        try {
            byte[] fromBy = Hex.decodeHex(from.toCharArray());
            byte[] toBy = Hex.decodeHex(to.toCharArray());
            JSONObject jsonObject = CreateDeployforRuleAssetTransferAsHash160(fromPubkeyStr, hash160, nonce, fromBy, toBy, value);
            if(jsonObject.getInteger("code") == 5000){
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 多重签名的部署（发布者签名）
     * @param fromPubkeyStr
     * @param assetHash
     * @param min
     * @param max
     * @param pubkeyHashList
     * @param signatures
     * @return
     */
    public static JSONObject CreateMultipleForRuleFirst(String fromPubkeyStr, long nonce , byte[] assetHash,int max, int min, List<byte[]> pubList,List<byte[]> signatures,List<byte[]> pubkeyHashList){
        try {
            Multiple multiple = new Multiple(assetHash, max, min,pubList,signatures,pubkeyHashList);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x07;
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
            String toPubkeyHashStr = "0000000000000000000000000000000000000000";
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = multiple.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length+1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x01}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重规则部署（发布者签名）
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param assetHash
     * @param min
     * @param max
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultipleToDeployforRuleFirst(String fromPubkeyStr, String prikeyStr, long nonce, String assetHash,int max, int min, List<String> pubkeyHashList) {
        try {
            byte[] assetHashBy;
            if(assetHash.equals("0000000000000000000000000000000000000000") || assetHash == "0000000000000000000000000000000000000000"){
                assetHashBy = Hex.decodeHex(assetHash.toCharArray());
            }else{
                assetHashBy = RipemdUtility.ripemd160(Hex.decodeHex(assetHash.toCharArray()));
            }
            List<byte[]> pubListBy = new ArrayList<>();
            List<byte[]> pubHashListBy = new ArrayList<>();
            for (int i = 0 ;i<pubkeyHashList.size();i++){
                String pubkeyHash = pubkeyHashList.get(i);
                byte[] pubkeyHashBy = Hex.decodeHex(pubkeyHash.toCharArray());
                pubHashListBy.add(pubkeyHashBy);
            }
            List<byte[]> signaturesBy = new ArrayList<>();
            JSONObject jsonObjectRes = CreateMultipleForRuleFirst(fromPubkeyStr,nonce ,assetHashBy, max, min,pubListBy,signaturesBy,pubHashListBy);
            if(jsonObjectRes.getInteger("code") == 5000){
                return jsonObjectRes;
            }
            String RawTransactionHex = jsonObjectRes.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            Transaction transaction = new Transaction(new String(Hex.encodeHex(signRawBasicTransaction)));
            byte[] sign = transaction.signature;
            signaturesBy.add(sign);
            JSONObject jsonObjectFirstSign = CreateMultipleForRuleFirst(fromPubkeyStr, nonce,assetHashBy, max, min,pubListBy,signaturesBy,pubHashListBy);
            if(jsonObjectFirstSign.getInteger("code") == 5000){
                return  jsonObjectFirstSign;
            }
            String RawTransactionHexFirstSign = jsonObjectFirstSign.getString("RawTransactionHex");
            byte[] signRawBasicTransactionSign = Hex.decodeHex(signRawBasicTransaction(RawTransactionHexFirstSign, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransactionSign, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransactionSign));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("pubkeyFirstSign",RawTransactionHex);
            jsonObject.put("pubkeyFirst",fromPubkeyStr);
            jsonObject.put("signFirst",traninfo);
            jsonObject.put("data",txHash);
            jsonObject.put("message",traninfo);
            jsonObject.put("statusCode",2000);
            String jsonString = JSON.toJSONString(jsonObject);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重规则部署（其他人签名）
     * @param fromPubkeyStr
     * @param prikeyStr
     * @return
     */
    public static JSONObject CreateMultipleToDeployforRuleOther(String fromPubkeyStr,String pubFirstSign, String prikeyStr,boolean isPutSign) {
        try {
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransactionAndIsSign(pubFirstSign, prikeyStr,isPutSign).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("pubkeyOther",fromPubkeyStr);
            jsonObject.put("signOther",traninfo);
            jsonObject.put("data",txHash);
            jsonObject.put("message",traninfo);
            jsonObject.put("statusCode",2000);
            String jsonString = JSON.toJSONString(jsonObject);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造多重签名部署（拼接事务）
     * @param fromPubkeyStr
     * @param nonce
     * @param assetHash
     * @param max
     * @param min
     * @param pubList
     * @param signatures
     * @return
     */
    public static JSONObject CreateMultipleForRuleSplice(String fromPubkeyStr, long nonce,byte[] assetHash,int max, int min, List<byte[]> pubList,List<byte[]> signatures, List<byte[]> pubkeyHashList){
        try {
            Multiple multiple = new Multiple(assetHash, max, min,pubList,signatures,pubkeyHashList);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x07;
            //Nonce 无符号64位
            byte[] nonece = BigEndian.encodeUint64(nonce +1);
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
            String toPubkeyHashStr = "0000000000000000000000000000000000000000";
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = multiple.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length+1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x01}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重规则部署(拼接签名)
     * @param prikeyStr
     * @param pubFirstSign
     * @param frompubkey
     * @param nonce
     * @param signFirst
     * @param pubkeyOther
     * @param signOther
     * @return
     */
    public static JSONObject CreateMultipleToDeployforRuleSignSplice( String prikeyStr, String pubFirstSign,String frompubkey, long nonce,String signFirst,String pubkeyOther,String signOther){
        try {

            Transaction transaction = new Transaction(signOther);
            byte[] sig = transaction.signature;
            byte[] pubkey = Hex.decodeHex(pubkeyOther.toCharArray());
            Ed25519PublicKey ed25519PublicKey = new Ed25519PublicKey(pubkey);
            boolean isTrue =ed25519PublicKey.verify(Hex.decodeHex(pubFirstSign.toCharArray()),sig);
            if(!isTrue){
                JSONObject jsonObjectSign = new JSONObject();
                jsonObjectSign.put("code",5000);
                jsonObjectSign.put("message","others sign is wrong");
                return jsonObjectSign;
            }
            Transaction transactionFirst = new Transaction(signFirst);
            byte[] payload = transactionFirst.payload;
            Multiple multiple = new Multiple();
            byte[] payloadNew = new byte[payload.length-1];
            for (int i = 1 ; i < payload.length ; i++){
                payloadNew[i-1] = payload[i];
            }
            multiple = multiple.RLPdeserialization(payloadNew);
            byte[] assethash = multiple.getAssetHash();
            int max = multiple.getMax();
            int min = multiple.getMin();
            List<byte[]> pubHashList = new ArrayList<>();
            for(int i = 0 ; i < multiple.getPubkeyHashList().size(); i++){
                pubHashList.add(multiple.getPubkeyHashList().get(i));
            }
            List<byte[]> pubListBy = new ArrayList<>();
            byte[] frompubkeyFirst = Hex.decodeHex(frompubkey.toCharArray());
            byte[] pubOther = Hex.decodeHex(pubkeyOther.toCharArray());
            if(multiple.getPubList().size() == 0) {
                pubListBy.add(frompubkeyFirst);
            } else {
                for (int i = 0; i < multiple.getPubList().size(); i++) {
                    pubListBy.add(multiple.getPubList().get(i));
                }
            }
            if(!frompubkey.equals(pubkeyOther)) {
                pubListBy.add(pubOther);
            }
            List<byte[]> list = new ArrayList<>();
            for(int i = 0 ;i < multiple.getSignatures().size(); i++){
                list.add(multiple.getSignatures().get(i));
            }
            Transaction transactionOther = new Transaction(signOther);
            byte[] sign = transactionOther.signature;
            list.add(sign);
            JSONObject jsonObjectRes = CreateMultipleForRuleSplice(frompubkey, nonce,assethash, max, min,pubListBy,list,pubHashList);
            String RawTransactionHex = jsonObjectRes.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造多重签名转账（发布者签名）
     * @param fromPubkeyStr
     * @param txHash
     * @param origin
     * @param dest
     * @param from
     * @param signatures
     * @param to
     * @param value
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultisignatureForTransferFirst(String fromPubkeyStr,String txHash,long nonce, int origin, int dest, List<byte[]> from, List<byte[]> signatures, byte[] to, BigDecimal value,List<byte[]> pubkeyHashList){
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectValue = new JSONObject();
            jsonObjectValue = isValidPositiveLong(value);
            if(jsonObjectValue.getInteger("code") == 5000){
                return jsonObjectValue;
            }
            MultTransfer multTransfer = new MultTransfer(origin,dest,from,signatures,to,value.longValue(),pubkeyHashList);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x08;
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
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = multTransfer.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length+1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x03},payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重签名转账（发布者签名）
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txHashRule
     * @param origin
     * @param dest
     * @param to
     * @param value
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultisignatureToDeployforRuleFirst(String fromPubkeyStr, String prikeyStr,String txHashRule,long nonce,int origin, int dest, String to, BigDecimal value,List<String> pubkeyHashList) {
        try {
            List<byte[]> pubListBy = new ArrayList<>();
            byte[] toBy = Hex.decodeHex(to.toCharArray());
            List<byte[]> signaturesListBy = new ArrayList<>();
            List<byte[]> pubHashList = new ArrayList<>();
            for (int i = 0 ;i<pubkeyHashList.size();i++){
                pubHashList.add(Hex.decodeHex(pubkeyHashList.get(i).toCharArray()));
            }
            JSONObject jsonObjectFirst = CreateMultisignatureForTransferFirst(fromPubkeyStr, txHashRule,nonce,origin, dest, pubListBy, signaturesListBy, toBy, value,pubHashList);
            if(jsonObjectFirst.getInteger("code") == 5000){
                return  jsonObjectFirst;
            }
            String RawTransactionHexFirst = jsonObjectFirst.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHexFirst, prikeyStr).toCharArray());
            String signRawBasicTransactionS = new String(Hex.encodeHex(signRawBasicTransaction));
            Transaction transaction = new Transaction(signRawBasicTransactionS);;
            byte[] sign = transaction.signature;
            signaturesListBy.add(sign);
            JSONObject jsonObjectFirstSign = CreateMultisignatureForTransferFirst(fromPubkeyStr, txHashRule,nonce,origin, dest, pubListBy, signaturesListBy, toBy, value,pubHashList);
            if(jsonObjectFirstSign.getInteger("code") == 5000){
                return  jsonObjectFirstSign;
            }
            String RawTransactionHexFirstSign = jsonObjectFirstSign.getString("RawTransactionHex");
            byte[] signRawBasicTransactionSign = Hex.decodeHex(signRawBasicTransaction(RawTransactionHexFirstSign, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransactionSign, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransactionSign));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("pubkeyFirstSign",RawTransactionHexFirst);
            jsonObject.put("pubkeyFirst",fromPubkeyStr);
            jsonObject.put("signFirst",traninfo);
            jsonObject.put("data",txHash);
            jsonObject.put("statusCode",2000);
            String jsonString = JSON.toJSONString(jsonObject);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重签名转账（其他人签名）
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param isPutSign
     * @return
     */
    public static JSONObject CreateMultisignatureToDeployforRuleOther(String fromPubkeyStr,String pubkeyFirstSign, String prikeyStr,boolean isPutSign){
        try {
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransactionAndIsSign(pubkeyFirstSign, prikeyStr,isPutSign).toCharArray());
            String signRawBasicTransactionS = new String(Hex.encodeHex(signRawBasicTransaction));
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("pubkeyOther",fromPubkeyStr);
            jsonObject.put("signOther",signRawBasicTransactionS);
            jsonObject.put("data",txHash);
            jsonObject.put("message",traninfo);
            jsonObject.put("statusCode",2000);
            String jsonString = JSON.toJSONString(jsonObject);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造多重签名转账（拼接签名）
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param origin
     * @param dest
     * @param from
     * @param signatures
     * @param to
     * @param value
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultisignatureForTransferSplice(String fromPubkeyStr, String txHash, long nonce,int origin, int dest, List<byte[]> from, List<byte[]> signatures, byte[] to, BigDecimal value,List<byte[]> pubkeyHashList){
        try {
            MultTransfer multTransfer = new MultTransfer(origin,dest,from,signatures,to,value.longValue(),pubkeyHashList);
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
            byte[] payload = multTransfer.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length+1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x03}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重签名转账(拼接签名)
     * @param prikeyStr
     * @param txHashRule
     * @param signFirst
     * @param pubkeyOther
     * @param signOther
     * @return
     */
    public static JSONObject CreateMultisignatureToDeployforRuleSignSplice(String prikeyStr, String pubkeyFirstSign,String frompubkey,String txHashRule,long nonce,String signFirst,String pubkeyOther,String signOther,int type){
        try {
            Transaction transactionPay = new Transaction(signFirst);
            byte[] payload = transactionPay.payload;
            MultTransfer multTransfer = new MultTransfer();
            byte[] payloadNew = new byte[payload.length-1];
            for (int i = 1 ; i < payload.length ; i++){
                payloadNew[i-1] = payload[i];
            }
            multTransfer = multTransfer.RLPdeserialization(payloadNew);
            List<byte[]> list = new ArrayList<>();
            for(int i = 0 ;i<multTransfer.getSignatures().size();i++){
                list.add(multTransfer.getSignatures().get(i));
            }
            int origin = multTransfer.getOrigin();
            int dest = multTransfer.getDest();
            byte[] toBy = multTransfer.getTo();
            long value = multTransfer.getValue();
            BigDecimal valueBig = new BigDecimal(value);
            byte[] frompubkeyBy = Hex.decodeHex(frompubkey.toCharArray());
            byte[] pubkeyOtherBy = Hex.decodeHex(pubkeyOther.toCharArray());
            //公钥数组
            List<byte[]> fromList = new ArrayList<>();
            if(multTransfer.getFrom().size() == 0){
                fromList.add(frompubkeyBy);
            }else{
                for(int i = 0 ;i<multTransfer.getFrom().size();i++){
                    fromList.add(multTransfer.getFrom().get(i));
                }
            }
            if(!frompubkey.equals(pubkeyOther)) {
                fromList.add(pubkeyOtherBy);
            }
            //公钥哈希数组
            List<byte[]> pubkeyHashList = new ArrayList<>();
            for(int i = 0 ;i<multTransfer.getPubkeyHashList().size();i++){
                pubkeyHashList.add(multTransfer.getPubkeyHashList().get(i));
            }
            JSONObject jsonObjectRes = new JSONObject();
            if(type == 1){
                jsonObjectRes = CreateMultisignatureForTransferSplice(frompubkey,txHashRule,nonce,origin,dest,fromList,list,toBy,valueBig,pubkeyHashList);
            }else if(type == 2 ||type == 3){
                //验证其他人的签名
                Transaction transaction = new Transaction(signOther);
                byte[] sig = transaction.signature;
                byte[] pubkey = Hex.decodeHex(pubkeyOther.toCharArray());
                Ed25519PublicKey ed25519PublicKey = new Ed25519PublicKey(pubkey);
                boolean isTrue =ed25519PublicKey.verify(Hex.decodeHex(pubkeyFirstSign.toCharArray()),sig);
                if(!isTrue){
                    JSONObject jsonObjectSign = new JSONObject();
                    jsonObjectSign.put("code",5000);
                    jsonObjectSign.put("message","others sign is wrong");
                    return jsonObjectSign;
                }
                list.add(sig);
                jsonObjectRes = CreateMultisignatureForTransferSplice(frompubkey,txHashRule,nonce,origin,dest,fromList,list,toBy,valueBig,pubkeyHashList);
            } else {
                JSONObject jsonObjectType = new JSONObject();
                jsonObjectType.put("code",5000);
                jsonObjectType.put("message","type can only be 1 or 2 or 3");
                return jsonObjectType;
            }
            String RawTransactionHex = jsonObjectRes.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }


    /**
     * 构造多重签名转账（发布者签名）(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param origin
     * @param dest
     * @param from
     * @param signatures
     * @param to
     * @param value
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultisignatureForTransferFirstAsHash160(String fromPubkeyStr,String txHash160,long nonce, int origin, int dest, List<byte[]> from, List<byte[]> signatures, byte[] to, BigDecimal value,List<byte[]> pubkeyHashList){
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectValue = new JSONObject();
            jsonObjectValue = isValidPositiveLong(value);
            if(jsonObjectValue.getInteger("code") == 5000){
                return jsonObjectValue;
            }
            MultTransfer multTransfer = new MultTransfer(origin,dest,from,signatures,to,value.longValue(),pubkeyHashList);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0x08;
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
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = multTransfer.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length+1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x03},payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重签名转账（发布者签名）(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txHashRule160
     * @param origin
     * @param dest
     * @param to
     * @param value
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultisignatureToDeployforRuleFirstAsHash160(String fromPubkeyStr, String prikeyStr,String txHashRule160,long nonce,int origin, int dest, String to, BigDecimal value,List<String> pubkeyHashList) {
        try {
            List<byte[]> pubListBy = new ArrayList<>();
            byte[] toBy = Hex.decodeHex(to.toCharArray());
            List<byte[]> signaturesListBy = new ArrayList<>();
            List<byte[]> pubHashList = new ArrayList<>();
            for (int i = 0 ;i<pubkeyHashList.size();i++){
                pubHashList.add(Hex.decodeHex(pubkeyHashList.get(i).toCharArray()));
            }
            JSONObject jsonObjectFirst = CreateMultisignatureForTransferFirstAsHash160(fromPubkeyStr, txHashRule160,nonce,origin, dest, pubListBy, signaturesListBy, toBy, value,pubHashList);
            if(jsonObjectFirst.getInteger("code") == 5000){
                return  jsonObjectFirst;
            }
            String RawTransactionHexFirst = jsonObjectFirst.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHexFirst, prikeyStr).toCharArray());
            String signRawBasicTransactionS = new String(Hex.encodeHex(signRawBasicTransaction));
            Transaction transaction = new Transaction(signRawBasicTransactionS);;
            byte[] sign = transaction.signature;
            signaturesListBy.add(sign);
            JSONObject jsonObjectFirstSign = CreateMultisignatureForTransferFirstAsHash160(fromPubkeyStr, txHashRule160,nonce,origin, dest, pubListBy, signaturesListBy, toBy, value,pubHashList);
            if(jsonObjectFirstSign.getInteger("code") == 5000){
                return  jsonObjectFirstSign;
            }
            String RawTransactionHexFirstSign = jsonObjectFirstSign.getString("RawTransactionHex");
            byte[] signRawBasicTransactionSign = Hex.decodeHex(signRawBasicTransaction(RawTransactionHexFirstSign, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransactionSign, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransactionSign));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("pubkeyFirstSign",RawTransactionHexFirst);
            jsonObject.put("pubkeyFirst",fromPubkeyStr);
            jsonObject.put("signFirst",traninfo);
            jsonObject.put("data",txHash);
            jsonObject.put("statusCode",2000);
            String jsonString = JSON.toJSONString(jsonObject);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重签名转账（其他人签名）(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param isPutSign
     * @return
     */
    public static JSONObject CreateMultisignatureToDeployforRuleOtherAsHash160(String fromPubkeyStr,String pubkeyFirstSign, String prikeyStr,boolean isPutSign){
        try {
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransactionAndIsSign(pubkeyFirstSign, prikeyStr,isPutSign).toCharArray());
            String signRawBasicTransactionS = new String(Hex.encodeHex(signRawBasicTransaction));
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("pubkeyOther",fromPubkeyStr);
            jsonObject.put("signOther",signRawBasicTransactionS);
            jsonObject.put("data",txHash);
            jsonObject.put("message",traninfo);
            jsonObject.put("statusCode",2000);
            String jsonString = JSON.toJSONString(jsonObject);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造多重签名转账（拼接签名）(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param origin
     * @param dest
     * @param from
     * @param signatures
     * @param to
     * @param value
     * @param pubkeyHashList
     * @return
     */
    public static JSONObject CreateMultisignatureForTransferSpliceAsHash160(String fromPubkeyStr, String txHash160, long nonce,int origin, int dest, List<byte[]> from, List<byte[]> signatures, byte[] to, BigDecimal value,List<byte[]> pubkeyHashList){
        try {
            MultTransfer multTransfer = new MultTransfer(origin,dest,from,signatures,to,value.longValue(),pubkeyHashList);
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
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = multTransfer.RLPdeserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length+1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x03}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的多重签名转账(拼接签名)(160哈希)
     * @param prikeyStr
     * @param txHashRule160
     * @param signFirst
     * @param pubkeyOther
     * @param signOther
     * @return
     */
    public static JSONObject CreateMultisignatureToDeployforRuleSignSpliceAsHash160(String prikeyStr, String pubkeyFirstSign,String frompubkey,String txHashRule160,long nonce,String signFirst,String pubkeyOther,String signOther,int type){
        try {
            Transaction transactionPay = new Transaction(signFirst);
            byte[] payload = transactionPay.payload;
            MultTransfer multTransfer = new MultTransfer();
            byte[] payloadNew = new byte[payload.length-1];
            for (int i = 1 ; i < payload.length ; i++){
                payloadNew[i-1] = payload[i];
            }
            multTransfer = multTransfer.RLPdeserialization(payloadNew);
            List<byte[]> list = new ArrayList<>();
            for(int i = 0 ;i<multTransfer.getSignatures().size();i++){
                list.add(multTransfer.getSignatures().get(i));
            }
            int origin = multTransfer.getOrigin();
            int dest = multTransfer.getDest();
            byte[] toBy = multTransfer.getTo();
            long value = multTransfer.getValue();
            BigDecimal valueBig = new BigDecimal(value);
            byte[] frompubkeyBy = Hex.decodeHex(frompubkey.toCharArray());
            byte[] pubkeyOtherBy = Hex.decodeHex(pubkeyOther.toCharArray());
            //公钥数组
            List<byte[]> fromList = new ArrayList<>();
            if(multTransfer.getFrom().size() == 0){
                fromList.add(frompubkeyBy);
            }else{
                for(int i = 0 ;i<multTransfer.getFrom().size();i++){
                    fromList.add(multTransfer.getFrom().get(i));
                }
            }
            if(!frompubkey.equals(pubkeyOther)) {
                fromList.add(pubkeyOtherBy);
            }
            //公钥哈希数组
            List<byte[]> pubkeyHashList = new ArrayList<>();
            for(int i = 0 ;i<multTransfer.getPubkeyHashList().size();i++){
                pubkeyHashList.add(multTransfer.getPubkeyHashList().get(i));
            }
            JSONObject jsonObjectRes = new JSONObject();
            if(type == 1){
                jsonObjectRes = CreateMultisignatureForTransferSpliceAsHash160(frompubkey,txHashRule160,nonce,origin,dest,fromList,list,toBy,valueBig,pubkeyHashList);
            }else if(type == 2 ||type == 3){
                //验证其他人的签名
                Transaction transaction = new Transaction(signOther);
                byte[] sig = transaction.signature;
                byte[] pubkey = Hex.decodeHex(pubkeyOther.toCharArray());
                Ed25519PublicKey ed25519PublicKey = new Ed25519PublicKey(pubkey);
                boolean isTrue =ed25519PublicKey.verify(Hex.decodeHex(pubkeyFirstSign.toCharArray()),sig);
                if(!isTrue){
                    JSONObject jsonObjectSign = new JSONObject();
                    jsonObjectSign.put("code",5000);
                    jsonObjectSign.put("message","others sign is wrong");
                    return jsonObjectSign;
                }
                list.add(sig);
                jsonObjectRes = CreateMultisignatureForTransferSpliceAsHash160(frompubkey,txHashRule160,nonce,origin,dest,fromList,list,toBy,valueBig,pubkeyHashList);
            } else {
                JSONObject jsonObjectType = new JSONObject();
                jsonObjectType.put("code",5000);
                jsonObjectType.put("message","type can only be 1 or 2 or 3");
                return jsonObjectType;
            }
            String RawTransactionHex = jsonObjectRes.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造时间锁定的事务
     * @param fromPubkeyStr
     * @param nonce
     * @param assetHash
     * @param pubkeyHash
     * @return
     */
    public static String hashTimeBlockForDeploy(String fromPubkeyStr,long nonce, byte[] assetHash,byte[] pubkeyHash){
        try {
            Hashtimeblock hashtimeblock = new Hashtimeblock(assetHash,pubkeyHash);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X07;
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
            //接收者公钥哈希,填0
            String toPubkeyHashStr = "0000000000000000000000000000000000000000";
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = hashtimeblock.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x02}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的时间锁定的事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @param assetHash
     * @param pubkeyHash
     * @return
     */
    public static JSONObject CreateHashTimeBlockForDeploy(String fromPubkeyStr,String prikeyStr,long nonce, String assetHash,String pubkeyHash) {
        try {
            byte[] assetHashBy;
            if(assetHash.equals("0000000000000000000000000000000000000000") || assetHash == "0000000000000000000000000000000000000000"){
                assetHashBy = Hex.decodeHex(assetHash.toCharArray());
            }else{
                assetHashBy = RipemdUtility.ripemd160(Hex.decodeHex(assetHash.toCharArray()));
            }
            byte[] pubkeyHashBy = Hex.decodeHex(pubkeyHash.toCharArray());
            String RawTransactionHex = hashTimeBlockForDeploy(fromPubkeyStr, nonce,assetHashBy, pubkeyHashBy);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造获得锁定资产事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static String hashTimeBlockGetForDeploy(String fromPubkeyStr,String txHash,long nonce, byte[] transferhash,String origintext){
        try {
            HashtimeblockGet hashtimeblockGet = new HashtimeblockGet(transferhash,origintext);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //部署事务的事务哈希
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = hashtimeblockGet.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x05},payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的获得锁定资产事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static JSONObject CreateHashTimeBlockGetForDeploy(String fromPubkeyStr,String prikeyStr,String txGetHash,long nonce, String transferhash,String origintext) {
        APIResult apiResult = new APIResult();
        try {
            if(origintext == null ){
                apiResult.setMessage("origintext can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String origintextNew = origintext.replace(" ","");
            byte[] origintext_utf8 = origintextNew.getBytes(StandardCharsets.UTF_8);
            if(origintext_utf8.length > 512 || origintext_utf8.length <= 0){
                apiResult.setMessage("origintext length is too large or too short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] transferhashBy = Hex.decodeHex(transferhash.toCharArray());
            String RawTransactionHex = hashTimeBlockGetForDeploy(fromPubkeyStr, txGetHash,nonce,transferhashBy,origintextNew);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造获得锁定资产事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static String hashTimeBlockGetForDeployAsHash160(String fromPubkeyStr,String txHash160,long nonce, byte[] transferhash,String origintext){
        try {
            HashtimeblockGet hashtimeblockGet = new HashtimeblockGet(transferhash,origintext);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //部署事务的事务哈希
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = hashtimeblockGet.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x05},payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的获得锁定资产事务(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash160
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static JSONObject CreateHashTimeBlockGetForDeployAsHash160(String fromPubkeyStr,String prikeyStr,String txGetHash160,long nonce, String transferhash,String origintext) {
        APIResult apiResult = new APIResult();
        try {
            if(origintext == null ){
                apiResult.setMessage("origintext can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String origintextNew = origintext.replace(" ","");
            byte[] origintext_utf8 = origintextNew.getBytes(StandardCharsets.UTF_8);
            if(origintext_utf8.length > 512 || origintext_utf8.length <= 0){
                apiResult.setMessage("origintext length is too large or too short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] transferhashBy = Hex.decodeHex(transferhash.toCharArray());
            String RawTransactionHex = hashTimeBlockGetForDeployAsHash160(fromPubkeyStr, txGetHash160,nonce,transferhashBy,origintextNew);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }


    /**
     * 构造时间锁定的转发资产事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param value
     * @param hashresult
     * @param timestamp
     * @return
     */
    public static JSONObject hashTimeBlockTransferForDeploy(String fromPubkeyStr,String txHash,long nonce,BigDecimal value,byte[] hashresult,BigDecimal timestamp){
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectValue = new JSONObject();
            jsonObjectValue = isValidPositiveLong(value);
            if(jsonObjectValue.getInteger("code") == 5000){
                return jsonObjectValue;
            }
            HashtimeblockTransfer hashtimeblockTransfer = new HashtimeblockTransfer(value.longValue(),hashresult,timestamp.longValue());
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = hashtimeblockTransfer.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x04}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的时间锁定的转发资产事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash
     * @param nonce
     * @param value
     * @param hashresult
     * @param timestamp
     * @return
     */
    public static JSONObject CreateHashTimeBlockTransferForDeploy(String fromPubkeyStr,String prikeyStr,String txGetHash,long nonce,BigDecimal value,String hashresult,BigDecimal timestamp) {
        APIResult apiResult = new APIResult();
        try {
            if(hashresult == null){
                apiResult.setMessage("hashresult can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String hashresultNew = hashresult.replace(" ","");
            if(hashresultNew == "" || "".equals(hashresultNew)){
                apiResult.setMessage("hashresult can not be empty");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresult_utf8 = hashresultNew.getBytes(StandardCharsets.UTF_8);
            if(hashresult_utf8.length > 512 || hashresult_utf8.length <= 0){
                apiResult.setMessage("hashresult length is too large or too short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresultByte = SHA3Utility.sha3256(hashresult_utf8);
            JSONObject jsonObject = hashTimeBlockTransferForDeploy(fromPubkeyStr,txGetHash, nonce,value,hashresultByte, timestamp);
            if(jsonObject.getInteger("code") == 5000){
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造时间锁定的转发资产事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param value
     * @param hashresult
     * @param timestamp
     * @return
     */
    public static JSONObject hashTimeBlockTransferForDeployAsHash160(String fromPubkeyStr,String txHash160,long nonce,BigDecimal value,byte[] hashresult,BigDecimal timestamp){
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectValue = new JSONObject();
            jsonObjectValue = isValidPositiveLong(value);
            if(jsonObjectValue.getInteger("code") == 5000){
                return jsonObjectValue;
            }
            HashtimeblockTransfer hashtimeblockTransfer = new HashtimeblockTransfer(value.longValue(),hashresult,timestamp.longValue());
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = hashtimeblockTransfer.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x04}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的时间锁定的转发资产事务(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash160
     * @param nonce
     * @param value
     * @param hashresult
     * @param timestamp
     * @return
     */
    public static JSONObject CreateHashTimeBlockTransferForDeployAsHa(String fromPubkeyStr,String prikeyStr,String txGetHash160,long nonce,BigDecimal value,String hashresult,BigDecimal timestamp) {
        APIResult apiResult = new APIResult();
        try {
            if(hashresult == null){
                apiResult.setMessage("hashresult can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String hashresultNew = hashresult.replace(" ","");
            if(hashresultNew == "" || "".equals(hashresultNew)){
                apiResult.setMessage("hashresult can not be empty");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresult_utf8 = hashresultNew.getBytes(StandardCharsets.UTF_8);
            if(hashresult_utf8.length > 512 || hashresult_utf8.length <= 0){
                apiResult.setMessage("hashresult length is too large or too short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresultByte = SHA3Utility.sha3256(hashresult_utf8);
            JSONObject jsonObject = hashTimeBlockTransferForDeployAsHash160(fromPubkeyStr,txGetHash160, nonce,value,hashresultByte, timestamp);
            if(jsonObject.getInteger("code") == 5000){
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造区块高度锁定支付的事务
     * @param fromPubkeyStr
     * @param nonce
     * @param assetHash
     * @param pubkeyHash
     * @return
     */
    public static String HashHeightBlockForDeploy(String fromPubkeyStr,long nonce, byte[] assetHash,byte[] pubkeyHash){
        try {
            Hashheightblock hashheightblock = new Hashheightblock(assetHash,pubkeyHash);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X07;
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
            //接收者公钥哈希,填0
            String toPubkeyHashStr = "0000000000000000000000000000000000000000";
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = hashheightblock.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x03}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的区块高度锁定支付事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @param assetHash
     * @param pubkeyHash
     * @return
     */
    public static JSONObject CreateHashHeightBlockForDeploy(String fromPubkeyStr,String prikeyStr,long nonce, String assetHash,String pubkeyHash) {
        try {
            byte[] assetHashBy;
            if(assetHash.equals("0000000000000000000000000000000000000000") || assetHash == "0000000000000000000000000000000000000000"){
                assetHashBy = Hex.decodeHex(assetHash.toCharArray());
            }else{
                assetHashBy = RipemdUtility.ripemd160(Hex.decodeHex(assetHash.toCharArray()));
            }
            byte[] pubkeyHashBy = Hex.decodeHex(pubkeyHash.toCharArray());
            String RawTransactionHex = HashHeightBlockForDeploy(fromPubkeyStr, nonce,assetHashBy, pubkeyHashBy);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造区块高度锁定的获得锁定资产事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static String HashHeightBlockGetForDeploy(String fromPubkeyStr,String txHash,long nonce, byte[] transferhash,String origintext){
        try {
            HashheightblockGet hashheightblockGet = new HashheightblockGet(transferhash,origintext);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = hashheightblockGet.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x07},payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的获得锁定资产事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static JSONObject CreateHashHeightBlockGetForDeploy(String fromPubkeyStr,String prikeyStr,String txGetHash,long nonce, String transferhash,String origintext) {
        APIResult apiResult = new APIResult();
        try {
            if(origintext == null){
                apiResult.setMessage("origintext can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String origintextNew = origintext.replace(" ","");
            byte[] origintext_utf8 = origintextNew.getBytes(StandardCharsets.UTF_8);
            if(origintext_utf8.length > 512 || origintext_utf8.length <=0){
                apiResult.setMessage("origintext length is too large or too short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] transferhashBy = Hex.decodeHex(transferhash.toCharArray());
            String RawTransactionHex = HashHeightBlockGetForDeploy(fromPubkeyStr, txGetHash,nonce,transferhashBy,origintextNew);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }


    /**
     * 构造区块高度锁定的获得锁定资产事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static String HashHeightBlockGetForDeployAsHash160(String fromPubkeyStr,String txHash160,long nonce, byte[] transferhash,String origintext){
        try {
            HashheightblockGet hashheightblockGet = new HashheightblockGet(transferhash,origintext);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = hashheightblockGet.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength, new byte[]{0x07},payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            return RawTransactionStr;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 构造签名的获得锁定资产事务(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash160
     * @param nonce
     * @param transferhash
     * @param origintext
     * @return
     */
    public static JSONObject CreateHashHeightBlockGetForDeployAsHash160(String fromPubkeyStr,String prikeyStr,String txGetHash160,long nonce, String transferhash,String origintext) {
        APIResult apiResult = new APIResult();
        try {
            if(origintext == null){
                apiResult.setMessage("origintext can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String origintextNew = origintext.replace(" ","");
            byte[] origintext_utf8 = origintextNew.getBytes(StandardCharsets.UTF_8);
            if(origintext_utf8.length > 512 || origintext_utf8.length <=0){
                apiResult.setMessage("origintext length is too large or too short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] transferhashBy = Hex.decodeHex(transferhash.toCharArray());
            String RawTransactionHex = HashHeightBlockGetForDeployAsHash160(fromPubkeyStr, txGetHash160,nonce,transferhashBy,origintextNew);
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造区块高度锁定的转发资产事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param value
     * @param hashresult
     * @param blockheight
     * @return
     */
    public static JSONObject HashHeightBlockTransferForDeploy(String fromPubkeyStr,String txHash,long nonce,BigDecimal value,byte[] hashresult,BigDecimal blockheight){
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectValue = new JSONObject();
            jsonObjectValue = isValidPositiveLong(value);
            if(jsonObjectValue.getInteger("code") == 5000){
                return jsonObjectValue;
            }
            if (new BigDecimal(blockheight.longValue()).compareTo(blockheight) != 0 || blockheight.compareTo(BigDecimal.ZERO) < 0 ) {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("message", "blockheight must be a positive long number");
                jsonObject.put("data", "");
                jsonObject.put("code", "5000");
                return jsonObject;
            }
            HashheightblockTransfer hashheightblockTransfer = new HashheightblockTransfer(value.longValue(),hashresult,blockheight.longValue());
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] txHash1 = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHash1);
            //构造payload
            byte[] payload = hashheightblockTransfer.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x06}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的区块高度锁定的转发资产事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash
     * @param nonce
     * @param value
     * @param hashresult
     * @param blockheight
     * @return
     */
    public static JSONObject CreateHashHeightBlockTransferForDeploy(String fromPubkeyStr,String prikeyStr,String txGetHash,long nonce,BigDecimal value,String hashresult,BigDecimal blockheight) {
        APIResult apiResult = new APIResult();
        try {
            if(hashresult == null){
                apiResult.setMessage("hashresult can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String hashresultNew = hashresult.replace(" ","");
            if(hashresultNew == "" || "".equals(hashresultNew)){
                apiResult.setMessage("hashresult can not be empty");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresult_utf8 = hashresultNew.getBytes(StandardCharsets.UTF_8);
            if(hashresult_utf8.length > 512 || hashresult_utf8.length <= 0){
                apiResult.setMessage("hashresult length is too large or to short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresultByte = SHA3Utility.sha3256(hashresult_utf8);
            JSONObject jsonObject = HashHeightBlockTransferForDeploy(fromPubkeyStr,txGetHash, nonce,value,hashresultByte, blockheight);
            if(jsonObject.getInteger("code") == 5000){
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造区块高度锁定的转发资产事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param value
     * @param hashresult
     * @param blockheight
     * @return
     */
    public static JSONObject HashHeightBlockTransferForDeployAsHash160(String fromPubkeyStr,String txHash160,long nonce,BigDecimal value,byte[] hashresult,BigDecimal blockheight){
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            JSONObject jsonObjectValue = new JSONObject();
            jsonObjectValue = isValidPositiveLong(value);
            if(jsonObjectValue.getInteger("code") == 5000){
                return jsonObjectValue;
            }
            if (new BigDecimal(blockheight.longValue()).compareTo(blockheight) != 0 || blockheight.compareTo(BigDecimal.ZERO) < 0 ) {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("message", "blockheight must be a positive long number");
                jsonObject.put("data", "");
                jsonObject.put("code", "5000");
                return jsonObject;
            }
            HashheightblockTransfer hashheightblockTransfer = new HashheightblockTransfer(value.longValue(),hashresult,blockheight.longValue());
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = hashheightblockTransfer.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x06}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的区块高度锁定的转发资产事务(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param txGetHash160
     * @param nonce
     * @param value
     * @param hashresult
     * @param blockheight
     * @return
     */
    public static JSONObject CreateHashHeightBlockTransferForDeployAsHash160(String fromPubkeyStr,String prikeyStr,String txGetHash160,long nonce,BigDecimal value,String hashresult,BigDecimal blockheight) {
        APIResult apiResult = new APIResult();
        try {
            if(hashresult == null){
                apiResult.setMessage("hashresult can not be null");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            String hashresultNew = hashresult.replace(" ","");
            if(hashresultNew == "" || "".equals(hashresultNew)){
                apiResult.setMessage("hashresult can not be empty");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresult_utf8 = hashresultNew.getBytes(StandardCharsets.UTF_8);
            if(hashresult_utf8.length > 512 || hashresult_utf8.length <= 0){
                apiResult.setMessage("hashresult length is too large or to short");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] hashresultByte = SHA3Utility.sha3256(hashresult_utf8);
            JSONObject jsonObject = HashHeightBlockTransferForDeployAsHash160(fromPubkeyStr,txGetHash160, nonce,value,hashresultByte, blockheight);
            if(jsonObject.getInteger("code") == 5000){
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造部署定额条件比例支付事务
     * @param fromPubkeyStr
     * @param nonce
     * @param assetHash
     * @param onetimedepositmultiple
     * @param withdrawperiodheight
     * @param withdrawrate
     * @param dest
     * @return
     */
    public static JSONObject CreateRateheightlockRule(String fromPubkeyStr, long nonce, byte[] assetHash, long onetimedepositmultiple, int withdrawperiodheight, String withdrawrate, byte[] dest){
        try {
            Map stateMap = new HashMap();
            Rateheightlock rateheightlock = new Rateheightlock(assetHash,onetimedepositmultiple,withdrawperiodheight,withdrawrate,dest, stateMap);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X07;
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
            //接收者公钥哈希,填0
            String toPubkeyHashStr = "0000000000000000000000000000000000000000";
            byte[] toPubkeyHash = Hex.decodeHex(toPubkeyHashStr.toCharArray());
            //构造payload
            byte[] payload = rateheightlock.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x04}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的部署定额条件比例支付事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @param assetHash
     * @param onetimedepositmultiple
     * @param withdrawperiodheight
     * @param withdrawrate
     * @param dest
     * @return
     */
    public static JSONObject CreateRateheightlockruleForDeploy(String fromPubkeyStr,String prikeyStr,long nonce, String assetHash, BigDecimal onetimedepositmultiple, int withdrawperiodheight, String withdrawrate, String dest) {
        APIResult apiResult = new APIResult();
        try {
//            if(assetHash == "0000000000000000000000000000000000000000") {
                byte[] assetHashByte;
                if(assetHash != "0000000000000000000000000000000000000000") {
                    assetHashByte = RipemdUtility.ripemd160(Hex.decodeHex(assetHash.toCharArray()));
                }else{
                    assetHashByte = Hex.decodeHex(assetHash.toCharArray());
                }
                BigDecimal compare = new BigDecimal("100000000");
                if(onetimedepositmultiple.compareTo(compare) > 0 || new BigDecimal(onetimedepositmultiple.longValue()).compareTo(onetimedepositmultiple) != 0
                        ||onetimedepositmultiple.compareTo(BigDecimal.ONE) <= 0){
                    apiResult.setMessage("转入的资产金额错误");
                    apiResult.setStatusCode(5000);
                    String jsonString = JSON.toJSONString(apiResult);
                    JSONObject json = JSON.parseObject(jsonString);
                    return json;
                }
                BigDecimal withdrawperiodheightBig = new BigDecimal(withdrawperiodheight);
                if(new BigDecimal(withdrawperiodheightBig.longValue()).compareTo(withdrawperiodheightBig) != 0 || withdrawperiodheightBig.compareTo(BigDecimal.ZERO) <= 0
                        || withdrawperiodheightBig.compareTo(new BigDecimal(Integer.MAX_VALUE)) > 0){
                    apiResult.setMessage("资产的提取高度周期错误");
                    apiResult.setStatusCode(5000);
                    String jsonString = JSON.toJSONString(apiResult);
                    JSONObject json = JSON.parseObject(jsonString);
                    return json;
                }
                BigDecimal fenzi = new BigDecimal("100");
                BigDecimal with = new BigDecimal(withdrawrate);
                BigDecimal chenJi = onetimedepositmultiple.multiply(BigDecimal.valueOf(rate));
                //判断提取比率小数位数
                String string = with.stripTrailingZeros().toPlainString();
                int index = string.indexOf(".");
                index = index < 0 ? 0 : string.length() - index - 1;
                if(with.compareTo(fenzi) > 0 || with.compareTo(BigDecimal.ZERO) <= 0 || new BigDecimal(onetimedepositmultiple.multiply(with).divide(fenzi).longValue()).compareTo(onetimedepositmultiple.multiply(with).divide(fenzi)) != 0
                || chenJi.divideAndRemainder(with.multiply(onetimedepositmultiple))[1].compareTo(BigDecimal.ZERO) != 0 || index > 6){
                    apiResult.setMessage("提取比例错误");
                    apiResult.setStatusCode(5000);
                    String jsonString = JSON.toJSONString(apiResult);
                    JSONObject json = JSON.parseObject(jsonString);
                    return json;
                }
                long onetimedepositmultipleLong = onetimedepositmultiple.longValue();
                byte[] destByte = Hex.decodeHex(dest.toCharArray());
                String withString = String.valueOf(with.divide(BigDecimal.valueOf(100)));
                JSONObject jsonObject = CreateRateheightlockRule(fromPubkeyStr, nonce, assetHashByte, onetimedepositmultipleLong, withdrawperiodheight, withString, destByte);
                if (jsonObject.getInteger("code") == 5000) {
                    return jsonObject;
                }
                String RawTransactionHex = jsonObject.getString("RawTransactionHex");
                byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
                byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
                String txHash = new String(Hex.encodeHex(hash));
                String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
                APIResult result = new APIResult();
                result.setData(txHash);
                result.setMessage(traninfo);
                result.setStatusCode(2000);
                String jsonString = JSON.toJSONString(result);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
//            }else{
//                apiResult.setMessage("还不支持非WDC资产");
//                apiResult.setStatusCode(5000);
//                String jsonString = JSON.toJSONString(apiResult);
//                JSONObject json = JSON.parseObject(jsonString);
//                return json;
//            }
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造调用定额条件比例支付的转入金额事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param value
     * @return
     */
    public static JSONObject CreateRateheightlockDepositRule(String fromPubkeyStr,String txHash, long nonce, BigDecimal value){
        try {
            RateheightlockDeposit rateheightlockDeposit = new RateheightlockDeposit(value.longValue());
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] txHashGet = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHashGet);
            //构造payload
            byte[] payload = rateheightlockDeposit.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x08}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的调用定额条件比例支付的转入金额事务
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @return
     */
    public static JSONObject CreateRateheightlockDepositRuleForDeploy(String fromPubkeyStr,String prikeyStr,String txHashCreate,long nonce, BigDecimal value) {
        APIResult apiResult = new APIResult();
        try {
                value = value.multiply(BigDecimal.valueOf(rate));
                if(value.equals("") || value == null){
                    apiResult.setMessage("金额不能为空");
                    apiResult.setStatusCode(5000);
                    String jsonString = JSON.toJSONString(apiResult);
                    JSONObject json = JSON.parseObject(jsonString);
                    return json;
                }
                if(value.compareTo(BigDecimal.ZERO) <= 0){
                    apiResult.setMessage("必须为正整数");
                    apiResult.setStatusCode(5000);
                    String jsonString = JSON.toJSONString(apiResult);
                    JSONObject json = JSON.parseObject(jsonString);
                    return json;
                }
                //判断是否有小数
                String string = value.stripTrailingZeros().toPlainString();
                int index = string.indexOf(".");
                index = index < 0 ? 0 : string.length() - index - 1;
                if(index > 0){
                    apiResult.setMessage("金额输入错误");
                    apiResult.setStatusCode(5000);
                    String jsonString = JSON.toJSONString(apiResult);
                    JSONObject json = JSON.parseObject(jsonString);
                    return json;
                }
                JSONObject jsonObject = CreateRateheightlockDepositRule(fromPubkeyStr, txHashCreate,nonce,value );
                if (jsonObject.getInteger("code") == 5000) {
                    return jsonObject;
                }
                String RawTransactionHex = jsonObject.getString("RawTransactionHex");
                byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
                byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
                String txHash = new String(Hex.encodeHex(hash));
                String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
                APIResult result = new APIResult();
                result.setData(txHash);
                result.setMessage(traninfo);
                result.setStatusCode(2000);
                String jsonString = JSON.toJSONString(result);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造调用定额条件比例支付的转入金额事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param value
     * @return
     */
    public static JSONObject CreateRateheightlockDepositRuleAsHash160(String fromPubkeyStr,String txHash160, long nonce, BigDecimal value){
        try {
            RateheightlockDeposit rateheightlockDeposit = new RateheightlockDeposit(value.longValue());
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = rateheightlockDeposit.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x08}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的调用定额条件比例支付的转入金额事务(160哈希)
     * @param fromPubkeyStr
     * @param prikeyStr
     * @param nonce
     * @return
     */
    public static JSONObject CreateRateheightlockDepositRuleForDeployAsHash160(String fromPubkeyStr,String prikeyStr,String txHashCreate160,long nonce, BigDecimal value) {
        APIResult apiResult = new APIResult();
        try {
            value = value.multiply(BigDecimal.valueOf(rate));
            if(value.equals("") || value == null){
                apiResult.setMessage("金额不能为空");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            if(value.compareTo(BigDecimal.ZERO) <= 0){
                apiResult.setMessage("必须为正整数");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            //判断是否有小数
            String string = value.stripTrailingZeros().toPlainString();
            int index = string.indexOf(".");
            index = index < 0 ? 0 : string.length() - index - 1;
            if(index > 0){
                apiResult.setMessage("金额输入错误");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            JSONObject jsonObject = CreateRateheightlockDepositRuleAsHash160(fromPubkeyStr, txHashCreate160,nonce,value );
            if (jsonObject.getInteger("code") == 5000) {
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造调用的定额条件比例支付的转出事务
     * @param fromPubkeyStr
     * @param txHash
     * @param nonce
     * @param deposithash
     * @param to
     * @return
     */
    public static JSONObject CreateRateheightlockWithdrawRule(String fromPubkeyStr, String txHash,long nonce, byte[] deposithash,byte[] to){
        try {
            RateheightlockWithdraw rateheightlockWithdraw = new RateheightlockWithdraw(deposithash,to);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] txHashGet = Hex.decodeHex(txHash.toCharArray());
            byte[] toPubkeyHash = RipemdUtility.ripemd160(txHashGet);
            //构造payload
            byte[] payload = rateheightlockWithdraw.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x09}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的调用定额条件比例支付的转出事务
     * @param fromPubkeyStr
     * @param txHashCreate
     * @param prikeyStr
     * @param nonce
     * @param deposithash
     * @param to
     * @return
     */
    public static JSONObject CreateRateheightlockWithdrawRuleForDeploy(String fromPubkeyStr,String txHashCreate,String prikeyStr,long nonce, String deposithash, String to) {
        APIResult apiResult = new APIResult();
        try {
            if(deposithash.equals("") || deposithash == null || to.equals("") || to == null){
                apiResult.setMessage("转入哈希或转出地址不能为空");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] deposithashByte = Hex.decodeHex(deposithash.toCharArray());
            byte[] toByte = Hex.decodeHex(to.toCharArray());
            JSONObject jsonObject = CreateRateheightlockWithdrawRule(fromPubkeyStr,txHashCreate, nonce, deposithashByte,toByte);
            if (jsonObject.getInteger("code") == 5000) {
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造调用的定额条件比例支付的转出事务(160哈希)
     * @param fromPubkeyStr
     * @param txHash160
     * @param nonce
     * @param deposithash
     * @param to
     * @return
     */
    public static JSONObject CreateRateheightlockWithdrawRuleAsHash160(String fromPubkeyStr, String txHash160,long nonce, byte[] deposithash,byte[] to){
        try {
            RateheightlockWithdraw rateheightlockWithdraw = new RateheightlockWithdraw(deposithash,to);
            //版本号
            byte[] version = new byte[1];
            version[0] = 0x01;
            //类型
            byte[] type = new byte[1];
            type[0] = 0X08;
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
            //接收者公钥哈希,填0
            byte[] toPubkeyHash = Hex.decodeHex(txHash160.toCharArray());
            //构造payload
            byte[] payload = rateheightlockWithdraw.RLPserialization();
            //长度
            byte[] payLoadLength = BigEndian.encodeUint32(payload.length + 1);
            byte[] allPayload = ByteUtil.merge(payLoadLength,new byte[]{0x09}, payload);
            byte[] RawTransaction = ByteUtil.merge(version, type, nonece, fromPubkeyHash, gasPrice, Amount, signull, toPubkeyHash, allPayload);
            String RawTransactionStr = new String(Hex.encodeHex(RawTransaction));
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("RawTransactionHex",RawTransactionStr);
            jsonObject.put("code",2000);
            return jsonObject;
        } catch (Exception e) {
            APIResult apiResult = new APIResult();
            apiResult.setMessage("exception error");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构造签名的调用定额条件比例支付的转出事务(160哈希)
     * @param fromPubkeyStr
     * @param txHashCreate160
     * @param prikeyStr
     * @param nonce
     * @param deposithash
     * @param to
     * @return
     */
    public static JSONObject CreateRateheightlockWithdrawRuleForDeployAsHash160(String fromPubkeyStr,String txHashCreate160,String prikeyStr,long nonce, String deposithash, String to) {
        APIResult apiResult = new APIResult();
        try {
            if(deposithash.equals("") || deposithash == null || to.equals("") || to == null){
                apiResult.setMessage("转入哈希或转出地址不能为空");
                apiResult.setStatusCode(5000);
                String jsonString = JSON.toJSONString(apiResult);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
            byte[] deposithashByte = Hex.decodeHex(deposithash.toCharArray());
            byte[] toByte = Hex.decodeHex(to.toCharArray());
            JSONObject jsonObject = CreateRateheightlockWithdrawRuleAsHash160(fromPubkeyStr,txHashCreate160, nonce, deposithashByte,toByte);
            if (jsonObject.getInteger("code") == 5000) {
                return jsonObject;
            }
            String RawTransactionHex = jsonObject.getString("RawTransactionHex");
            byte[] signRawBasicTransaction = Hex.decodeHex(signRawBasicTransaction(RawTransactionHex, prikeyStr).toCharArray());
            byte[] hash = ByteUtil.bytearraycopy(signRawBasicTransaction, 1, 32);
            String txHash = new String(Hex.encodeHex(hash));
            String traninfo = new String(Hex.encodeHex(signRawBasicTransaction));
            APIResult result = new APIResult();
            result.setData(txHash);
            result.setMessage(traninfo);
            result.setStatusCode(2000);
            String jsonString = JSON.toJSONString(result);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        } catch (Exception e) {
            apiResult.setMessage("事务构造有问题");
            apiResult.setStatusCode(5000);
            String jsonString = JSON.toJSONString(apiResult);
            JSONObject json = JSON.parseObject(jsonString);
            return json;
        }
    }

    /**
     * 构建判断是否签名事务
     *
     * @param RawTransactionHex
     * @param prikeyStr
     * @return
     */
    public static String signRawBasicTransactionAndIsSign(String RawTransactionHex, String prikeyStr,boolean isPutSign) {
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
            //payloadlen
            byte[] payloadlen = ByteUtil.bytearraycopy(RawTransaction, 142, 4);
            //payload
            byte[] payload = ByteUtil.bytearraycopy(RawTransaction, 146, (int) BigEndian.decodeUint32(payloadlen));
            byte[] RawTransactionNoSign = ByteUtil.merge(version, type, nonce, from, gasprice, amount, signo, to, payloadlen, payload);
            byte[] RawTransactionNoSig = ByteUtil.merge(version, type, nonce, from, gasprice, amount);
            //签名数据
            byte[] sig = new byte[64];
            if(isPutSign) {
                sig = new Ed25519PrivateKey(privkey).sign(RawTransactionNoSign);
            }
            byte[] transha = SHA3Utility.keccak256(ByteUtil.merge(RawTransactionNoSig, sig, to, payloadlen, payload));
            byte[] signRawBasicTransaction = ByteUtil.merge(version, transha, type, nonce, from, gasprice, amount, sig, to, payloadlen, payload);
            String signRawBasicTransactionHex = new String(Hex.encodeHex(signRawBasicTransaction));
            return signRawBasicTransactionHex;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 判断BigDecimal值是否有小数点或者超过long的最大值
     *
     * @param number
     * @return
     * @throws Exception
     */
    public static JSONObject isValidPositiveLong(BigDecimal number){
        if (new BigDecimal(number.longValue()).compareTo(number) != 0) {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("message", "offering must be an integer");
            jsonObject.put("data", "");
            jsonObject.put("code", "5000");
            return jsonObject;
        }
        if (number.compareTo(BigDecimal.ZERO) <= 0 || number.compareTo(MAXIMUM_LONG) > 0) {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("message", "offering must be a positive long number");
            jsonObject.put("data", "");
            jsonObject.put("code", "5000");
            return jsonObject;
        }
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("message", number);
        jsonObject.put("data", "");
        jsonObject.put("code", "2000");
        return jsonObject;
    }

//    /**
//     * 通过事务哈希得到合约地址
//     * @param txHash
//     * @return
//     * @throws Exception
//     */
//    public static String contractAddress(String txHash) throws Exception {
//        String contractAdd = RipemdUtility.HexStringRipemd160(Hex.decodeHex(txHash.toCharArray()));
//        byte[] r1 = Hex.decodeHex(contractAdd.toCharArray());
//        byte[] r2 = ByteUtil.prepend(r1, (byte) 0x00);
//        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
//        byte[] b4 = ByteUtil.bytearraycopy(r3, 0, 4);
//        byte[] b5 = ByteUtil.byteMerger(r2, b4);
//        String s6 = Base58Utility.encode(b5);
//        return "WR"+s6;
//    }

    /**
     * 事务哈希转公钥哈希
     * @param txHash
     * @return
     * @throws Exception
     */
    public static String txhashTopubhash(String txHash) throws Exception {
        String contractAdd = RipemdUtility.HexStringRipemd160(Hex.decodeHex(txHash.toCharArray()));
        return contractAdd;
    }


    /**
     * 获取Asset资产部署的详细信息
     * @param payload
     * @return
     */
    public static APIResult getAsset(byte[] payload) {
        APIResult apiResult = new APIResult();
        Asset asset = new Asset();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        asset = RLPElement.fromEncoded(payloadNew).as(Asset.class);
        if(asset == null){
            return APIResult.newFailResult(5000,"Invalid Asset Rules");
        }
        asset = asset.RLPdeserialization(payloadNew);
        String createuser = new String(Hex.encodeHex(asset.getCreateuser()));
        String owner = new String(Hex.encodeHex(asset.getOwner()));
        String info = "";
        if(asset.getInfo() != null){
            info = new String(Hex.encodeHex(asset.getInfo()));
        }
        JSONObject json = new JSONObject();
        json.put("code",asset.getCode());
        json.put("offering",asset.getOffering());
        json.put("totalamount",asset.getTotalamount());
        json.put("createuser",createuser);
        json.put("owner",owner);
        json.put("allowincrease",asset.getAllowincrease());
        json.put("info",info);
//        JSONObject json = (JSONObject) JSONObject.toJSON(asset);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取AssetChangeowner资产更换所有者的详细信息
     * @param payload
     * @return
     */
    public static APIResult getAssetIncreased(byte[] payload) {
        AssetIncreased assetIncreased = new AssetIncreased();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        assetIncreased = RLPElement.fromEncoded(payloadNew).as(AssetIncreased.class);
        if(assetIncreased == null){
            return APIResult.newFailResult(5000,"Invalid AssetIncreased Rules");
        }
        assetIncreased = assetIncreased.RLPdeserialization(payloadNew);
        JSONObject json = (JSONObject) JSONObject.toJSON(assetIncreased);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取AssetIncreased资产增发的详细信息
     * @param payload
     * @return
     */
    public static APIResult getAssetChangeowner(byte[] payload) {
        APIResult apiResult = new APIResult();
        AssetChangeowner assetChangeowner = new AssetChangeowner();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        assetChangeowner = RLPElement.fromEncoded(payloadNew).as(AssetChangeowner.class);
        if(assetChangeowner == null){
            return APIResult.newFailResult(5000,"Invalid AssetChangeowner Rules");
        }
        assetChangeowner = assetChangeowner.RLPdeserialization(payloadNew);
        String newowner = new String(Hex.encodeHex(assetChangeowner.getNewowner()));
        JSONObject json = new JSONObject();
        json.put("newowner",newowner);
//        JSONObject json = (JSONObject) JSONObject.toJSON(assetChangeowner);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取AssetTransfer的详细信息
     * @param payload
     * @return
     */
    public static APIResult getAssetTransfer(byte[] payload) {
        APIResult apiResult = new APIResult();
        AssetTransfer assetTransfer = new AssetTransfer();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        assetTransfer = RLPElement.fromEncoded(payloadNew).as(AssetTransfer.class);
        if(assetTransfer == null){
            return APIResult.newFailResult(5000,"Invalid AssetTransfer Rules");
        }
        assetTransfer = assetTransfer.RLPdeserialization(payloadNew);
        String from = new String(Hex.encodeHex(assetTransfer.getFrom()));
        String to = new String(Hex.encodeHex(assetTransfer.getTo()));
        JSONObject json = new JSONObject();
        json.put("from",from);
        json.put("to",to);
        json.put("value",assetTransfer.getValue());
//        JSONObject json = (JSONObject) JSONObject.toJSON(assetChangeowner);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取Multiple多签部署的详细信息
     * @param payload
     * @return
     */
    public static APIResult getMultiple(byte[] payload) {
        Multiple multiple = new Multiple();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        multiple = RLPElement.fromEncoded(payloadNew).as(Multiple.class);
        if(multiple == null){
            return APIResult.newFailResult(5000,"Invalid Multiple Rules");
        }
        multiple = multiple.RLPdeserialization(payloadNew);
        String assetHash = new String(Hex.encodeHex(multiple.getAssetHash()));
        List<String>  pubHashList = new ArrayList();
        for(int i = 0;i<multiple.getPubkeyHashList().size();i++){
           String a = new String(Hex.encodeHex(multiple.getPubkeyHashList().get(i)));
           pubHashList.add(a);
        }
        List<String>  signatures = new ArrayList();
        for(int i = 0;i<multiple.getSignatures().size();i++){
           String a = new String(Hex.encodeHex(multiple.getSignatures().get(i)));
           signatures.add(a);
        }
        List<String>  pubList = new ArrayList();
        for(int i = 0;i<multiple.getPubList().size();i++){
            String a = new String(Hex.encodeHex(multiple.getPubList().get(i)));
            pubList.add(a);
        }
        JSONObject json = new JSONObject();
        json.put("assetHash",assetHash);
        json.put("max",multiple.getMax());
        json.put("min",multiple.getMin());
        json.put("pubList",pubList);
        json.put("signatures",signatures);
        json.put("pubHashList",pubHashList);
//        JSONObject json = (JSONObject) JSONObject.toJSON(assetTransfer);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取MultTransfer的详细信息
     * @param payload
     * @return
     */
    public static APIResult getMultTransfer(byte[] payload) {
        MultTransfer multTransfer = new MultTransfer();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        multTransfer = RLPElement.fromEncoded(payloadNew).as(MultTransfer.class);
        if(multTransfer == null){
            return APIResult.newFailResult(5000,"Invalid MultTransfer Rules");
        }
        multTransfer = multTransfer.RLPdeserialization(payloadNew);
        String to = new String(Hex.encodeHex(multTransfer.getTo()));
        List<String>  publist = new ArrayList();
        for(int i = 0;i<multTransfer.getFrom().size();i++){
            String a = new String(Hex.encodeHex(multTransfer.getFrom().get(i)));
            publist.add(a);
        }
        List<String>  pubHashlist = new ArrayList();
        for(int i = 0;i<multTransfer.getPubkeyHashList().size();i++){
            String a = new String(Hex.encodeHex(multTransfer.getPubkeyHashList().get(i)));
            pubHashlist.add(a);
        }
        List<String>  listSignList = new ArrayList();
        for(int i = 0;i<multTransfer.getSignatures().size();i++){
            String a = new String(Hex.encodeHex(multTransfer.getSignatures().get(i)));
            listSignList.add(a);
        }
        JSONObject json = new JSONObject();
        json.put("origin",multTransfer.getOrigin());
        json.put("dest",multTransfer.getDest());
        json.put("from",publist);
        json.put("signaturesList",listSignList);
        json.put("to",to);
        json.put("value",multTransfer.getValue());
        json.put("pubHashList",pubHashlist);
//        JSONObject json = (JSONObject) JSONObject.toJSON(assetTransfer);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取Hashtimeblock的详细信息
     * @param payload
     * @return
     */
    public static APIResult getHashtimeblock(byte[] payload) {
        Hashtimeblock hashtimeblock = new Hashtimeblock();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        hashtimeblock = RLPElement.fromEncoded(payloadNew).as(Hashtimeblock.class);
        if(hashtimeblock == null){
            return APIResult.newFailResult(5000,"Invalid Hashtimeblock Rules");
        }
        hashtimeblock = hashtimeblock.RLPdeserialization(payloadNew);
        String assetHash = new String(Hex.encodeHex(hashtimeblock.getAssetHash()));
        String pubkeyHash = new String(Hex.encodeHex(hashtimeblock.getPubkeyHash()));
        JSONObject json = new JSONObject();
        json.put("assetHash",assetHash);
        json.put("pubkeyHash",pubkeyHash);
//        JSONObject json = (JSONObject) JSONObject.toJSON(assetTransfer);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得HashtimeblockGet的详细信息
     * @param payload
     * @return
     */
    public static APIResult getHashtimeblockGet(byte[] payload) {
        HashtimeblockGet hashtimeblockGet = new HashtimeblockGet();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        hashtimeblockGet = RLPElement.fromEncoded(payloadNew).as(HashtimeblockGet.class);
        if(hashtimeblockGet == null){
            return APIResult.newFailResult(5000,"Invalid HashtimeblockGet Rules");
        }
        hashtimeblockGet = hashtimeblockGet.RLPdeserialization(payloadNew);
        String transferhash = new String(Hex.encodeHex(hashtimeblockGet.getTransferhash()));
        JSONObject json = new JSONObject();
        json.put("transferhash",transferhash);
        json.put("origintext",hashtimeblockGet.getOrigintext());
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得HashtimeblockTransfer的详细信息
     * @param payload
     * @return
     */
    public static APIResult getHashtimeblockTransfer(byte[] payload) {
        HashtimeblockTransfer hashtimeblockTransfer = new HashtimeblockTransfer();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        hashtimeblockTransfer = RLPElement.fromEncoded(payloadNew).as(HashtimeblockTransfer.class);
        if(hashtimeblockTransfer == null){
            return APIResult.newFailResult(5000,"Invalid HashtimeblockTransfer Rules");
        }
        hashtimeblockTransfer = hashtimeblockTransfer.RLPdeserialization(payloadNew);
        String hashresult = new String(Hex.encodeHex(hashtimeblockTransfer.getHashresult()));
        JSONObject json = new JSONObject();
        json.put("value",hashtimeblockTransfer.getValue());
        json.put("hashresult",hashresult);
        json.put("timestamp",hashtimeblockTransfer.getTimestamp());
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获取Hashheightblock的详细信息
     * @param payload
     * @return
     */
    public static APIResult getHashheightblock(byte[] payload) {
        Hashheightblock hashheightblock = new Hashheightblock();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        hashheightblock = RLPElement.fromEncoded(payloadNew).as(Hashheightblock.class);
        if(hashheightblock == null){
            return APIResult.newFailResult(5000,"Invalid Hashheightblock Rules");
        }
        hashheightblock = hashheightblock.RLPdeserialization(payloadNew);
        String assetHash = new String(Hex.encodeHex(hashheightblock.getAssetHash()));
        String pubkeyHash = new String(Hex.encodeHex(hashheightblock.getPubkeyHash()));
        JSONObject json = new JSONObject();
        json.put("assetHash",assetHash);
        json.put("pubkeyHash",pubkeyHash);
//        JSONObject json = (JSONObject) JSONObject.toJSON(assetTransfer);
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得HashheightblockGet的详细信息
     * @param payload
     * @return
     */
    public static APIResult getHashheightblockGet(byte[] payload) {
        HashheightblockGet hashheightblockGet = new HashheightblockGet();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        hashheightblockGet = RLPElement.fromEncoded(payloadNew).as(HashheightblockGet.class);
        if(hashheightblockGet == null){
            return APIResult.newFailResult(5000,"Invalid HashheightblockGet Rules");
        }
        hashheightblockGet = hashheightblockGet.RLPdeserialization(payloadNew);
        String transferhash = new String(Hex.encodeHex(hashheightblockGet.getTransferhash()));
        JSONObject json = new JSONObject();
        json.put("transferhash",transferhash);
        json.put("origintext",hashheightblockGet.getOrigintext());
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得HashheightblockTransfer的详细信息
     * @param payload
     * @return
     */
    public static APIResult getHashheightblockTransfer(byte[] payload) {
        HashheightblockTransfer hashheightblockTransfer = new HashheightblockTransfer();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        hashheightblockTransfer = RLPElement.fromEncoded(payloadNew).as(HashheightblockTransfer.class);
        if(hashheightblockTransfer == null){
            return APIResult.newFailResult(5000,"Invalid HashheightblockTransfer Rules");
        }
        hashheightblockTransfer = hashheightblockTransfer.RLPdeserialization(payloadNew);
        String hashresult = new String(Hex.encodeHex(hashheightblockTransfer.getHashresult()));
        JSONObject json = new JSONObject();
        json.put("value",hashheightblockTransfer.getValue());
        json.put("hashresult",hashresult);
        json.put("height",hashheightblockTransfer.getHeight());
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得Rateheightlock的详细信息
     * @param payload
     * @return
     */
    public static APIResult getRateheightlock(byte[] payload) {
        Rateheightlock rateheightlock = new Rateheightlock();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        rateheightlock = RLPElement.fromEncoded(payloadNew).as(Rateheightlock.class);
        if(rateheightlock == null){
            return APIResult.newFailResult(5000,"Invalid Rateheightlock Rules");
        }
        rateheightlock = rateheightlock.RLPdeserialization(payloadNew);
        String assetHash = new String(Hex.encodeHex(rateheightlock.getAssetHash()));
        String dest = new String(Hex.encodeHex(rateheightlock.getDest()));
        JSONObject json = new JSONObject();
        json.put("assetHash",assetHash);
        json.put("onetimedepositmultiple",rateheightlock.getOnetimedepositmultiple());
        json.put("withdrawperiodheight",rateheightlock.getWithdrawperiodheight());
        json.put("withdrawrate",rateheightlock.getWithdrawrate());
        json.put("dest",dest);
        json.put("stateMap",rateheightlock.getStateMap().toString());
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得RateheightlockDeposit的详细信息
     * @param payload
     * @return
     */
    public static APIResult getRateheightlockDeposit(byte[] payload) {
        RateheightlockDeposit rateheightlockDeposit = new RateheightlockDeposit();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        rateheightlockDeposit = RLPElement.fromEncoded(payloadNew).as(RateheightlockDeposit.class);
        if(rateheightlockDeposit == null){
            return APIResult.newFailResult(5000,"Invalid RateheightlockDeposit Rules");
        }
        rateheightlockDeposit = rateheightlockDeposit.RLPdeserialization(payloadNew);
        JSONObject json = new JSONObject();
        json.put("value",rateheightlockDeposit.getValue());
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }

    /**
     * 获得RateheightlockWithdraw的详细信息
     * @param payload
     * @return
     */
    public static APIResult getRateheightlockWithdraw(byte[] payload) {
        RateheightlockWithdraw rateheightlockWithdraw = new RateheightlockWithdraw();
        APIResult apiResult = new APIResult();
        byte[] payloadNew = new byte[payload.length-1];
        for (int i = 1 ; i < payload.length ; i++){
            payloadNew[i-1] = payload[i];
        }
        rateheightlockWithdraw = RLPElement.fromEncoded(payloadNew).as(RateheightlockWithdraw.class);
        if(rateheightlockWithdraw == null){
            return APIResult.newFailResult(5000,"Invalid RateheightlockWithdraw Rules");
        }
        rateheightlockWithdraw = rateheightlockWithdraw.RLPdeserialization(payloadNew);
        JSONObject json = new JSONObject();
        json.put("deposithash",Hex.encodeHexString(rateheightlockWithdraw.getDeposithash()));
        json.put("to",Hex.encodeHexString(rateheightlockWithdraw.getTo()));
        String message = json.toString();
        apiResult.setMessage(message);
        apiResult.setStatusCode(2000);
        apiResult.setData("");
        return apiResult;
    }
}
