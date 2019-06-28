package com.example.wdc.keystore.wallet;

import com.example.wdc.ApiResult.APIResult;
import com.example.wdc.encoding.BigEndian;
import com.example.wdc.keystore.crypto.*;
import com.example.wdc.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.example.wdc.keystore.crypto.ed25519.Ed25519PublicKey;
import com.example.wdc.keystore.util.Base58Utility;
import com.example.wdc.keystore.util.ByteUtil;
import com.example.wdc.keystore.util.ByteUtils;
import com.example.wdc.keystore.util.Utils;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import net.sf.json.JSONObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.util.*;

import static com.example.wdc.ApiResult.APIResult.newFailResult;
import static com.example.wdc.ApiResult.APIResult.newSuccessResult;


public class WalletUtility {
    public String address;
    public Crypto crypto;
    private static final int saltLength = 32;
    private static final int ivLength = 16;
    private static final String defaultVersion = "1";
    private static final String t = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec";
    public static byte[] outscrip;
    private static final Long rate= 100000000L;



    public static Keystore unmarshal(String in) throws com.google.gson.JsonSyntaxException {
        Gson gson = new Gson();
        return gson.fromJson(in, Keystore.class);
    }
    public static String marshal(Keystore keystore){
        Gson gson = new Gson();
        return gson.toJson(keystore);
    }

    public static String fromPassword(String password) throws Exception{
        if (password.length()>20 || password.length()<8){
            throw new Exception("invalid password");
        }else {
            KeyPair keyPair = KeyPair.generateEd25519KeyPair();
            PublicKey publicKey = keyPair.getPublicKey();
            byte[] salt = new byte[saltLength];
            byte[] iv = new byte[ivLength];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(salt);
            ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, salt);
            AESManage aes = new AESManage(iv);

            byte[] derivedKey = argon2id.hash(password.getBytes());
            byte[] cipherPrivKey = aes.encrypt(derivedKey, keyPair.getPrivateKey().getBytes());
            byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                    derivedKey,cipherPrivKey
                    )
            );
            String b= Hex.encodeHexString(iv);

            Crypto crypto = new Crypto(
                    AESManage.cipher, Hex.encodeHexString(cipherPrivKey),
                    new Cipherparams(
                            Hex.encodeHexString(iv)
                    )
            );
            Kdfparams kdfparams = new Kdfparams(ArgonManage.memoryCost,ArgonManage.timeCost,ArgonManage.parallelism, Hex.encodeHexString(salt));

            com.example.wdc.keystore.account.Address ads = new com.example.wdc.keystore.account.Address(publicKey);
            ArgonManage params = new ArgonManage(salt);
            Keystore ks = new Keystore(ads.getAddress(), crypto, Utils.generateUUID(),
                    defaultVersion, Hex.encodeHexString(mac), argon2id.kdf(),kdfparams
            );
            APIResult as =  newSuccessResult(ks);
            String json = String.valueOf(JSONObject.fromObject(as));
            return  json;
        }
    }

    /*
        地址生成逻辑
       1.对公钥进行SHA3-256哈希，再进行RIPEMD-160哈希，
           得到哈希值r1
      2.在r1前面附加一个字节的版本号:0x01
           得到结果r2
      3.将r1进行两次SHA3-256计算，得到结果r3，
           获得r3的前面4个字节，称之为b4
      4.将b4附加在r2的后面，得到结果r5
      5.将r5进行base58编码，得到结果r6
      6.r6就是地址

   */
    public static String pubkeyHashToAddress(String r1Str) throws DecoderException {
        byte[] r1 = Hex.decodeHex(r1Str.toCharArray());
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = Base58Utility.encode(b5);
        APIResult ar =  newFailResult(0,s6);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

    /**
     *    1.将地址进行base58解码，得到结果r5
     *    2.将r5移除后后面4个字节得到r2
     *    3.将r2移除第1个字节:0x01得到r1(公钥哈希值)
     * @param address
     * @return
     */
    public static String addressToPubkeyHash(String address){
        byte[] r5 = Base58Utility.decode(address);
        byte[] r2 = ByteUtil.bytearraycopy(r5,0,21);
        byte[] r1 = ByteUtil.bytearraycopy(r2,1,20);
        String publickeyHash =  Hex.encodeHexString(r1);
        APIResult ar =  newFailResult(0,publickeyHash);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }


    public static byte[] decrypt(Keystore keystore,String password) throws Exception{
        if (!WalletUtility.verifyPassword(keystore,password)){
            throw new Exception("invalid password");
        }
        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex(keystore.kdfparams.salt.toCharArray()));
        byte[] derivedKey = argon2id.hash(password.getBytes());
        byte[] iv = Hex.decodeHex(keystore.crypto.cipherparams.iv.toCharArray());
        AESManage aes = new AESManage(iv);
        return aes.decrypt(derivedKey, Hex.decodeHex(keystore.crypto.ciphertext.toCharArray()));
    }

    public static boolean verifyPassword(Keystore keystore,String password) throws Exception{
        // 验证密码是否正确 计算 mac
        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex(keystore.kdfparams.salt.toCharArray()));
        byte[] derivedKey = argon2id.hash(password.getBytes());
        byte[] cipherPrivKey = Hex.decodeHex(keystore.crypto.ciphertext.toCharArray());
        byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                derivedKey,cipherPrivKey
                )
        );
        return Hex.encodeHexString(mac).equals(keystore.mac);
    }

    public static String prikeyToPubkey(String prikey) throws Exception {
        if(prikey.length() != 64 || new BigInteger(Hex.decodeHex(prikey.toCharArray())).compareTo(new BigInteger(ByteUtils.hexStringToBytes(t))) > 0){
            throw new Exception("Private key format error");
        }
        Ed25519PrivateKey eprik = new Ed25519PrivateKey(Hex.decodeHex(prikey.toCharArray()));
        Ed25519PublicKey epuk = eprik.generatePublicKey();
        String pubkey = Hex.encodeHexString(epuk.getEncoded());
        APIResult ar =  newFailResult(0,pubkey);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

    public static String keystoreToPubkey(Keystore ks,String password) throws Exception {
        String privateKey =  obtainPrikey(ks,password);
        String pubkey = prikeyToPubkey(privateKey);
        APIResult ar =  newFailResult(0,pubkey);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }
    /**
     * 地址有效性校验
     * @param address
     * @return
     */
    public static String verifyAddress(String address) throws DecoderException {
        byte[] r5 = Base58Utility.decode(address);
//        ResultSupport ar = new ResultSupport();
        if(!address.startsWith("1")){
//            jr.setStatusCode(-1);
            APIResult as =  newFailResult(-1,"地址开头字母有误");
            String str = String.valueOf(JSONObject.fromObject(as));
            return str;
        }
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(KeystoreAction.atph(address)));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] _b4 = ByteUtil.bytearraycopy(r5,r5.length-4,4);
        if(Arrays.equals(b4,_b4)){
            APIResult as =  newFailResult(0,"正确");
            String str = String.valueOf(JSONObject.fromObject(as));
            return str;
        }else {
            APIResult as =  newFailResult(-2,"地址格式错误");
            String str = String.valueOf(JSONObject.fromObject(as));
            return  str;
        }
    }
    public static String obtainPrikey(Keystore ks,String password) throws Exception {
        String privateKey =  Hex.encodeHexString(WalletUtility.decrypt(ks,password));
        APIResult ar =  newFailResult(0,privateKey);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

    public static String oldaddtonewadd(String address){
        byte[] pubhash = KeystoreAction.atph(address);
        String newAddress = KeystoreAction.phta(pubhash);
        APIResult ar =  newFailResult(0,newAddress);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

//    public static Map CreateRawTransaction(String address, BigDecimal amount, List<UTXO> in, BigDecimal fee) throws Exception {
//        //事务
//        byte[] version=new byte[1];
//        version[0]=0x01;
//        //发起WDC转账
//        byte[] type=new byte[1];
//        type[0]=0x01;
//        byte[] tran1=ByteUtil.merge(version,type);
//        //锁定时间戳
//        byte[] date= BigEndian.encodeUint32(0);//长度为4
//
//        byte[] nosigin = new byte[0];
//        byte[] _nosigin = new byte[0];
//        List<byte[]> indexList = new ArrayList<>();
//        List<byte[]> sha32List = new ArrayList<>();
//        List<byte[]> inlengthList = new ArrayList<>();
//
//        //输入
//        byte[] incount=new byte[1];
//        incount[0]= (byte) in.size();
//
//        Long inAmount = 0L;
//        for(int i=0;i<in.size();i++){
////            byte[] eachin = new byte[136];
//            //前置交易哈希值 32长度
////            byte[] sha32=SHA3Utility.sha3256(new byte[32]);
//            byte[] sha32=in.get(i).getHash();
//            sha32List.add(sha32);
//            //索引 4长度
////            byte[] indexex=ByteUtil.intToBytes(0);
//            byte[] index=ByteUtil.intToBytes(in.get(i).getIndex());
//
//            indexList.add(index);
//            //输入脚本长度 4长度
//            byte[] inlength=ByteUtil.intToBytes(96);
//            inlengthList.add(inlength);
//            //输入脚本
//            //本次交易事务数据
//            byte[] signull=new byte[64];
//
//            byte[] pubhash = KeystoreAction.atph(in.get(i).getAddress());
//            byte[] eachnosigin=ByteUtil.merge(incount,sha32,index,inlength,signull,pubhash);
//            _nosigin=ByteUtil.merge(nosigin,eachnosigin);
//            inAmount = inAmount+in.get(i).getAmount();
//        }
//        nosigin=ByteUtil.merge(incount,_nosigin);
//
//
//
//        //输出费用
//        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(rate));
//
//        //输出 1个62长度
//        byte[] outacount=new byte[1];
//        outacount[0]=1;
//        byte[] Amount=ByteUtil.longToBytes(bdAmount.longValue());
////        System.out.println(Amount.length);
//        //锁定脚本长度 4长度
//        byte[] outlength=ByteUtil.intToBytes(24);
//        //输出脚本 50长度
//        byte[] outf=new byte[2];
///*        int s=0xb9;
//        System.out.println("int:"+s);*/
//        outf[0]=(byte)0x76;
//        outf[1]= (byte) 0xa9;
//
////        byte[] pubkeysha=SHA3Utility.sha3256(epuk.getEncoded());
////        byte[] pubkey160= RipemdUtility.ripemd160(pubkeysha);
//        byte[] pubkey160 = KeystoreAction.atph(address);
//        byte[] outl=new byte[2];
//        outl[0]= (byte) 0x88;
//        outl[1]= (byte) 0xac;
//        outscrip=ByteUtil.merge(outf,pubkey160,outl);
//        //手续费
//        Long feeValue = fee.multiply(BigDecimal.valueOf(rate)).longValue();
//        byte[] outfullToOwner = new byte[0];
//        if(feeValue+bdAmount.longValue()<inAmount){//存在找零
//                outacount[0]=2;
//                //转出金额 8长度
//            byte[] AmountToOwner=ByteUtil.longToBytes(inAmount-(feeValue+bdAmount.longValue()));
////          System.out.println(Amount.length);
//            //锁定脚本长度 4长度
//            byte[] outlengthToOwner=ByteUtil.intToBytes(24);
//            //输出脚本 50长度
//            byte[] outfToOwner=new byte[2];
///*        int s=0xb9;
//        System.out.println("int:"+s);*/
//            outfToOwner[0]=(byte)0x76;
//            outfToOwner[1]= (byte) 0xa9;
//
////        byte[] pubkeysha=SHA3Utility.sha3256(epuk.getEncoded());
////        byte[] pubkey160= RipemdUtility.ripemd160(pubkeysha);
//            byte[] pubkey160ToOwner = KeystoreAction.atph(in.get(0).getAddress());
//            byte[] outlToOwner=new byte[2];
//            outlToOwner[0]= (byte) 0x88;
//            outlToOwner[1]= (byte) 0xac;
//            outscrip=ByteUtil.merge(outfToOwner,pubkey160ToOwner,outlToOwner);
//            outfullToOwner=ByteUtil.merge(Amount,outlength,outscrip);
//        }
//        byte[] _outfull=ByteUtil.merge(outacount,Amount,outlength,outscrip);
//        byte[] outfull= ByteUtil.merge(_outfull,outfullToOwner);
//        byte[] _localdate=ByteUtil.merge(tran1,nosigin,outfull,date);
//        byte[] localdate=new byte[0];
////        //签名原文数据
//        List<byte[]> indexdateList = new ArrayList<>();
//        for(int j=0;j<in.size();j++){
//            localdate=ByteUtil.merge(sha32List.get(j),indexList.get(j),outscrip);
//        }
//        byte[] indexdate = ByteUtil.merge(_localdate,localdate);
//        HashMap indexdateMap = new HashMap();
//        indexdateMap.put("indexdate",indexdate);
//        indexdateMap.put("indexList",indexList);
//        indexdateMap.put("sha32List",sha32List);
//        indexdateMap.put("inlengthList",inlengthList);
//        indexdateMap.put("outfull",outfull);
//        return  indexdateMap;
//    }
//
//    public static byte[] signRawBasicTransaction(String privateKey, Map indexdateMap) throws Exception {
//            byte[] indexdate = (byte[]) indexdateMap.get("indexdate");
//            byte[] outfull = (byte[]) indexdateMap.get("outfull");
//            List<byte[]> indexList = (List<byte[]>) indexdateMap.get("indexList");
//            List<byte[]> sha32List = (List<byte[]>) indexdateMap.get("sha32List");
//            List<byte[]> inlengthList = (List<byte[]>) indexdateMap.get("inlengthList");
//            byte[] privkey = Hex.decodeHex(privateKey.toCharArray());
//            byte[] pubkey = Hex.decodeHex(WalletUtility.prikeyToPubkey(privateKey).toCharArray());
//            byte[] incount = new byte[1];
//            incount[0] = (byte) indexList.size();
//            byte[] version=new byte[1];
//            version[0]=0x01;
//            //发起WDC转账
//            byte[] type=new byte[1];
//            type[0]=0x01;
//            byte[] date= BigEndian.encodeUint32(0);//长度为4
//            List<byte[]> tranfullList = new ArrayList<>();
//            //签名数据
//            byte[] sig = new Ed25519PrivateKey(privkey).sign(indexdate);
//
//            byte[] val = new byte[0];
//            for (int i=0;i< indexList.size();i++){
//                byte[] sha32 = sha32List.get(i);
//                byte[] index = indexList.get(i);
//                byte[] inlength = inlengthList.get(i);
//                val = ByteUtil.merge(val,sha32,index,inlength);
//            }
//            byte[] sigfull = ByteUtil.merge(sig, pubkey);
//
////            byte[] infull = ByteUtil.merge(incount, sha32, indexex, inlength, sigfull);
//            byte[] infull = ByteUtil.merge(incount, val, sigfull);
//
//            byte[] transha = SHA3Utility.sha3256(ByteUtil.merge(version, type, infull, outfull, date));
//
//            byte[] tranfull = ByteUtil.merge(version, transha, type, infull, outfull, date);
//
//        return tranfull;
//    }
//
//    public static byte[] SendToAddress(String address, BigDecimal amount, List<UTXO> in, BigDecimal fee, String privateKey) throws Exception {
//        Map indexdateMap = CreateRawTransaction(address,amount,in,fee);
//        byte[] tranfullList = signRawBasicTransaction(privateKey,indexdateMap);
//        return  tranfullList;
//    }

}