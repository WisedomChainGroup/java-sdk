package com.sdk.wdc.keystore.wallet;

import com.sdk.wdc.ApiResult.APIResult;
import com.sdk.wdc.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.sdk.wdc.keystore.crypto.ed25519.Ed25519PublicKey;
import com.sdk.wdc.keystore.util.Base58Utility;
import com.sdk.wdc.keystore.util.ByteUtil;
import com.sdk.wdc.keystore.util.ByteUtils;
import com.sdk.wdc.keystore.util.Utils;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import com.sdk.wdc.keystore.account.Address;
import com.sdk.wdc.keystore.crypto.*;
import net.sf.json.JSONObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;


import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.sdk.wdc.ApiResult.APIResult.newFailResult;


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

    //生成keystore
    public static JSONObject fromPassword(String password) throws Exception{
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

            Address ads = new Address(publicKey);
            ArgonManage params = new ArgonManage(salt);
            Keystore ks = new Keystore(ads.getAddress(), crypto, Utils.generateUUID(),
                    defaultVersion, Hex.encodeHexString(mac), argon2id.kdf(),kdfparams
            );
            JSONObject json = JSONObject.fromObject(ks);
            return  json;
        }
    }

    /**
     * Generate keystore file
     */
    public static String generateKeystore(String password,String path) throws Exception{
        String folderPath = path;
        if (folderPath == "" || folderPath == null){
            folderPath = System.getProperty("user.dir")+File.separator+"wisdom_keystore";
        }

        File folder = new File(folderPath);
        if (!folder.exists()) {
            folder.mkdirs();
        }
        Keystore ks = KeystoreAction.fromPassword(password);
        Crypto crypto = ks.crypto;
        Cipherparams cipherparams = crypto.cipherparams;
        String filePath=folderPath+"\\"+ks.address;
        File file = new File(filePath);
        file.createNewFile();
        JSONObject ksjson = JSONObject.fromObject(ks);
        JSONObject cryptojson = JSONObject.fromObject(crypto);
        JSONObject cipherparamsjson = JSONObject.fromObject(cipherparams);
        cryptojson.put("cipherparams",cipherparamsjson.toString());
        ksjson.put("crypto", cryptojson.toString());
        String str = ksjson.toString();
        FileWriter fw = new FileWriter(file.getAbsoluteFile());
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(str);
        bw.close();
        return  ks.address;
    }

    /**
     * 修改keystore密码
     * @param keystoreJson
     * @param password
     * @param newPassword
     * @return
     * @throws Exception
     */
    public static JSONObject modifyPassword(String keystoreJson, String password,String newPassword) throws Exception{
        String prikey = obtainPrikey(keystoreJson,password);
        Ed25519PrivateKey privateKey = new Ed25519PrivateKey(Hex.decodeHex(prikey.toCharArray()));
        Ed25519PublicKey publicKey = privateKey.generatePublicKey();
        if (password.length()>20 || password.length()<8){
            throw new Exception("invalid password");
        }else {
            byte[] salt = new byte[saltLength];
            byte[] iv = new byte[ivLength];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(salt);
            ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, salt);
            AESManage aes = new AESManage(iv);

            byte[] derivedKey = argon2id.hash(newPassword.getBytes());
            byte[] cipherPrivKey = aes.encrypt(derivedKey, privateKey.getEncoded());
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

            Address ads = new Address(publicKey);
            ArgonManage params = new ArgonManage(salt);
            Keystore ks = new Keystore(ads.getAddress(), crypto, Utils.generateUUID(),
                    defaultVersion, Hex.encodeHexString(mac), argon2id.kdf(),kdfparams
            );
            JSONObject json = JSONObject.fromObject(ks);
            return  json;
        }
    }

    /**
     * 导入KeyStore
     * @param ksJson
     * @param path
     * @return
     * @throws Exception
     */
    public static String importKeystore(String ksJson,String path) throws Exception{
        JSONObject jsonObject = JSONObject.fromObject(ksJson);
        Keystore ks = (Keystore) JSONObject.toBean(jsonObject,Keystore.class);
        String folderPath = path;
        if (folderPath == "" || folderPath == null){
            folderPath = System.getProperty("user.dir")+File.separator+"Keystore";
        }

        File folder = new File(folderPath);
        if (!folder.exists()) {
            folder.mkdirs();
        }
        Crypto crypto = ks.crypto;
        Cipherparams cipherparams = crypto.cipherparams;
        String filePath=folderPath+"\\"+ks.address;
        File file = new File(filePath);
        file.createNewFile();
        JSONObject ksjson = JSONObject.fromObject(ks);
        JSONObject cryptojson = JSONObject.fromObject(crypto);
        JSONObject cipherparamsjson = JSONObject.fromObject(cipherparams);
        cryptojson.put("cipherparams",cipherparamsjson.toString());
        ksjson.put("crypto", cryptojson.toString());
        String str = ksjson.toString();
        FileWriter fw = new FileWriter(file.getAbsoluteFile());
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(str);
        bw.close();
        return  ks.address;
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
        return  s6;
    }

    /**
     *     地址转公钥哈希
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
        return  publickeyHash;
    }

    /**
     * 通过keystore,密码获取地址
     * @param ksJson
     * @param password
     * @return
     * @throws Exception
     */
    public static String keystoreToAddress(String ksJson,String password) throws Exception {
        JSONObject jsonObject = JSONObject.fromObject(ksJson);
        Keystore ks = (Keystore) JSONObject.toBean(jsonObject,Keystore.class);
        String address = ks.address;
        return  address;
    }

    /**
     * 通过keystore,密码获取公钥
     * @param ksJson
     * @param password
     * @return
     * @throws Exception
     */
    public static String keystoreToPubkey(String ksJson,String password) throws Exception {
        JSONObject jsonObject = JSONObject.fromObject(ksJson);
        Keystore ks = (Keystore) JSONObject.toBean(jsonObject,Keystore.class);
        String privateKey =  KeystoreAction.obPrikey(ks,password);
        String pubkey = KeystoreAction.prikeyToPubkey(privateKey);
        return  pubkey;
    }

    /**
     * 通过keystore,密码获取公钥hash
     * @param ksJson
     * @param password
     * @return
     * @throws Exception
     */
    public static String keystoreToPubkeyHash(String ksJson,String password) throws Exception {
        JSONObject jsonObject = JSONObject.fromObject(ksJson);
        Keystore ks = (Keystore) JSONObject.toBean(jsonObject,Keystore.class);
        String privateKey =  KeystoreAction.obPrikey(ks,password);
        String pubkey = KeystoreAction.prikeyToPubkey(privateKey);
        byte[] pub256 = SHA3Utility.keccak256(Hex.decodeHex(pubkey.toCharArray()));
        byte[] r1 = RipemdUtility.ripemd160(pub256);
        String pubkeyHash = Hex.encodeHexString(r1);
        return  pubkeyHash;
    }

    /**
     * 通过keystore,密码获取私钥
     * @param ksJson
     * @param password
     * @return
     * @throws Exception
     */
    public static String obtainPrikey(String ksJson, String password) throws Exception {
        JSONObject jsonObject = JSONObject.fromObject(ksJson);
        Keystore ks = (Keystore) JSONObject.toBean(jsonObject,Keystore.class);
        String privateKey =  Hex.encodeHexString(KeystoreAction.decrypt(ks,password));
        return  privateKey;
    }

    /**
     * 通过私钥获取公钥
     * @param prikey
     * @return
     * @throws Exception
     */
    public static String prikeyToPubkey(String prikey) throws Exception {
        if(prikey.length() != 64 || new BigInteger(Hex.decodeHex(prikey.toCharArray())).compareTo(new BigInteger(ByteUtils.hexStringToBytes(t))) > 0){
            throw new Exception("Private key format error");
        }
        Ed25519PrivateKey eprik = new Ed25519PrivateKey(Hex.decodeHex(prikey.toCharArray()));
        Ed25519PublicKey epuk = eprik.generatePublicKey();
        String pubkey = Hex.encodeHexString(epuk.getEncoded());
        return  pubkey;
    }
    /**
     * 地址有效性校验
     * @param address
     * @return
     */
    public static int verifyAddress(String address) throws DecoderException {
        byte[] r5 = Base58Utility.decode(address);
//        ResultSupport ar = new ResultSupport();
        if(!address.startsWith("1")){
//            jr.setStatusCode(-1);
            return  -1;
        }
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(KeystoreAction.atph(address)));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] _b4 = ByteUtil.bytearraycopy(r5,r5.length-4,4);
        if(Arrays.equals(b4,_b4)){
            return  0;
        }else {
            return  -2;
        }
    }

    /**
     * 获取余额
     * @param address
     * @return
     */
    public static JSONObject getBalance(String address){
        APIResult ar = new APIResult();
        JSONObject result = JSONObject.fromObject(ar);
        return result;
    }




//    public static void doPost(String url,String paramName,String paramValue) throws IOException {
//        String praiseUrl = url; // 澎湃新闻评论点赞url
//        HttpClient client = new HttpClient();
//        PostMethod postMethod = new PostMethod(praiseUrl);
//        // 必须设置下面这个Header
//        postMethod.addRequestHeader("Content-Type", "application/octet-stream;charset=utf-8");
//        postMethod.addRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36");
//        postMethod.addParameter(paramName, paramValue); // 评论的id，抓包获得
////        PostMethod postMethod = new PostMethod(praiseUrl);
////        postMethod.addRequestHeader("Content-Type", "application/octet-stream;charset=utf-8");
////        postMethod.setRequestEntity(new ByteArrayRequestEntity(paramValue ));
////        client.executeMethod(postMethod);
//
//        try {
//            int code = client.executeMethod(postMethod);
//            if (code == 200) {
//                String res = postMethod.getResponseBodyAsString();
//                System.out.println(res);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    /**
//     * 发送事务
//     * @param transaction
//     */
//    public static void sendTransaction(byte[] transaction) throws IOException {
//        HatchModel.Hatch.Builder transactions = HatchModel.Hatch.newBuilder();
//        transactions.setInfo(ByteString.copyFrom(transaction));
////        HatchModel.Hatch tra = transactions.build();
//        byte[] paramValue = transactions.build().toByteArray();
////        String paramValue = Hex.encodeHexString(transactions.build().toByteArray());
//        String u ="http://192.168.0.101:19585/sendTransaction";
//        String paramName = "traninfo";
//        doPost(u,paramName,paramValue);
//    }





    public static void main(String[] args) throws Exception{
//                String json = "{\n" +
//                "\t\"address\": \"19RV9M4oCuXcrm79ykSk2CyWGxFyufRk3x\",\n" +
//                "\t\"crypto\": {\n" +
//                "\t\t\"cipher\": \"aes-256-ctr\",\n" +
//                "\t\t\"cipherparams\": {\n" +
//                "\t\t\t\"iv\": \"3c4b696f83ee5e604cc2c33523adac9b\"\n" +
//                "\t\t},\n" +
//                "\t\t\"ciphertext\": \"70065eb92dd48a6e4b646f6aa101231b8438287a5691083a08c535cc91476b3a\"\n" +
//                "\t},\n" +
//                "\t\"id\": \"5579022c-23ea-43d8-b49f-2e7802e7025e\",\n" +
//                "\t\"kdf\": \"argon2id\",\n" +
//                "\t\"kdfparams\": {\n" +
//                "\t\t\"memoryCost\": 20480,\n" +
//                "\t\t\"parallelism\": 2,\n" +
//                "\t\t\"salt\": \"2363b4f8522cd70e266549de454c4c63eb1d6aa48af755a45e6eacc1fbbe26f5\",\n" +
//                "\t\t\"timeCost\": 4\n" +
//                "\t},\n" +
//                "\t\"mac\": \"7391cdea77c1ea9fb6f0803a0a18db70431de622ee591042606e30e98f8ad92f\",\n" +
//                "\t\"version\": \"1\"\n" +
//                "}";
//                System.out.println(obtainPrikey(json,"111111111"));

        //转账事务
//        byte[] transaction  = CreatesignBasicTransaction("21676fc8ec5ad32650149022ed7cf46d544699c8dd4873716e292a9edea5a3c3","4ee8cf6beef7cb91a6ec2db408c4b98f0dc5808e",BigDecimal.valueOf(0.1),BigDecimal.valueOf(0.0003),"80d59014f588f817ab5597b475722df3e2b4fc97deadb96aa07af53f1330e1ab");
        //孵化事务
//        byte[] transaction  = CreatesignHatchTransaction("21676fc8ec5ad32650149022ed7cf46d544699c8dd4873716e292a9edea5a3c3","4ee8cf6beef7cb91a6ec2db408c4b98f0dc5808e",BigDecimal.valueOf(300),BigDecimal.valueOf(0.0003),"80d59014f588f817ab5597b475722df3e2b4fc97deadb96aa07af53f1330e1ab","a8041b5b7e47176b73d92455ecb7af5db032f935",120);
        //收益事务
//        byte[] transaction  =CreatesignHatchProfitTransaction("21676fc8ec5ad32650149022ed7cf46d544699c8dd4873716e292a9edea5a3c3","4ee8cf6beef7cb91a6ec2db408c4b98f0dc5808e",BigDecimal.valueOf(0.012813000),BigDecimal.valueOf(0.0003),"80d59014f588f817ab5597b475722df3e2b4fc97deadb96aa07af53f1330e1ab","80d59014f588f817ab5597b475722df3e2b4fc97deadb96aa07af53f1330e1ab");
        //分享事务
//        byte[] transaction  =CreatesignShareHatchProfitTransaction("21676fc8ec5ad32650149022ed7cf46d544699c8dd4873716e292a9edea5a3c3","4ee8cf6beef7cb91a6ec2db408c4b98f0dc5808e",BigDecimal.valueOf(0.012813000),BigDecimal.valueOf(0.0003),"80d59014f588f817ab5597b475722df3e2b4fc97deadb96aa07af53f1330e1ab","80d59014f588f817ab5597b475722df3e2b4fc97deadb96aa07af53f1330e1ab");
//        String ae = Hex.encodeHexString(transaction);
//        String base58 = Base58Utility.encode(transaction);
////        System.out.println(1111);
//        sendTransac("http://192.168.0.101:19585/sendTransaction","traninfo="+ae);


        generateKeystore("111111111","");
//        String json = "{\"address\":\"14FK7qoUCwFfWhyxRNZ2raTTpdxash5X5F\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"cipherparams\":{\"iv\":\"217641cd61819ad69308d112bf5e0d45\"},\"ciphertext\":\"ff14986b43032681133286f7bda525391620b491f0c515c4a0c81785eec5dd4e\"},\"id\":\"b94acf2c-8cd2-438a-81db-bbe6a054591d\",\"kdf\":\"argon2id\",\"kdfparams\":{\"memoryCost\":20480,\"parallelism\":2,\"salt\":\"bddcd55fda732028c04f58fe606393cd462ea8f97734974e5e97240bead90f24\",\"timeCost\":4},\"mac\":\"d83b224cc5600283b6a7b4707ee7a33a2bae6744354b4efb037852ebbbe8b766\",\"version\":\"1\"}";
//        String j2 = "{\"address\":\"14FK7qoUCwFfWhyxRNZ2raTTpdxash5X5F\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"cipherparams\":{\"iv\":\"10f7e5c71469e5d1113a65fdc8ad7904\"},\"ciphertext\":\"bced792a2d4c08023ab08cce040d26548d14e3a95ba0cb80b63fab37e41243b3\"},\"id\":\"1210a3de-76b9-4dff-a931-0cac40696eaa\",\"kdf\":\"argon2id\",\"kdfparams\":{\"memoryCost\":20480,\"parallelism\":2,\"salt\":\"31c3a1abe88b2d548c6134ed6c898a5d3ca7364b076a0aefe7be36677a3b829a\",\"timeCost\":4},\"mac\":\"6d7baba7496d54aa78a2e2cb6180ccf3cfee35f7fe28ed915063b141663d8de1\",\"version\":\"1\"}";
//        System.out.println(json.equals(j2));
//        System.out.println(obtainPrikey(j2,"66666666"));
//        String pri = "d20169b247ded0188a5e2ce39e4f13a6c9990c22ce953216900cd2c0c98f238e";
//        modifyPassword(json,"111111111","13245678");

//        String json = "{\"address\":\"14FK7qoUCwFfWhyxRNZ2raTTpdxash5X5F\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"cipherparams\":{\"iv\":\"217641cd61819ad69308d112bf5e0d45\"},\"ciphertext\":\"ff14986b43032681133286f7bda525391620b491f0c515c4a0c81785eec5dd4e\"},\"id\":\"b94acf2c-8cd2-438a-81db-bbe6a054591d\",\"kdf\":\"argon2id\",\"kdfparams\":{\"memoryCost\":20480,\"parallelism\":2,\"salt\":\"bddcd55fda732028c04f58fe606393cd462ea8f97734974e5e97240bead90f24\",\"timeCost\":4},\"mac\":\"d83b224cc5600283b6a7b4707ee7a33a2bae6744354b4efb037852ebbbe8b766\",\"version\":\"1\"}";
//        String json2= "{\"address\":\"14FK7qoUCwFfWhyxRNZ2raTTpdxash5X5F\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"cipherparams\":{\"iv\":\"f7c7955c264fab611448a5a7547c19f5\"},\"ciphertext\":\"3a79082e5e7e7cfb104d343f15b6b89cb2f9ea2798295434dc49d199a7d87068\"},\"id\":\"b61c5f1a-8614-4000-b3a4-535da6761cba\",\"kdf\":\"argon2id\",\"kdfparams\":{\"memoryCost\":20480,\"parallelism\":2,\"salt\":\"88f5f11ad699b928cbb730cfeab464840e185b81204dfca0ead2f8c5a580fe62\",\"timeCost\":4},\"mac\":\"f37fab8200aa7bf60655ea24cdd0639ebf2421e5f66950f96d657668e6828aa2\",\"version\":\"1\"}";
//        System.out.println(modifyPassword(json,"111111111","77777777"));
//
////        System.out.println(importKeystore(json2,""));
////        APIResult a = new APIResult();
////        a.setMessage("1");
////        JSONObject json  = JSONObject.fromObject(a);
//        System.out.println(json);
//
//
//        System.out.println(pubkeyHashToAddress("00e9dfbeb7887ca5a16859c162d50457be2910f0"));
    }


}