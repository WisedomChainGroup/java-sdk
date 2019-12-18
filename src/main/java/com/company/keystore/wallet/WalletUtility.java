package com.company.keystore.wallet;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.company.ApiResult.APIResult;
import com.company.keystore.crypto.*;
import com.company.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.company.keystore.crypto.ed25519.Ed25519PublicKey;
import com.company.keystore.util.Base58Utility;
import com.company.keystore.util.ByteUtil;
import com.company.keystore.util.ByteUtils;
import com.company.keystore.util.Utils;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomStringUtils;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class WalletUtility {

    public String address;
    public Crypto crypto;
    private static final int saltLength = 32;
    private static final int ivLength = 16;
    private static final String defaultVersion = "1";
    private static final String newVersion = "2";
    private static final String t = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec";
    private static final Long rate = 100000000L;


    public static Keystore unmarshal(String in) throws com.google.gson.JsonSyntaxException {
        Gson gson = new Gson();
        return gson.fromJson(in, Keystore.class);
    }

    public static String marshal(Keystore keystore) {
        Gson gson = new Gson();
        return gson.toJson(keystore);
    }

    //生成keystore
    public static JSON fromPassword(String password) {
        try {
            if (password.length() > 20 || password.length() < 8) {
                JSONObject json = JSON.parseObject("");
                return json;
            } else {
                KeyPair keyPair = KeyPair.generateEd25519KeyPair();
                PublicKey publicKey = keyPair.getPublicKey();
                byte[] salt = new byte[saltLength];
                byte[] iv = new byte[ivLength];
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);
                SecureRandom sr = new SecureRandom();
                sr.nextBytes(salt);
                ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex(Hex.encodeHexString(salt).toCharArray()));
                AESManage aes = new AESManage(iv);

                byte[] derivedKey = argon2id.hash(password.getBytes(),newVersion);
                byte[] cipherPrivKey = aes.encrypt(derivedKey, keyPair.getPrivateKey().getBytes());
                byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                        derivedKey, cipherPrivKey
                        )
                );
                Crypto crypto = new Crypto(
                        AESManage.cipher, new String(Hex.encodeHex(cipherPrivKey)),
                        new Cipherparams(
                                new String(Hex.encodeHex(iv))
                        )
                );
                Kdfparams kdfparams = new Kdfparams(ArgonManage.memoryCost, ArgonManage.timeCost, ArgonManage.parallelism, new String(Hex.encodeHex(salt)));

                com.company.keystore.account.Address ads = new com.company.keystore.account.Address(publicKey);
                ArgonManage params = new ArgonManage(salt);
                Keystore ks = new Keystore(ads.getAddress(), crypto, Utils.generateUUID(),
                        newVersion, new String(Hex.encodeHex(mac)), argon2id.kdf(), kdfparams
                );
                String jsonString = JSON.toJSONString(ks);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
        } catch (Exception e) {
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    /**
     * Generate keystore file
     */
    public static String generateKeystore(String password, String path) {
        try {
            String folderPath = path;
            if (folderPath == "" || folderPath == null) {
                folderPath = System.getProperty("user.dir") + File.separator + "Keystore";
            }

            File folder = new File(folderPath);
            if (!folder.exists()) {
                folder.mkdirs();
            }
            Keystore ks = JSON.parseObject(fromPassword(password).toJSONString(), Keystore.class);
            Crypto crypto = ks.crypto;
            Cipherparams cipherparams = crypto.cipherparams;
            String filePath = folderPath + "\\" + ks.address;
            File file = new File(filePath);
            file.createNewFile();
            //        JSONObject ksjson = JSONObject.fromObject(ks);
            String _ksjson = JSONObject.toJSONString(ks);
            JSONObject ksjson = JSON.parseObject(_ksjson);
            String _cryptojson = JSONObject.toJSONString(crypto);
            JSONObject cryptojson = JSON.parseObject(_cryptojson);
            String _cipherparamsjson = JSONObject.toJSONString(cipherparams);
            JSONObject cipherparamsjson = JSON.parseObject(_cipherparamsjson);
            cryptojson.put("cipherparams", cipherparamsjson.toString());
            ksjson.put("crypto", cryptojson.toString());
            String str = ksjson.toString();
            FileWriter fw = new FileWriter(file.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(str);
            bw.close();
            return ks.address;
        } catch (Exception e) {
            return "";
        }
    }



    /*
      3.将r1进行两次SHA3-256计算，得到结果r3，
           获得r3的前面4个字节，称之为b4
      4.将b4附加在r2的后面，得到结果r5
      5.将r5进行base58编码，得到结果r6
      6.r6就是地址

   */
    public static String pubkeyHashToAddress(String r1Str) {
        try {
            byte[] r1 = Hex.decodeHex(r1Str.toCharArray());
            byte[] r2 = ByteUtil.prepend(r1, (byte) 0x00);
            byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
            byte[] b4 = ByteUtil.bytearraycopy(r3, 0, 4);
            byte[] b5 = ByteUtil.byteMerger(r2, b4);
            String s6 = Base58Utility.encode(b5);
            return "WX" + s6;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 地址转公钥哈希
     * 1.将地址进行base58解码，得到结果r5
     * 2.将r5移除后后面4个字节得到r2
     * 3.将r2移除第1个字节:0x01得到r1(公钥哈希值)
     *
     * @param address
     * @return
     */
    public static String addressToPubkeyHash(String address) {
        try {
            byte[] r1 = KeystoreController.addressToPubkeyhashByte(address);
            String publickeyHash = new String(Hex.encodeHex(r1));
            return publickeyHash;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 通过keystore,密码获取地址
     * @param ksJson
     * @param password
     * @return
     */
    public static String keystoreToAddress(String ksJson, String password) {
        try {
            Keystore ks = JSON.parseObject(ksJson, Keystore.class);
            String address = ks.address;
            return address;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 通过keystore,密码获取公钥
     * @param ksJson
     * @param password
     * @return
     */
    public static String keystoreToPubkey(String ksJson, String password) {
        try {
            Keystore ks = JSON.parseObject(ksJson, Keystore.class);
            String privateKey = KeystoreController.obPrikey(ks, password);
            String pubkey = prikeyToPubkey(privateKey);
            return pubkey;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * 通过keystore,密码获取公钥hash
     * @param ksJson
     * @param password
     * @return
     */
    public static String keystoreToPubkeyHash(String ksJson, String password) {
        try {
            Keystore ks = JSON.parseObject(ksJson, Keystore.class);
            String privateKey = KeystoreController.obPrikey(ks, password);
            String pubkey = prikeyToPubkey(privateKey);
            byte[] pub256 = SHA3Utility.keccak256(Hex.decodeHex(pubkey.toCharArray()));
            byte[] r1 = RipemdUtility.ripemd160(pub256);
            String pubkeyHash = new String(Hex.encodeHex(r1));
            return pubkeyHash;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 通过keystore,密码获取私钥
     * @param ksJson
     * @param password
     * @return
     */
    public static String obtainPrikey(String ksJson, String password) {
        try {
            Keystore ks = JSON.parseObject(ksJson, Keystore.class);
            String privateKey =  new String(Hex.encodeHex(KeystoreController.decrypt(ks,password)));
            return  privateKey;
        }catch (Exception e){
            e.printStackTrace();
            return "";
        }
    }

    /**
     * 通过私钥获取公钥
     *
     * @param prikey
     * @return
     */
    public static String prikeyToPubkey(String prikey) {
        try {
            if (prikey.length() == 64) {
                if (new BigInteger(Hex.decodeHex(prikey.toCharArray())).compareTo(new BigInteger(ByteUtils.hexStringToBytes(t))) > 0) {
                    return "";
                }
            } else if (prikey.length() == 128) {
                if (new BigInteger(Hex.decodeHex(prikey.substring(0, 64).toCharArray())).compareTo(new BigInteger(ByteUtils.hexStringToBytes(t))) > 0) {
                    return "";
                }
            }
            Ed25519PrivateKey eprik = new Ed25519PrivateKey(Hex.decodeHex(prikey.toCharArray()));
            Ed25519PublicKey epuk = eprik.generatePublicKey();
            String pubkey = new String(Hex.encodeHex(epuk.getEncoded()));
            return pubkey;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * pubkeyStrToPubkeyHashStr
     *
     * @param pubkeyStr
     * @return
     */
    public static String pubkeyStrToPubkeyHashStr(String pubkeyStr) {
        try {
            byte[] pubkey = Hex.decodeHex(pubkeyStr.toCharArray());
            byte[] pub256 = SHA3Utility.keccak256(pubkey);
            byte[] r1 = RipemdUtility.ripemd160(pub256);
            String pubkeyHashStr = new String(Hex.encodeHex(r1));
            return pubkeyHashStr;
        } catch (Exception e) {
            return "";
        }
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    /**
     * 地址有效性校验
     * @param address
     * @return
     */
    public static int verifyAddress(String address) {
        try {
            if (!address.startsWith("1") && !address.startsWith("WX") && !address.startsWith("WR")) {
                return -1;
            }
            byte[] r5 = {};
            if (address.startsWith("1")) {
                r5 = Base58Utility.decode(address);
            } else {
                r5 = Base58Utility.decode(address.substring(2));
            }
            byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(KeystoreController.addressToPubkeyhashByte(address)));
            byte[] b4 = ByteUtil.bytearraycopy(r3, 0, 4);
            byte[] _b4 = ByteUtil.bytearraycopy(r5, r5.length - 4, 4);
            if (Arrays.equals(b4, _b4)) {
                return 0;
            } else {
                return -2;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return -2;
        }
    }

    public static JSON updateKeystoreVersion1to2(String keystoreJson, String password){
        try {
            String prikey = obtainPrikey(keystoreJson,password);
            Ed25519PrivateKey privateKey = new Ed25519PrivateKey(Hex.decodeHex(prikey.toCharArray()));
            Ed25519PublicKey publicKey = privateKey.generatePublicKey();
            if (password.length()>20 || password.length()<8){
                JSONObject json = JSON.parseObject("");;
                return json;
            }else {
                byte[] salt = new byte[saltLength];
                byte[] iv = new byte[ivLength];
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);
                SecureRandom sr = new SecureRandom();
                sr.nextBytes(salt);
                ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex(Hex.encodeHexString(salt).toCharArray()));
                AESManage aes = new AESManage(iv);

                byte[] derivedKey = argon2id.hash(password.getBytes(),newVersion);
                byte[] cipherPrivKey = aes.encrypt(derivedKey, privateKey.getEncoded());
                byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                        derivedKey, cipherPrivKey
                        )
                );
                Crypto crypto = new Crypto(
                        AESManage.cipher, new String(Hex.encodeHex(cipherPrivKey)),
                        new Cipherparams(
                                new String(Hex.encodeHex(iv))
                        )
                );
                Kdfparams kdfparams = new Kdfparams(ArgonManage.memoryCost, ArgonManage.timeCost, ArgonManage.parallelism, new String(Hex.encodeHex(salt)));

                com.company.keystore.account.Address ads = new com.company.keystore.account.Address(publicKey);
                ArgonManage params = new ArgonManage(salt);
                Keystore ks = new Keystore(ads.getAddress(), crypto, Utils.generateUUID(),
                        newVersion, new String(Hex.encodeHex(mac)), argon2id.kdf(), kdfparams
                );
                String jsonString = JSON.toJSONString(ks);
                JSONObject json = JSON.parseObject(jsonString);
                return json;
            }
        }catch (Exception e){
            JSONObject json = JSON.parseObject("");
            return json;
        }
    }

    public static void main(String[] args) throws DecoderException {
        String t = "{\"address\":\"WX1CRXnUJx9Tq4ZpNkkueeKFxCbYg1E4uTCt\",\"kdfparams\":{\"salt\":\"234b39aee82b3f1a6b0d8ca82f55f7cdfe68aaf7bdf81ab409845131fb0cbded\",\"memoryCost\":20480,\"parallelism\":2,\"timeCost\":4},\"id\":\"2503441f-dbaa-4a08-870b-6a10e517293e\",\"kdf\":\"argon2id\",\"version\":\"2\",\"mac\":\"68fa5fb450e1d25e9f85f860c47736c0f4235e640bbd5704b72468a2c3882922\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"ciphertext\":\"154e1ecf3a4ca92563804ae19d524f13d32d394473d0d0ce9ab2316d4eefb3e9\",\"cipherparams\":{\"iv\":\"150f6026ea457d6c65104c5a6d4307a5\"}}}";
//        String t = "{\"address\":\"1CRXnUJx9Tq4ZpNkkueeKFxCbYg1E4uTCt\",\"kdfparams\":{\"salt\":\"e8b8ae8daea9873a478dca5e6125b937c986df116d0f6d124f981e865ddeec86\",\"memoryCost\":20480,\"parallelism\":2,\"timeCost\":4},\"id\":\"e3354109-50ac-4a6e-97cc-3aa87f85f1bf\",\"kdf\":\"argon2id\",\"version\":\"1\",\"mac\":\"b9cea49dbf53eed3b7922310d735b6245841284bd1dedca0510734b3eb3a51d3\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"ciphertext\":\"d1d957207037169b318618051a4985fb44f0ee4d21d1af42612c0dcb8ccb3d4e\",\"cipherparams\":{\"iv\":\"a377a16b806d4ed3910ab15b67b3661a\"}}}";
//        System.out.println(obtainPrikey(t,"test123456"));
//        System.out.println(prikeyToPubkey("014c2f41f7c267c3c6fc41fa652b34e8b7f65861e839061d9ad9b8b00b1cd39c"));
//        System.out.println(prikeyToPubkey("01ddaccaa550531531c98810220cdb7c003de4ff70ea8d693d3d026f1992c6a4"));
//        System.out.println(updateKeystoreVersion1to2(t,"test123456"));

        String salt = "3b663f3f3f3f3f3f653f501e3f3f3f3f4e3f3f38673f5220783f3f3f173f3f3f";

        String e8 = "e8b8ae8daea9873a478dca5e6125b937c986df116d0f6d124f981e865ddeec86";

        String _3f = "3f293f3f3f3f3f3f3f3f3f4a3f073f3f744a0c6f3f4a00773f19743f143f3f43";

        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, _3f.getBytes(StandardCharsets.US_ASCII));
        for(byte b: "e8b8ae8daea9873a478dca5e6125b937c986df116d0f6d124f981e865ddeec86".getBytes(StandardCharsets.US_ASCII)){
//            System.out.println(0xff & b);
        }
        byte[] derivedKey = argon2id.hash("test123456".getBytes(StandardCharsets.US_ASCII),newVersion);
        System.out.println(Hex.encodeHexString(derivedKey));
//
//        ArgonManage argon2id2 = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex("3b663f3f3f3f3f3f653f501e3f3f3f3f4e3f3f38673f5220783f3f3f173f3f3f".toCharArray()));
//        byte[] derivedKey2 = argon2id2.hash("test123456".getBytes(),newVersion);
//        System.out.println(Hex.encodeHexString(derivedKey2));

//System.out.println(fromPassword("test123456"));

//        String s = "{\"address\":\"WX19zujA9ZZrXaFBHJtFRSWkTvHyGxWX94Fm\",\"kdfparams\":{\"salt\":\"3b663f3f3f3f3f3f653f501e3f3f3f3f4e3f3f38673f5220783f3f3f173f3f3f\",\"memoryCost\":20480,\"parallelism\":2,\"timeCost\":4},\"id\":\"a713f151-4ec7-4f08-ad1d-4208df0a4c51\",\"kdf\":\"argon2id\",\"version\":\"2\",\"mac\":\"33c787fff89007d223de6cd0fbbb5e352e71abbc4822a28acae06012ac956712\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"ciphertext\":\"ea9ca7b7865b1db021513c6957aae2d27af9f878c349960f54b7c4e20bd74a90\",\"cipherparams\":{\"iv\":\"e6b860d069dfb0883219cd9704769669\"}}}\n";
//        String s = "{\"address\":\"WX19zujA9ZZrXaFBHJtFRSWkTvHyGxWX94Fm\",\"kdfparams\":{\"salt\":\"000a453f5f60203f0e3f3f125d07593f7d3f3f084c7e373f3f3f745e161e3f41\",\"memoryCost\":20480,\"parallelism\":2,\"timeCost\":4},\"id\":\"1a7ecd2b-7775-41a1-94d1-a22ccd4422c4\",\"kdf\":\"argon2id\",\"version\":\"2\",\"mac\":\"f62d4b2a2937c652dce2201f012ea305e9ed069aa8f0a0f12dddbd031e093c88\",\"crypto\":{\"cipher\":\"aes-256-ctr\",\"ciphertext\":\"5503be55c62f6abf5b129c315f83fd530c8ede659378a2471854eb18ae6e1042\",\"cipherparams\":{\"iv\":\"4fabdeec94355ff8d879b29435eaaee3\"}}}\n";
//        System.out.println(updateKeystoreVersion1to2(s,"test123456"));
//        System.out.println(obtainPrikey(s,"test123456"));
        //a2fd0c910cda464a3bdd0591038597920a85adfd7cd38c78978df94932145f4f

        String json = "{\n" +
                "  \"address\": \"1CRXnUJx9Tq4ZpNkkueeKFxCbYg1E4uTCt\",\n" +
                "  \"kdfparams\": {\n" +
                "    \"salt\": \"e8b8ae8daea9873a478dca5e6125b937c986df116d0f6d124f981e865ddeec86\",\n" +
                "    \"memoryCost\": 20480,\n" +
                "    \"parallelism\": 2,\n" +
                "    \"timeCost\": 4\n" +
                "  },\n" +
                "  \"id\": \"e3354109-50ac-4a6e-97cc-3aa87f85f1bf\",\n" +
                "  \"kdf\": \"argon2id\",\n" +
                "  \"version\": \"1\",\n" +
                "  \"mac\": \"b9cea49dbf53eed3b7922310d735b6245841284bd1dedca0510734b3eb3a51d3\",\n" +
                "  \"crypto\": {\n" +
                "    \"cipher\": \"aes-256-ctr\",\n" +
                "    \"ciphertext\": \"d1d957207037169b318618051a4985fb44f0ee4d21d1af42612c0dcb8ccb3d4e\",\n" +
                "    \"cipherparams\": {\n" +
                "      \"iv\": \"a377a16b806d4ed3910ab15b67b3661a\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        System.out.println(updateKeystoreVersion1to2(json, "test123456"));

    }
}