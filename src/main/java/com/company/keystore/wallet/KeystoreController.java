package com.company.keystore.wallet;

import com.company.keystore.crypto.*;
import com.company.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.company.keystore.crypto.ed25519.Ed25519PublicKey;
import com.company.keystore.util.Base58Utility;
import com.company.keystore.util.ByteUtil;
import com.company.keystore.util.ByteUtils;
import com.company.keystore.util.Utils;
import com.google.common.primitives.Bytes;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class KeystoreController {
    private static final String t = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec";
    public String address;
    public Crypto crypto;
    private static final int saltLength = 32;
    private static final int ivLength = 16;
    private static final String defaultVersion = "1";
    private static final String newVersion = "1";
    private SecureRandom random;


    public static String pta(byte[] pubkey){
        byte[] pub256 = SHA3Utility.keccak256(pubkey);
        byte[] r1 = RipemdUtility.ripemd160(pub256);
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = "WX"+Base58Utility.encode(b5);
        return  s6;
    }

    public static byte[] addressToPubkeyhashByte(String address){
        byte[] r5 = {};
        if(address.startsWith("1")){
            r5 = Base58Utility.decode(address);
        }else{
            r5 = Base58Utility.decode(address.substring(2));
        }
        byte[] r2 = ByteUtil.bytearraycopy(r5,0,21);
        byte[] r1 = ByteUtil.bytearraycopy(r2,1,20);
        return  r1;
    }


    public static byte[] decrypt(Keystore keystore,String password) throws Exception{
        if (!verifyPassword(keystore,password)){
            throw new Exception("invalid password");
        }
        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, keystore.kdfparams.salt, keystore.version);
        byte[] derivedKey = argon2id.hash(password.getBytes());
        byte[] iv = Hex.decodeHex(keystore.crypto.cipherparams.iv.toCharArray());
        AESManage aes = new AESManage(iv);
        return aes.decrypt(derivedKey, Hex.decodeHex(keystore.crypto.ciphertext.toCharArray()));
    }

    public static boolean verifyPassword(Keystore keystore,String password) throws Exception{
        // 验证密码是否正确 计算 mac
        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, keystore.kdfparams.salt, keystore.version);

        byte[] derivedKey = argon2id.hash(password.getBytes());
        byte[] cipherPrivKey = Hex.decodeHex(keystore.crypto.ciphertext.toCharArray());
        byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                derivedKey,cipherPrivKey
                )
        );
        return new String(Hex.encodeHex(mac)).equals(keystore.mac);
    }

    public static String obPrikey(Keystore ks,String password) throws Exception {
        String privateKey =  new String(Hex.encodeHex(KeystoreController.decrypt(ks,password)));
        return privateKey;
    }





}
