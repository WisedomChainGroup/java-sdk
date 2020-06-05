package com.company.keystore.wallet;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {

    private final static String KEY="1234123412341324";
    private final static String IV="1234123412341234";

    /**
     * aes 加密
     * @param data
     * @return
     */
    public static String encryptData(String data){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }
            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
            SecretKeySpec keyspec = new SecretKeySpec(KEY.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(IV.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] encrypted = cipher.doFinal(plaintext);
            return new String(Base64.encodeBase64(encrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * aes 解密
     * @param data 密文
     * @return
     */
    public static String decryptData(String data){
        try {
            byte[] encrypted1 = Base64.decodeBase64(data.getBytes());
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(KEY.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(IV.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original);
            return originalString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
