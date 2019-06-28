package com.example.wdc.keystore.wallet;

import com.example.wdc.keystore.crypto.RipemdUtility;
import com.example.wdc.keystore.crypto.SHA3Utility;
import com.example.wdc.keystore.util.Base58Utility;
import com.example.wdc.keystore.util.ByteUtil;

public class KeystoreAction {


    public static String pta(byte[] pubkey){
        byte[] pub256 = SHA3Utility.keccak256(pubkey);
        byte[] r1 = RipemdUtility.ripemd160(pub256);
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = Base58Utility.encode(b5);
        return  s6;
    }

    public static byte[] atph(String address){
        byte[] r5 = Base58Utility.decode(address);
        byte[] r2 = ByteUtil.bytearraycopy(r5,0,21);
        byte[] r1 = ByteUtil.bytearraycopy(r2,1,20);
        return  r1;
    }

    public static String phta(byte[] r1){
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = Base58Utility.encode(b5);
        return  s6;
    }
}
