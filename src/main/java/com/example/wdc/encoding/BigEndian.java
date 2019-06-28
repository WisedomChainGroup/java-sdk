package com.example.wdc.encoding;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;

public class BigEndian {
    private static final long MAX_UINT_32 = 0x00000000ffffffffL;
    private static final int MAX_UINT_16 = 0x0000ffff;
    private static final String MAX_UINT_256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    public static int getMaxUint16() {
        return MAX_UINT_16;
    }

    public static long decodeUint32(byte[] data) {
        return new BigInteger(1, data).longValue();
    }

    // big-endian encoding
    public static byte[] encodeUint32(long value) {
        byte[] res = new byte[4];
        res[0] = (byte) ((value & 0x00000000FF000000L) >>> 24);
        res[1] = (byte) ((value & 0x0000000000FF0000L) >>> 16);
        res[2] = (byte) ((value & 0x000000000000FF00L) >>> 8);
        res[3] = (byte) (value & 0x00000000000000FFL);
        return res;
    }

    public static int compareUint256(byte[] a, byte[] b) {
        return new BigInteger(1, a).compareTo(
                new BigInteger(1, b)
        );
    }

    public static long getMaxUint32() {
        return MAX_UINT_32;
    }

    public static int decodeUint16(byte[] in){
        return new BigInteger(1, in).intValue();
    }

    public static byte[] encodeUint16(int value){
        byte[] res = new byte[2];
        res[0] = (byte) ((value & 0x0000ff00) >>> 8);
        res[1] = (byte) (value & 0x000000ff);
        return res;
    }

    public static void main(String[] args){
        System.out.println(Hex.encodeHex(encodeUint16(getMaxUint16())));
    }
}
