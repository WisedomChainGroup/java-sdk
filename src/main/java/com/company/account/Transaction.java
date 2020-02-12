package com.company.account;

import com.company.encoding.BigEndian;
import com.company.keystore.crypto.SHA3Utility;
import com.company.keystore.util.ByteUtil;
import com.company.protobuf.ProtocolModel;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.protobuf.ByteString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.Arrays;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class Transaction {

    public static final int DEFAULT_TRANSACTION_VERSION = 1;

    public static final int PUBLIC_KEY_SIZE = 32;

    public static final int SIGNATURE_SIZE = 64;

    public static final int ADDRESS_SIZE = 20;

    public static final long[] GAS_TABLE = new long[]{
            0, 50000, 20000,
            80000, 50000, 50000,
            50000, 50000, 50000,
            50000, 50000, 50000,
            50000
    };

    public static final int TYPE_MAX = 12;

    public enum Type {
        COINBASE, TRANSFER, VOTE,
        DEPOSIT, TRANSFER_MULTISIG_MULTISIG, TRANSFER_MULTISIG_NORMAL,
        TRANSFER_NORMAL_MULTISIG, ASSET_DEFINE, ATOMIC_EXCHANGE,
        INCUBATE, EXTRACT_INTEREST, EXTRACT_SHARING_PROFIT,
        TERMINATE_INCUBATE
    }

    public static Transaction fromProto(ProtocolModel.Transaction tx) {
        Transaction res = new Transaction();
        res.version = tx.getVersion();
        res.type = tx.getType().getNumber();
        res.nonce = tx.getNonce();
        if (tx.getFrom() != null) {
            res.from = tx.getFrom().toByteArray();
        }
        res.gasPrice = tx.getGasPrice();
        res.amount = tx.getAmount();
        if (tx.getPayload() != null) {
            res.payload = tx.getPayload().toByteArray();
        }
        if (tx.getTo() != null) {
            res.to = tx.getTo().toByteArray();
        }
        if (tx.getSignature() != null) {
            res.signature = tx.getSignature().toByteArray();
        }
        return res;
    }

    public int version;

    @Min(0)
    @Max(TYPE_MAX)
    public int type;

    @Min(0)
    public long nonce;

    @NotNull
    @Size(min = PUBLIC_KEY_SIZE, max = PUBLIC_KEY_SIZE)
    public byte[] from;

    // unit brain
    @Min(0)
    public long gasPrice;

    @Min(0)
    public long amount;

    public byte[] payload;

    @NotNull
    @Size(min = ADDRESS_SIZE, max = ADDRESS_SIZE)
    public byte[] to;

    @NotNull
    @Size(max = SIGNATURE_SIZE, min = SIGNATURE_SIZE)
    public byte[] signature;

    @JsonIgnore
    private byte[] hashCache;

    @JsonIgnore
    private String hashHexString;

    @JsonIgnore
    public byte[] blockHash;

    @JsonIgnore
    public long height;

    public void setHashCache(byte[] hashCache) {
        this.hashCache = hashCache;
    }

    @JsonIgnore
    private byte[] getRaw(boolean nullSignature) {
        long payloadLength = 0;
        if (payload != null) {
            payloadLength = payload.length;
        }
        byte[] sig = new byte[SIGNATURE_SIZE];
        if (!nullSignature) {
            sig = signature;
        }
        return Arrays.concatenate(new byte[][]{
                new byte[]{(byte) version}, // 1 byte
                new byte[]{(byte) type}, // 1 byte
                BigEndian.encodeUint64(nonce), // 8 byte
                from, // 32 byte
                BigEndian.encodeUint64(gasPrice), // 8 byte
                BigEndian.encodeUint64(amount), // 8 byte
                sig,
                to, // 20 byte
                BigEndian.encodeUint32(payloadLength),
                payload,
        });
    }

    @JsonIgnore
    public byte[] getRawForHash() {
        return getRaw(false);
    }

    @JsonIgnore
    public byte[] getRawForSign() {
        return getRaw(true);
    }

    public int size() {
        return getRawForHash().length + getHash().length;
    }

    @JsonIgnore
    public byte[] getHash() {
        if (hashCache == null) {
//            hashCache = HashUtil.sha3256(getRawForHash());
            hashCache = SHA3Utility.sha3256(getRawForHash());
        }
        return hashCache;
    }

    @JsonIgnore
    public String getHashHexString() {
        if (hashHexString == null) {
            hashHexString = new String(Hex.encodeHex(getHash()));
        }
        return hashHexString;
    }


    @JsonIgnore
    public long getFee() {
        return gasPrice * GAS_TABLE[type];
    }

    public ProtocolModel.Transaction encode() {
        ProtocolModel.Transaction.Builder builder = ProtocolModel.Transaction.newBuilder();
        builder.setVersion(version);
        builder.setType(ProtocolModel.Transaction.Type.forNumber(type));
        builder.setNonce(nonce);
        builder.setFrom(ByteString.copyFrom(from));
        builder.setGasPrice(gasPrice);
        builder.setAmount(amount);
        builder.setPayload(ByteString.copyFrom(payload));
        builder.setTo(ByteString.copyFrom(to));
        builder.setSignature(ByteString.copyFrom(signature));
        builder.setHash(ByteString.copyFrom(getHash()));
        return builder.build();
    }

    public byte[] toRPCBytes(){
        byte[] raw = getRawForHash();
        return Arrays.concatenate(new byte[]{(byte)version}, getHash(), Arrays.copyOfRange(raw, 1, raw.length));
    }

    public static ProtocolModel.Transaction changeProtobuf(byte[] msg) {
        ProtocolModel.Transaction.Builder tran = ProtocolModel.Transaction.newBuilder();
        //version
        byte[] version = ByteUtil.bytearraycopy(msg, 0, 1);
        tran.setVersion(version[0]);
        msg = ByteUtil.bytearraycopy(msg, 1, msg.length - 1);
        //hash
        byte[] hash = ByteUtil.bytearraycopy(msg, 0, 32);
        tran.setHash(ByteString.copyFrom(hash));
        msg = ByteUtil.bytearraycopy(msg, 32, msg.length - 32);
        //type
        byte[] type = ByteUtil.bytearraycopy(msg, 0, 1);
        tran.setType(ProtocolModel.Transaction.Type.forNumber(type[0]));
        msg = ByteUtil.bytearraycopy(msg, 1, msg.length - 1);
        //nonce
        byte[] nonce = ByteUtil.bytearraycopy(msg, 0, 8);
        tran.setNonce(BigEndian.decodeUint64(nonce));
        msg = ByteUtil.bytearraycopy(msg, 8, msg.length - 8);
        //from
        byte[] from = ByteUtil.bytearraycopy(msg, 0, 32);
        tran.setFrom(ByteString.copyFrom(from));
        msg = ByteUtil.bytearraycopy(msg, 32, msg.length - 32);
        //gasprice
        byte[] gasprice = ByteUtil.bytearraycopy(msg, 0, 8);
        tran.setGasPrice(BigEndian.decodeUint64(gasprice));
        msg = ByteUtil.bytearraycopy(msg, 8, msg.length - 8);
        //amount
        byte[] amount = ByteUtil.bytearraycopy(msg, 0, 8);
        tran.setAmount(BigEndian.decodeUint64(amount));
        msg = ByteUtil.bytearraycopy(msg, 8, msg.length - 8);
        //sig
        byte[] sig = ByteUtil.bytearraycopy(msg, 0, 64);
        tran.setSignature(ByteString.copyFrom(sig));
        msg = ByteUtil.bytearraycopy(msg, 64, msg.length - 64);
        //to
        byte[] to = ByteUtil.bytearraycopy(msg, 0, 20);
        tran.setTo(ByteString.copyFrom(to));
        msg = ByteUtil.bytearraycopy(msg, 20, msg.length - 20);
        //payloadlen
        byte[] payloadlen = ByteUtil.bytearraycopy(msg, 0, 4);
        tran.setPayloadlen(ByteUtil.byteArrayToInt(payloadlen));
        if (type[0] == 0x09 || type[0] == 0x0a || type[0] == 0x0b) {
            msg = ByteUtil.bytearraycopy(msg, 4, msg.length - 4);
            byte[] payload = ByteUtil.bytearraycopy(msg, 0, ByteUtil.byteArrayToInt(payloadlen));
            tran.setPayload(ByteString.copyFrom(payload));
        }
        return tran.build();
    }


    public Transaction(){

    }

    public Transaction(String message) throws Exception {
        byte[] msg =  Hex.decodeHex((message.toCharArray()));
        //version
        byte[] version = ByteUtil.bytearraycopy(msg, 0, 1);
        this.version = version[0];
        msg = ByteUtil.bytearraycopy(msg, 1, msg.length - 1);
        //hash
        byte[] hash = ByteUtil.bytearraycopy(msg, 0, 32);
        msg = ByteUtil.bytearraycopy(msg, 32, msg.length - 32);
        //type
        byte[] type = ByteUtil.bytearraycopy(msg, 0, 1);
        this.type = type[0];
        msg = ByteUtil.bytearraycopy(msg, 1, msg.length - 1);
        //nonce
        byte[] nonce = ByteUtil.bytearraycopy(msg, 0, 8);
        this.nonce = BigEndian.decodeUint64(nonce);
        msg = ByteUtil.bytearraycopy(msg, 8, msg.length - 8);
        //fromx
        byte[] from =  ByteUtil.bytearraycopy(msg, 0, 32);
        this.from = from;
        msg = ByteUtil.bytearraycopy(msg, 32, msg.length - 32);
        //gasprice
        byte[] gasprice = ByteUtil.bytearraycopy(msg, 0, 8);
        this.gasPrice = BigEndian.decodeUint64(gasprice);
        msg = ByteUtil.bytearraycopy(msg, 8, msg.length - 8);
        //amount
        byte[] amount = ByteUtil.bytearraycopy(msg, 0, 8);
        this.amount = BigEndian.decodeUint64(amount);
        msg = ByteUtil.bytearraycopy(msg, 8, msg.length - 8);
        //sig
        byte[] signature = ByteUtil.bytearraycopy(msg, 0, 64);
        this.signature = signature;
        msg = ByteUtil.bytearraycopy(msg, 64, msg.length - 64);
        //to
        byte[] to = ByteUtil.bytearraycopy(msg, 0, 20);
        this.to = to;
        msg = ByteUtil.bytearraycopy(msg, 20, msg.length - 20);
        //payloadlen
        byte[] payloadlen= ByteUtil.bytearraycopy(msg, 0, 4);
        msg = ByteUtil.bytearraycopy(msg, 4, msg.length - 4);
        //payload
        byte[] payload = ByteUtil.bytearraycopy(msg, 0, ByteUtil.byteArrayToInt(payloadlen));
        this.payload = payload;
    }

}
