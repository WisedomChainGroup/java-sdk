//package com.example.wdc.command;
//
//import com.example.wdc.encoding.BigEndian;
//
//import com.example.wdc.keystore.crypto.SHA3Utility;
//import com.example.wdc.keystore.crypto.ed25519.Ed25519PrivateKey;
//import com.example.wdc.keystore.util.ByteUtil;
//import com.example.wdc.keystore.wallet.WalletUtility;
//import com.example.wdc.result.JsonResult;
//import com.example.wdc.utxo.UTXO;
//import net.sf.json.JSONObject;
//import org.apache.commons.codec.DecoderException;
//import org.apache.commons.codec.binary.Hex;
//
//
//import java.math.BigDecimal;
//import java.util.ArrayList;
//import java.util.List;
//
//public class TransactionUtility {
//
//
//    public static List<byte[]> CreateRawTransaction(String address, BigDecimal amount, List<UTXO> in, BigDecimal fee) throws DecoderException {
//        //手续费
////        Long feeValue = fee.longValue();
////        if (feeValue==0){
////            feeValue =
////        }
//
//        //事务
//        byte[] version=new byte[1];
//        version[0]=0x01;
//        //发起WDC转账
//        byte[] type=new byte[1];
//        type[0]=0x01;
//        byte[] tran1=ByteUtil.merge(version,type);
////        //锁定时间戳
//        byte[] date= BigEndian.encodeUint32(0);//长度为4
//
//        byte[] nosigin = new byte[0];
//        List<byte[]> indexs = new ArrayList<>();
//        List<byte[]> sha32s = new ArrayList<>();
//        for(int i=0;i<in.size();i++){
//            byte[] eachin = new byte[136];
//
//            //输入
//            byte[] incount=new byte[1];
//            incount[0]= (byte) in.size();
//            //前置交易哈希值 32长度
////            byte[] sha32=SHA3Utility.sha3256(new byte[32]);
//            byte[] sha32=in.get(i).getHash();
//            //索引 4长度
////            byte[] indexex=ByteUtil.intToBytes(0);
//            byte[] index=ByteUtil.intToBytes(in.get(i).getIndex());
//
//            indexs.add(index);
//            //输入脚本长度 4长度
//            byte[] inlength=ByteUtil.intToBytes(96);
//            //输入脚本
//            //本次交易事务数据
//            byte[] signull=new byte[64];
//
//            byte[] pubhash = WalletUtility.addressToPubkeyHash(in.get(i).getAddress());
//            byte[] eachnosigin=ByteUtil.merge(incount,sha32,index,inlength,signull,pubhash);
//            nosigin=ByteUtil.merge(nosigin,eachnosigin);
//        }
//
//        //输出 1个62长度
//        byte[] outacount=new byte[1];
//        outacount[0]=1;
//        //转出金额 8长度
//
//        BigDecimal bdAmount = amount.multiply(BigDecimal.valueOf(100000000L));
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
//        byte[] pubkey160 = WalletUtility.addressToPubkeyHash(address);
//        byte[] outl=new byte[2];
//        outl[0]= (byte) 0x88;
//        outl[1]= (byte) 0xac;
//        outscrip=ByteUtil.merge(outf,pubkey160,outl);
//        byte[] outfull=ByteUtil.merge(outacount,Amount,outlength,outscrip);
//        byte[] localdate=ByteUtil.merge(tran1,nosigin,outfull,date);
//
////        //签名原文数据
//        List<byte[]> indexdateList = new ArrayList<>();
//        for(int j=0;j<in.size();j++){
//            byte[] indexdate=ByteUtil.merge(localdate,sha32s.get(j),indexs.get(j),outscrip);
//            indexdateList.add(indexdate);
//        }
//        return  indexdateList;
//    }
//
//    public static byte[] signRawBasicTransaction(String privateKey,List<byte[]> indexdateList) throws Exception {
//        byte[] privkey = Hex.decodeHex(privateKey.toCharArray());
//        byte[] pubkey = Hex.decodeHex(WalletUtility.prikeyToPubkey(privateKey).toCharArray());
//        byte[] incount = new byte[1];
//        incount[0] = (byte) indexdateList.size();
//        List<byte[]> tranfullList = new ArrayList<>();
//        for (int i = 0; i < indexdateList.size(); i++) {
//            //签名数据
//            byte[] sig = new Ed25519PrivateKey(privkey).sign(indexdateList.get(i));
//
//            byte[] sigfull = ByteUtil.merge(sig, pubkey);
//
//            byte[] infull = ByteUtil.merge(incount, sha32, indexex, inlength, sigfull);
//
//            byte[] transha = SHA3Utility.sha3256(ByteUtil.merge(version, type, infull, outfull, date));
//
//            byte[] tranfull = ByteUtil.merge(version, transha, type, infull, outfull, date);
//        }
//        return tranfullList;
//    }
//
//    public static List<byte[]> SendToAddress(String address, BigDecimal amount, List<UTXO> in, BigDecimal fee,String privateKey) throws Exception {
//        List<byte[]> indexdateList = CreateRawTransaction(address,amount,in,fee);
//        List<byte[]> tranfullList = signRawBasicTransaction(privateKey,indexdateList);
//        return  tranfullList;
//    }
//}