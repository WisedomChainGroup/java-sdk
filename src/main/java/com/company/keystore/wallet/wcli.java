package com.company.keystore.wallet;

import com.company.keystore.crypto.RipemdUtility;
import com.company.keystore.crypto.SHA3Utility;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class wcli {
    private static final Logger log = Logger.getLogger(wcli.class.getName());
    private static Options options = new Options();
    private static String[] args = { "-addresstopubkeyhash","111111"};

    public static void main(String[] args) {
        // 定义阶段
        options.addOption("accountnew", "accountnew", false, "new account.");
        options.addOption("accountsnew", "accountsnew", false, "new accounts.");
        options.addOption("password", "password", true, "password");
        //options.addOption("confirmpassword", "confirmpassword", true, "confirmpassword.");
        options.addOption("addresstopubkeyhash", "addresstopubkeyhash ", true, "address to pubkeyhash .");
        options.addOption("keystoretoaddress", "keystoretoaddress  ", false, "keystore to address .");
        options.addOption("keystoretopubkeyhash", "keystoretopubkeyhash   ", false, "keystore to pubkeyhash.");
        options.addOption("connect", "connect", false, "connect rpc");
        options.addOption("path", "path", true, "path");
        options.addOption("ip", "ip", true, "ip");
        options.addOption("port", "port", true, "port");
        options.addOption("batch", "batch", true, "batch");
        options.addOption("address", "address", true, "address");



        // 解析阶段
        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;
        try {

            // 获取参数值，应用程序交互阶段。应用程序启动。
            cmd = parser.parse(options, args);
            //新建keystore
            if(cmd.hasOption("accountnew")){
                String password = cmd.getOptionValue("password");
                String path = cmd.getOptionValue("path");
                String batch = cmd.getOptionValue("batch");
                int numb;
                if(batch == "" || batch == null){
                    numb = 1;
                }else{
                    numb = Integer.valueOf(batch);
                }
                if(password == null || password.length()>20 || password.length()<8){
                    log.log(Level.SEVERE, "Check password");
                }else{
                    for(int i=0;i<numb;i++){
                        WalletUtility.generateKeystore(password,path);
                    }
                    System.out.println("SUCCESS!");
                }
            }

            //地址转公钥哈希
            if (cmd.hasOption("addresstopubkeyhash")) {
                String address = cmd.getOptionValue("addresstopubkeyhash");
                String pubkeyhash = WalletUtility.addressToPubkeyHash(address);
                System.out.println("pubkeyhash:"+pubkeyhash);
            }
            //keystore转地址
            if(cmd.hasOption("keystoretoaddress")){
                String path = cmd.getOptionValue("path");
                String password = cmd.getOptionValue("password");
                if(password == null || password.length()>20 || password.length()<8){
                    log.log(Level.SEVERE, "Check password");
                }else{
                    Keystore ks = new Keystore();
                    String privateKey;
                    try {
                        String folderPath = path;
                        FileInputStream file = null;
                        file= new FileInputStream(folderPath);
                        byte[] data = new byte[1024]; //数据存储的数组
                        int i = file.read(data);//对比上面代码中的 int n = fis.read();读取第一个字节的数据返回到n中
                        //解析数据
                        String str = new String(data,0,i);
                        ks = WalletUtility.unmarshal(str);
                        file.close();
                        String address = ks.address;
                        System.out.println("address:"+address);
                    }catch (FileNotFoundException e){
                        e.printStackTrace();
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
            //keystore转公钥哈希
            if(cmd.hasOption("keystoretopubkeyhash")){
                String path = cmd.getOptionValue("path");
                String password = cmd.getOptionValue("password");
                if(password == null || password.length()>20 || password.length()<8){
                    log.log(Level.SEVERE, "Check password");
                }else{
                    Keystore ks = new Keystore();
                    String privateKey;
                    try {
                        String folderPath = path;
                        FileInputStream file = null;
                        file= new FileInputStream(folderPath);
                        byte[] data = new byte[1024]; //数据存储的数组
                        int i = file.read(data);//对比上面代码中的 int n = fis.read();读取第一个字节的数据返回到n中
                        //解析数据
                        String str = new String(data,0,i);
                        ks = WalletUtility.unmarshal(str);
                        file.close();
                        String privatekey =  KeystoreController.obPrikey(ks,password);
                        String pubkey = WalletUtility.prikeyToPubkey(privatekey);
                        byte[] pub256 = SHA3Utility.keccak256(Hex.decodeHex(pubkey.toCharArray()));
                        byte[] r1 = RipemdUtility.ripemd160(pub256);
                        String pubkeyHash = new String(Hex.encodeHex(r1));
                        System.out.println("pubkeyHash:"+pubkeyHash);
                    }catch (FileNotFoundException e){
                        e.printStackTrace();
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
            //连接rpc
            if(cmd.hasOption("connect")){
                String port = cmd.getOptionValue("port");
                String ip = cmd.getOptionValue("ip");
                TxUtility.connect(ip,port);
                System.out.println(true);
            }
        } catch (ParseException e) {
            log.log(Level.SEVERE, "false");
        } catch (Exception e) {
            log.log(Level.SEVERE,"false");
        }

    }
}
