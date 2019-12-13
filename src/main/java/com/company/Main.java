package com.company;

import com.company.keystore.wallet.*;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
//import net.sf.json.JSONObject;
//import org.apache.commons.cli.*;

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    private static final Logger log = Logger.getLogger(Main.class.getName());
    private static Options options = new Options();
    private static String[] args = { "-addresstopubkeyhash","111111"};

    public static void main(String[] args) {
        // 定义阶段
        options.addOption("accountnew", "accountnew", false, "new account.");
        //options.addOption("confirmpassword", "confirmpassword", true, "confirmpassword.");
        options.addOption("addresstopubkeyhash", "addresstopubkeyhash ", true, "address to pubkeyhash .");
        options.addOption("keystoretoaddress", "keystoretoaddress  ", false, "keystore to address .");
        options.addOption("keystoretopubkeyhash", "keystoretopubkeyhash   ", false, "keystore to pubkeyhash.");
        options.addOption("connect", "connect", false, "connect rpc");
        options.addOption("path", "path", true, "path");
        options.addOption("password", "password", true, "password");


        // 解析阶段
        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;
        try {

            // 获取参数值，应用程序交互阶段。应用程序启动。
            cmd = parser.parse(options, args);

            if(cmd.hasOption("accountnew")){//新建keystore
                String password1 = cmd.getOptionValue("password");
//                confirmPassword(password1);
            }

            if (cmd.hasOption("addresstopubkeyhash")) {//地址转公钥哈希
                String address = cmd.getOptionValue("addresstopubkeyhash");
                String pubkeyhash = WalletUtility.addressToPubkeyHash(address);
                System.out.println("pubkeyhash:"+pubkeyhash);
            }

            if(cmd.hasOption("keystoretoaddress")){

               String path = cmd.getOptionValue("keystoretoaddress");
                System.out.println(path);
               String password = cmd.getOptionValue("password");
                System.out.println("11111111111");
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
                       privateKey = new String(Hex.encodeHex(KeystoreController.decrypt(ks,password)));
                       System.out.println("privateKey:"+privateKey);
                   }catch (FileNotFoundException e){
                       e.printStackTrace();
                   }catch (Exception e){
                       e.printStackTrace();
                   }
               }
            }
        } catch (ParseException e) {
            log.log(Level.SEVERE, "Failed to parse comand line properties", e);
        }

    }



}
