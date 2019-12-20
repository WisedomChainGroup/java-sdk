package org.company;

import com.company.keystore.wallet.WalletUtility;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.FileOutputStream;
import java.io.InputStream;

@RunWith(JUnit4.class)
public class TestController {

    @Test
    public void test0() throws Exception{
        InputStream inputStream = TestController.class.getClassLoader().getResource("ks2.json")
                .openStream();
        byte[] bytes
         = new byte[inputStream.available()];
        inputStream.read(bytes);
        String str = new String(bytes);
        System.out.println(str);
        System.out.println(WalletUtility.obtainPrikey(str, "test123456"));
    }

    @Test
    public void testConvert() throws Exception{
        InputStream inputStream = TestController.class.getClassLoader().getResource("ks.json")
                .openStream();
        byte[] bytes
                = new byte[inputStream.available()];
        inputStream.read(bytes);
        String str = new String(bytes);
        System.out.println(WalletUtility.updateKeystoreVersion1to2(str, "test123456"));
    }
}
