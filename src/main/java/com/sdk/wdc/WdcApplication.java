package com.sdk.wdc;

import com.sdk.wdc.keystore.wallet.WalletUtility;
import org.apache.commons.codec.binary.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class WdcApplication {

    public static void main(String[] args) {
        SpringApplication.run(WdcApplication.class, args);
    }

}
