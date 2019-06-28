package com.example.wdc.keystore.account;


import com.example.wdc.keystore.wallet.KeystoreAction;
import com.example.wdc.keystore.wallet.WalletUtility;

import java.security.PublicKey;

public class Address {

    //hex string,not include 0x prefix
    private  String address;
    private  String pubkeyToAddress(PublicKey publicKey){
        return KeystoreAction.pta(publicKey.getEncoded());
    }
    public Address(PublicKey publicKey){
        this.address = pubkeyToAddress(publicKey);
    }

    public String getAddress() {
        return address;
    }

}
