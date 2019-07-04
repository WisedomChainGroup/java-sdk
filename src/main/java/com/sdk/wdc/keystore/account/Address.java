package com.sdk.wdc.keystore.account;


import com.sdk.wdc.keystore.wallet.KeystoreAction;

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
