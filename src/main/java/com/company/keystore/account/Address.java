package com.company.keystore.account;


import com.company.keystore.wallet.KeystoreController;

import java.security.PublicKey;

public class Address {

    //hex string,not include 0x prefix
    private  String address;
    private  String pubkeyToAddress(PublicKey publicKey){
        return KeystoreController.pta(publicKey.getEncoded());
    }
    public Address(PublicKey publicKey){
        this.address = pubkeyToAddress(publicKey);
    }

    public String getAddress() {
        return address;
    }

}
