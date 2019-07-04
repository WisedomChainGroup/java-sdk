package com.sdk.wdc.keystore.account;


import com.sdk.wdc.keystore.crypto.KeyPair;

public class Account {
    private  final KeyPair keyPair;
    private  final Address address;

    public Account(KeyPair keyPair,Address address){
        this.keyPair=keyPair;
        this.address=address;
    }


}
