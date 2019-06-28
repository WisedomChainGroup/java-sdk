package com.example.wdc.keystore.account;


import com.example.wdc.keystore.crypto.KeyPair;

public class Account {
    private  final KeyPair keyPair;
    private  final Address address;

    public Account(KeyPair keyPair,Address address){
        this.keyPair=keyPair;
        this.address=address;
    }


}
