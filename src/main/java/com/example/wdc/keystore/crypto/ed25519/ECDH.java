package com.example.wdc.keystore.crypto.ed25519;




import com.example.wdc.keystore.crypto.CryptoException;


import java.security.PublicKey;

public interface ECDH {
    byte[] generateSecretKey(PublicKey publicKey) throws CryptoException;
}
