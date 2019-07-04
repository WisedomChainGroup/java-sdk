package com.sdk.wdc.keystore.crypto.ed25519;




import com.sdk.wdc.keystore.crypto.CryptoException;


import java.security.PublicKey;

public interface ECDH {
    byte[] generateSecretKey(PublicKey publicKey) throws CryptoException;
}
