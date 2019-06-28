package com.example.wdc.keystore.crypto.ed25519;

import com.example.wdc.keystore.crypto.CryptoException;

public interface PrivateKey extends java.security.PrivateKey {
    byte[] sign(byte[] msg) throws CryptoException;
    PublicKey generatePublicKey();
}
