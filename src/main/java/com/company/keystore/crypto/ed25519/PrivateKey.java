package com.company.keystore.crypto.ed25519;

import com.company.keystore.crypto.CryptoException;

public interface PrivateKey extends java.security.PrivateKey {
    byte[] sign(byte[] msg) throws CryptoException;
    PublicKey generatePublicKey();
}
