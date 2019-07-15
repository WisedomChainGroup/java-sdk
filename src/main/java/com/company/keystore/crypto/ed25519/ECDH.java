package com.company.keystore.crypto.ed25519;


import com.company.keystore.crypto.CryptoException;

import java.security.PublicKey;

public interface ECDH {
    byte[] generateSecretKey(PublicKey publicKey) throws CryptoException;
}
