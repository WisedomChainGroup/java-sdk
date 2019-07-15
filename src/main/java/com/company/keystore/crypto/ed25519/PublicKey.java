package com.company.keystore.crypto.ed25519;

public interface PublicKey extends java.security.PublicKey {
    boolean verify(byte[] msg, byte[] signature);
}
