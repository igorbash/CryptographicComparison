package org.compare.signatures;

import java.security.*;

import static org.compare.Config.dilithiumParameterSpec;

public class Dilithium extends SignatureAlg {
    public Dilithium() {
        super("Dilithium", "BCPQC");
    }

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(dilithiumParameterSpec);
        return keyPair.generateKeyPair();
    }
}
