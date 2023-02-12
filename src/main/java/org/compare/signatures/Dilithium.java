package org.compare.signatures;

import java.security.*;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public class Dilithium extends SignatureAlg {
    public Dilithium() {
        super("Dilithium", "BCPQC");
    }

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(DilithiumParameterSpec.dilithium5);
        return keyPair.generateKeyPair();
    }
}
