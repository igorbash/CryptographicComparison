package org.compare.signatures;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Falcon extends SignatureAlg {
    public Falcon() {
        super("Falcon", "BCPQC");
    }

    @Override
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(FalconParameterSpec.falcon_1024);
        return keyPair.generateKeyPair();
    }
}
