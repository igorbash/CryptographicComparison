package org.compare.signatures;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Sphincs extends SignatureAlg {
    public Sphincs() {
        super("Sphincs+", "BCPQC");
    }

    @Override
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(SPHINCSPlusParameterSpec.sha2_256s);
        return keyPair.generateKeyPair();
    }
}
