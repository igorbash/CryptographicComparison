package org.compare.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.compare.Config.sphincsPlusParameterSpec;

public class Sphincs extends SignatureAlg {
    public Sphincs() {
        super("Sphincs+", "BCPQC");
    }

    @Override
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(sphincsPlusParameterSpec);
        return keyPair.generateKeyPair();
    }
}
