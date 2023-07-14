package org.compare.signatures;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.compare.Config.falconParameterSpec;

public class Falcon extends SignatureAlg {
    public Falcon() {
        super("Falcon", "BCPQC");
    }

    @Override
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(falconParameterSpec);
        return keyPair.generateKeyPair();
    }
}
