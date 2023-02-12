package org.compare.kem;

import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

public class Kyber extends KEMAlg {
    public Kyber() {
        super("Kyber", "BCPQC", KyberParameterSpec.kyber1024);
    }
}
