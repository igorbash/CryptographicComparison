package org.compare.kem;

import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;

public class HQC extends KEMAlg {
    public HQC() {
        super("HQC", "BCPQC", HQCParameterSpec.hqc256);
    }
}
