package org.compare.kem;

import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;

public class BIKE extends KEMAlg {
    public BIKE() {
        super("BIKE", "BCPQC", BIKEParameterSpec.bike256);
    }
}
