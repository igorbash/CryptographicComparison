package org.compare.kem;

import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;

public class McEliece extends KEMAlg {
    public McEliece() {
        super("CMCE", "BCPQC", CMCEParameterSpec.mceliece8192128);
    }
}
