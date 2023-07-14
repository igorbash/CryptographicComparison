package org.compare.kem;


import static org.compare.Config.hqcParameterSpec;

public class HQC extends KEMAlg {
    public HQC() {
        super("HQC", "BCPQC", hqcParameterSpec);
    }
}
