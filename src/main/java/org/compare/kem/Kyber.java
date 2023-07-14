package org.compare.kem;

import static org.compare.Config.kyberParameterSpec;

public class Kyber extends KEMAlg {
    public Kyber() {
        super("Kyber", "BCPQC", kyberParameterSpec);
    }
}
