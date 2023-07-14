package org.compare.kem;


import static org.compare.Config.bikeParameterSpec;

public class BIKE extends KEMAlg {
    public BIKE() {
        super("BIKE", "BCPQC", bikeParameterSpec);
    }
}
