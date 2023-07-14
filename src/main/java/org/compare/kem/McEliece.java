package org.compare.kem;

import static org.compare.Config.cmceParameterSpec;

public class McEliece extends KEMAlg {
    public McEliece() {
        super("CMCE", "BCPQC", cmceParameterSpec);
    }
}
