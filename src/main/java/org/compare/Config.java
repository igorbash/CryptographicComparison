package org.compare;

import org.bouncycastle.pqc.jcajce.spec.*;

public class Config {
    public static DilithiumParameterSpec dilithiumParameterSpec = DilithiumParameterSpec.dilithium5;
    public static SPHINCSPlusParameterSpec sphincsPlusParameterSpec = SPHINCSPlusParameterSpec.sha2_256s;
    public static FalconParameterSpec falconParameterSpec = FalconParameterSpec.falcon_1024;
    public static int rsaKeySize = 2048;
    public static String ecdhParameter = "B-571";
    public static String ecdhKey = "AES[256]";
    public static BIKEParameterSpec bikeParameterSpec = BIKEParameterSpec.bike256;
    public static HQCParameterSpec hqcParameterSpec = HQCParameterSpec.hqc256;
    public static KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber1024;
    public static CMCEParameterSpec cmceParameterSpec = CMCEParameterSpec.mceliece8192128;
}
