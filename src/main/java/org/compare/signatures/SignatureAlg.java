package org.compare.signatures;

import java.security.*;

public abstract class SignatureAlg {
    String algorithm;
    String provider;


    public SignatureAlg(String algorithm, String provider) {
        this.algorithm = algorithm;
        this.provider = provider;
    }


    public abstract KeyPair generateKeyPair() throws GeneralSecurityException;

    public byte[] generateSignature(PrivateKey privateKey, byte[] input) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(algorithm, provider);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    public boolean verifySignature(PublicKey publicKey, byte[] input, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(algorithm, provider);
        signature.initVerify(publicKey);
        signature.update(input);
        return signature.verify(encSignature);
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
