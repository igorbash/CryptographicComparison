package org.compare.kem;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public abstract class KEMAlg {
    String name;
    String provider;
    AlgorithmParameterSpec algorithmParameterSpec;

    public KEMAlg(String name, String provider, AlgorithmParameterSpec algorithmParameterSpec) {
        this.name = name;
        this.provider = provider;
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    public Double kem() {
        try {
            long start = System.nanoTime();
            KeyPair keyPair = keyGeneration();
            SecretKeyWithEncapsulation secretKeyWithEncapsulationEncryption = encryption(keyPair.getPublic());
            SecretKeyWithEncapsulation secretKeyWithEncapsulationDecryption = decryption(keyPair.getPrivate(), secretKeyWithEncapsulationEncryption.getEncapsulation());
            long end = System.nanoTime();
            System.out.println("KEM: " + (end - start) / 1_000_000_000.00 + " seconds");
            assert Arrays.equals(secretKeyWithEncapsulationEncryption.getEncoded(), secretKeyWithEncapsulationDecryption.getEncoded());
            return (end - start) / 1_000_000_000.00;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return -1.0;
    }

    private KeyPair keyGeneration() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(name, provider);
        keyPairGenerator.initialize(algorithmParameterSpec);
        long start = System.nanoTime();
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        long end = System.nanoTime();
        System.out.println("Key generation: " + (end - start) / 1_000_000_000.00 + " seconds");
        return keyPair;
    }

    private SecretKeyWithEncapsulation encryption(PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(name, provider);
        keyGenerator.init(new KEMGenerateSpec(publicKey, "AES"));
        long start = System.nanoTime();
        SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        long end = System.nanoTime();
        System.out.println("Encryption: " + (end - start) / 1_000_000_000.00 + " seconds");
        return secretKeyWithEncapsulation;
    }

    private SecretKeyWithEncapsulation decryption(PrivateKey privateKey, byte[] encapsulatedKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(name, provider);
        keyGenerator.init(new KEMExtractSpec(privateKey, encapsulatedKey, "AES"));
        long start = System.nanoTime();
        SecretKeyWithEncapsulation secretKeyWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        long end = System.nanoTime();
        System.out.println("Decryption: " + (end - start) / 1_000_000_000.00 + " seconds");
        return secretKeyWithEncapsulation;
    }

    public String getName() {
        return name;
    }
}
