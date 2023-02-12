package org.compare;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.compare.kem.*;
import org.compare.signatures.*;

import java.security.*;
import java.util.Arrays;

public class Main {
    static final byte[] MESSAGE = "MESSAGE".getBytes();

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
        measureSignAlgorithmsTime();
        measureRSAEncryption();
        measureECDH();
        measureKEM();
    }

    static void measureSignAlgorithmsTime() {
        SignatureAlg[] signatureAlgs = {new RSA(), new Dilithium(), new Sphincs(), new Falcon()};
        Arrays.stream(signatureAlgs).toList().forEach(Main::measureSignAlgorithmTime);
    }

    static void measureRSAEncryption() {
        try {
            RSA rsa = new RSA();
            KeyPair keyPair = rsa.generateKeyPair();
            long start = System.nanoTime();
            byte[] cipherText = rsa.encrypt(MESSAGE, keyPair.getPublic());
            long end = System.nanoTime();
            System.out.println("RSA Encryption: " + (end - start) / 1_000_000_000.00 + " seconds");

            start = System.nanoTime();
            byte[] plainText = rsa.decrypt(cipherText, keyPair.getPrivate());
            end = System.nanoTime();
            System.out.println("RSA Decryption: " + (end - start) / 1_000_000_000.00 + " seconds");
            assert new String(MESSAGE).equals(new String(plainText));
            System.out.println("===========================================");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    static void measureECDH() {
        try {
            System.out.println("Running ECDH");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
            keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("B-571"));
            PublicKey recipientPublic = keyPairGenerator.generateKeyPair().getPublic();
            long start = System.nanoTime();
            keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
            keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("B-571"));
            PrivateKey initiatorPrivate = keyPairGenerator.generateKeyPair().getPrivate();
            ECDH.initiatorAgreementBasic(initiatorPrivate, recipientPublic);
            long end = System.nanoTime();
            System.out.println("Key exchange: " + (end - start) / 1_000_000_000.00 + " seconds");
            System.out.println("===========================================");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    static void measureSignAlgorithmTime(SignatureAlg signatureAlg) {
        try {
            System.out.println("Running " + signatureAlg.getAlgorithm());

            long start = System.nanoTime();
            KeyPair keyPair = signatureAlg.generateKeyPair();
            long end = System.nanoTime();
            System.out.println("Key generation: " + (end - start) / 1_000_000_000.00 + " seconds");

            start = System.nanoTime();
            byte[] signature = signatureAlg.generateSignature(keyPair.getPrivate(), MESSAGE);
            end = System.nanoTime();
            System.out.println("Sign: " + (end - start) / 1_000_000_000.00 + " seconds");

            start = System.nanoTime();
            assert signatureAlg.verifySignature(keyPair.getPublic(), MESSAGE, signature);
            end = System.nanoTime();
            System.out.println("Verify: " + (end - start) / 1_000_000_000.00 + " seconds");

            System.out.println("===========================================");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    static void measureKEM() {
        KEMAlg[] kemAlgs = {new McEliece(), new BIKE(), new HQC(), new Kyber()};
        Arrays.stream(kemAlgs).toList().forEach(alg -> {
            System.out.println("Running " + alg.getName());
            alg.kem();
            System.out.println("===========================================");
        });
    }
}
