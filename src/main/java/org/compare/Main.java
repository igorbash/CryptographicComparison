package org.compare;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.compare.kem.*;
import org.compare.signatures.*;

import java.security.*;
import java.util.Arrays;
import java.util.HashMap;

import static org.compare.Config.*;

public class Main {
    static final byte[] MESSAGE = "MESSAGE".getBytes();
    static final HashMap<String, Double> keyGenerationTimes = new HashMap<>();
    static final HashMap<String, Double> signTimes = new HashMap<>();
    static final HashMap<String, Double> verifyTimes = new HashMap<>();
    static final HashMap<String, Double> kemTimes = new HashMap<>();

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
        measureSignAlgorithmsTime();
        measureRSAEncryption();
        measureECDH();
        measureKEM();
        measureRelative();
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
            System.out.println("Running ECDH with " + ecdhParameter + " for " + ecdhKey);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
            keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec(ecdhParameter));
            PublicKey recipientPublic = keyPairGenerator.generateKeyPair().getPublic();
            long start = System.nanoTime();
            keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
            keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec(ecdhParameter));
            PrivateKey initiatorPrivate = keyPairGenerator.generateKeyPair().getPrivate();
            ECDH.initiatorAgreementBasic(initiatorPrivate, recipientPublic);
            long end = System.nanoTime();
            System.out.println("Key exchange: " + (end - start) / 1_000_000_000.00 + " seconds");
            kemTimes.put("ECDH", (end - start) / 1_000_000_000.00);
            System.out.println("===========================================");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    static void measureSignAlgorithmTime(SignatureAlg signatureAlg) {
        String specs = "";
        switch (signatureAlg.getAlgorithm()) {
            case "RSA" -> specs = String.valueOf(rsaKeySize);
            case "Dilithium" -> specs = dilithiumParameterSpec.getName();
            case "Falcon" -> specs = falconParameterSpec.getName();
            case "Sphincs+" -> specs = sphincsPlusParameterSpec.getName();
        }
        try {
            System.out.println("Running Signing Algorithm" + signatureAlg.getAlgorithm() + " " + specs);

            long start = System.nanoTime();
            KeyPair keyPair = signatureAlg.generateKeyPair();
            long end = System.nanoTime();
            System.out.println("Key generation: " + (end - start) / 1_000_000_000.00 + " seconds");
            keyGenerationTimes.put(signatureAlg.getAlgorithm(), (end - start) / 1_000_000_000.00);

            start = System.nanoTime();
            byte[] signature = signatureAlg.generateSignature(keyPair.getPrivate(), MESSAGE);
            end = System.nanoTime();
            System.out.println("Sign: " + (end - start) / 1_000_000_000.00 + " seconds");
            signTimes.put(signatureAlg.getAlgorithm(), (end - start) / 1_000_000_000.00);

            start = System.nanoTime();
            assert signatureAlg.verifySignature(keyPair.getPublic(), MESSAGE, signature);
            end = System.nanoTime();
            System.out.println("Verify: " + (end - start) / 1_000_000_000.00 + " seconds");
            verifyTimes.put(signatureAlg.getAlgorithm(), (end - start) / 1_000_000_000.00);

            System.out.println("===========================================");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    static void measureKEM() {
        KEMAlg[] kemAlgs = {new McEliece(), new BIKE(), new HQC(), new Kyber()};
        Arrays.stream(kemAlgs).toList().forEach(alg -> {
            String specs = "";
            switch (alg.getName()) {
                case "CMCE" -> specs = cmceParameterSpec.getName();
                case "BIKE" -> specs = bikeParameterSpec.getName();
                case "HQC" -> specs = hqcParameterSpec.getName();
                case "Kyber" -> specs = kyberParameterSpec.getName();
            }
            System.out.println("Running KEM algorithm" + alg.getName() + " " + specs);
            kemTimes.put(alg.getName(), alg.kem());
            System.out.println("===========================================");
        });
    }

    private static void measureRelative() {
        System.out.println("Signature algorithms relative to RSA2048");
        Double keyGenerationBaseTime = keyGenerationTimes.get("RSA");
        Double signBaseTime = signTimes.get("RSA");
        Double verifyBaseTime = verifyTimes.get("RSA");
        System.out.println("KEY GENERATION:");
        keyGenerationTimes.forEach((name, time) -> System.out.println(name + ": " + time / keyGenerationBaseTime));
        System.out.println("SIGN:");
        signTimes.forEach((name, time) -> System.out.println(name + ": " + time / signBaseTime));
        System.out.println("VERIFY:");
        verifyTimes.forEach((name, time) -> System.out.println(name + ": " + time / verifyBaseTime));
        System.out.println("===========================================");
        System.out.println("KEM algorithms relative to ECDH B-571");
        Double kemBaseTime = kemTimes.get("ECDH");
        kemTimes.forEach((name, time) -> System.out.println(name + ": " + time / kemBaseTime));


    }
}
