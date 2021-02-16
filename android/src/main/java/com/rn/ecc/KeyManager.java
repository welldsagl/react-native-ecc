package com.rn.ecc;

import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

public class KeyManager {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final int KEY_SIZE = 256;
    private static final String ALGORITHM = "SHA256withECDSA";

    private SharedPreferences sharedPreferences;

    public KeyManager(SharedPreferences sharedPreferences) {
        this.sharedPreferences = sharedPreferences;
    }

    /**
     * Generate public and private keys.
     *
     * The private key is stored in the KeyStore,
     */
    public String generateKeys() throws
        CertificateException,
        IOException,
        InvalidAlgorithmParameterException,
        InvalidKeyException,
        KeyStoreException,
        NoSuchAlgorithmException,
        NoSuchProviderException {

        String keystoreAlias = UUID.randomUUID().toString();

        // TODO: Check if needed.
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        KeyPairGenerator keyPairGenerator = getKeyPairGenerator(keystoreAlias);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
        String publicKey = EllipticCurveCryptography.getPublicKey(ecPublicKey);

        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(publicKey, keystoreAlias);
        editor.commit();

        return publicKey;
    }

    public boolean hasStoredKeysInKeystore(String publicKey) {
        try {
            String keystoreAlias = sharedPreferences.getString(publicKey, null);
            if (keystoreAlias == null) {
                return false;
            }

            // TODO: Check if needed.
            KeyStore keystore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keystore.load(null);

            KeyStore.Entry entry = keystore.getEntry(keystoreAlias, null);

            return entry instanceof KeyStore.PrivateKeyEntry;
        } catch (Exception ex) {
            return false;
        }
    }

    public Signature getSignature(String publicKey) throws
        CertificateException,
        NoSuchAlgorithmException,
        IOException,
        UnrecoverableKeyException,
        KeyStoreException,
        InvalidKeyException {

        Signature signature = Signature.getInstance(ALGORITHM);
        String keyAlias = sharedPreferences.getString(publicKey, null);

        // TODO: Check if needed.
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
        signature.initSign(privateKey);

        return signature;
    }

    public String sign(String data, Signature signature) throws SignatureException {
        byte[] dataBytes = Base64.decode(data, Base64.NO_WRAP);
        signature.update(dataBytes);
        byte[] signedDataBytes = signature.sign();
        return Base64.encodeToString(signedDataBytes, Base64.NO_WRAP);
    }

    public boolean verify(String data, String publicKey, String expected) throws GeneralSecurityException {
        byte[] dataBytes = Base64.decode(data, Base64.NO_WRAP);
        byte[] publicKeyBytes = Base64.decode(publicKey, Base64.NO_WRAP);
        byte[] expectedBytes = Base64.decode(expected, Base64.NO_WRAP);

        ECPublicKey ecPublicKey = EllipticCurveCryptography.decodeECPublicKey(publicKeyBytes);
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(ecPublicKey);
        signature.update(dataBytes);
        return signature.verify(expectedBytes);
    }

    private KeyPairGenerator getKeyPairGenerator(String keystoreAlias) throws
        NoSuchAlgorithmException,
        InvalidAlgorithmParameterException,
        NoSuchProviderException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keystoreAlias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512, KeyProperties.DIGEST_NONE)
            .setUserAuthenticationRequired(true)
            .setKeySize(KEY_SIZE)
            .build();
        keyPairGenerator.initialize(keyGenParameterSpec);
        return keyPairGenerator;
    }
}
