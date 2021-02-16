package com.rn.ecc;

import android.content.Context;
import android.util.Log;

import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;

import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;


/**
 * Created by Jacob Gins on 6/2/2016.
 */
public class ECCModule extends ReactContextBaseJavaModule {
    private static final String KEY_TO_ALIAS_MAPPER = "key.to.alias.mapper";
    private final KeyManager keyManager;

    public ECCModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.keyManager = new KeyManager(reactContext.getSharedPreferences(KEY_TO_ALIAS_MAPPER, Context.MODE_PRIVATE));
    }

    @Override
    public String getName() {
        return "RNECC";
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put("preHash", true);
        return constants;
    }

    @ReactMethod
    public void generateECPair(ReadableMap map, Callback function) {
        try {
            String publicKey = keyManager.generateKeys();
            function.invoke(null, publicKey);
        } catch (Exception ex) {
            function.invoke(ex.toString(), null);
        }
    }

    @ReactMethod
    public void hasKey(String publicKey, Callback function) {
        function.invoke(null, keyManager.hasStoredKeysInKeystore(publicKey));
    }

    @ReactMethod
    public void sign(final ReadableMap map, final Callback function) {
        final String publicKey = map.getString("pub");

        final String message = map.getString("promptMessage");
        final String title = map.getString("promptTitle");
        final String cancel = map.getString("promptCancel");

        UiThreadUtil.runOnUiThread(
            new Runnable() {
                @Override
                public void run() {
                    try {
                        FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                        Executor executor = Executors.newSingleThreadExecutor();
                        BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor,
                            new BiometricPrompt.AuthenticationCallback() {
                                @Override
                                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult authenticationResult) {
                                    super.onAuthenticationSucceeded(authenticationResult);
                                    try {
                                        BiometricPrompt.CryptoObject cryptoObject = authenticationResult.getCryptoObject();
                                        Signature signature = cryptoObject.getSignature();
                                        String data = map.hasKey("data")
                                            ? map.getString("data")
                                            : map.getString("hash");
                                        String signedData = keyManager.sign(data, signature);
                                        function.invoke(null, signedData);
                                    } catch (Exception ex) {
                                        function.invoke(ex.toString(), null);
                                    }
                                }

                                @Override
                                public void onAuthenticationError(int errorCode, CharSequence errorCharSequence) {
                                    super.onAuthenticationError(errorCode, errorCharSequence);
                                    function.invoke(errorCharSequence.toString(), null);
                                }
                            });

                        PromptInfo promptInfo = new PromptInfo.Builder()
                            .setTitle(title)
                            .setDescription(message)
                            .setNegativeButtonText(cancel)
                            .build();

                        Signature signature = keyManager.getSignature(publicKey);
                        BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
                        biometricPrompt.authenticate(promptInfo, cryptoObject);
                    } catch (Exception ex) {
                        function.invoke(ex.toString(), null);
                    }
                }
            });

    }

    @ReactMethod
    public void verify(ReadableMap map, Callback function) {
        try {
            String data = map.hasKey("data")
                ? map.getString("data")
                : map.getString("hash");
            String publicKey = map.getString("pub");
            String expected = map.getString("sig");
            function.invoke(null, keyManager.verify(data, publicKey, expected));
        } catch (Exception ex) {
            function.invoke(ex.toString(), null);
        }
    }
}
