/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.android.keystore;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;

import com.android.identity.internal.Util;
import com.android.identity.keystore.KeystoreEngine;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.Logger;
import com.android.identity.util.Timestamp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * An implementation of {@link KeystoreEngine} using Android Keystore.
 *
 * <p>Keys created using this implementation are hardware-backed, that is the private key
 * material is designed to never leave Secure Hardware. In this context Secure Hardware
 * can mean either the TEE (Trusted Execution Environment) or an SE (Secure Element), specifically
 * anything meeting the definition of an <em>Isolated Execution Environment</em> as per
 * <a href="https://source.android.com/docs/compatibility/13/android-13-cdd#911_keys_and_credentials">
 * section 9.11 of the Android CDD</a>.
 *
 * <p>Any key created will be attested to by the Secure Hardware, using
 * <a href="https://developer.android.com/training/articles/security-key-attestation">Android
 * Keystore Key Attestation</a>. This gives remote parties (such as real-world identity credential
 * issuers) a high level of assurance that the private part of the key exists only in Secure
 * Hardware and also gives a strong signal about the general state of the device (including whether
 * <a href="https://source.android.com/docs/security/features/verifiedboot">verified boot</a>
 * is enabled, latest patch level, etc.) and which particular Android application (identified by
 * <a href="https://developer.android.com/build/configure-app-module#set_the_application_id">
 * Application Id</a>) created the key.
 *
 * <p>Curve {@link AndroidKeystore#EC_CURVE_P256} for signing using algorithm
 * {@link AndroidKeystore#ALGORITHM_ES256} is guaranteed to be implemented in
 * Secure Hardware on any Android device shipping with Android 8.1 or later. As of 2023
 * this includes nearly all Android devices.
 *
 * <p>If the device has a <a href="https://source.android.com/docs/compatibility/13/android-13-cdd#9112_strongbox">
 * StrongBox Android Keystore</a>, keys can be stored there using
 * {@link CreateKeySettings.Builder#setUseStrongBox(boolean)}.
 *
 * <p>Other optional features may be available depending on the version of the underlying
 * software (called <a href="https://source.android.com/docs/security/features/keystore">Keymint</a>)
 * running in the Secure Area. The application may examine the
 * <a href="https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_HARDWARE_KEYSTORE">
 * FEATURE_HARDWARE_KEYSTORE</a> and
 * <a href="https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_STRONGBOX_KEYSTORE">
 * FEATURE_STRONGBOX_KEYSTORE</a> to determine the KeyMint version for either
 * the normal hardware-backed keystore and - if available - the StrongBox-backed keystore.
 *
 * <p>For Keymint 1.0 (version 100 and up), ECDH is also supported when using
 * {@link AndroidKeystore#EC_CURVE_P256}. Additionally, this version also supports
 * the use of
 * <a href="https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestKeyAlias(java.lang.String)">
 * attest keys</a>.
 *
 * <p>For Keymint 2.0 (version 200 and up), curves {@link #EC_CURVE_ED25519} is available
 * for {@link #KEY_PURPOSE_SIGN} keys and curve {@link #EC_CURVE_X25519} is available for
 * {@link #KEY_PURPOSE_AGREE_KEY} keys.
 *
 * <p>If the device has a secure lock screen (either PIN, pattern, or password) this can
 * be used to protect keys using
 * {@link CreateKeySettings.Builder#setUserAuthenticationRequired(boolean, long)}.
 * The application can test for whether the lock screen is configured using
 * <a href="https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure()">
 * KeyGuardManager.isDeviceSecure()</a>.
 *
 * <p>This implementation works only on Android and requires API level 24 or later.
 */
public class AndroidKeystore implements KeystoreEngine {
    private static final String TAG = "AndroidKeystore";
    private final Context mContext;
    private final StorageEngine mStorageEngine;

    // Prefix used for storage items, the key alias follows.
    private static final String PREFIX = "IC_AndroidKeystore_";


    /**
     * Constructs a new {@link AndroidKeystore}.
     *
     * @param context the application context.
     * @param storageEngine the storage engine to use for storing metadata about keys.
     */
    public AndroidKeystore(@NonNull Context context,
                           @NonNull StorageEngine storageEngine) {
        mContext = context;
        mStorageEngine = storageEngine;
    }

    @Override
    public void createKey(@NonNull String alias,
                          @NonNull KeystoreEngine.CreateKeySettings createKeySettings) {
        CreateKeySettings aSettings = (CreateKeySettings) createKeySettings;
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            int purposes = 0;
            if ((aSettings.getKeyPurposes() & KEY_PURPOSE_SIGN) != 0) {
                purposes |= KeyProperties.PURPOSE_SIGN;
            }
            if ((aSettings.getKeyPurposes() & KEY_PURPOSE_AGREE_KEY) != 0) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    purposes |= KeyProperties.PURPOSE_AGREE_KEY;
                } else {
                    throw new IllegalArgumentException(
                            "PURPOSE_AGREE_KEY not supported on this device");
                }
            }

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, purposes);
            switch (aSettings.getEcCurve()) {
                case EC_CURVE_P256:
                    // Works with both purposes.
                    builder.setDigests(KeyProperties.DIGEST_SHA256);
                    break;

                case EC_CURVE_ED25519:
                    // Only works with KEY_PURPOSE_SIGN
                    if (aSettings.getKeyPurposes() != KEY_PURPOSE_SIGN) {
                        throw new IllegalArgumentException(
                                "Curve Ed25519 only works with KEY_PURPOSE_SIGN");
                    }
                    builder.setAlgorithmParameterSpec(new ECGenParameterSpec("ed25519"));
                    break;

                case EC_CURVE_X25519:
                    // Only works with KEY_PURPOSE_AGREE_KEY
                    if (aSettings.getKeyPurposes() != KEY_PURPOSE_AGREE_KEY) {
                        throw new IllegalArgumentException(
                                "Curve X25519 only works with KEY_PURPOSE_AGREE_KEY");
                    }
                    builder.setAlgorithmParameterSpec(new ECGenParameterSpec("x25519"));
                    break;

                case KeystoreEngine.EC_CURVE_BRAINPOOLP256R1:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP320R1:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP384R1:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP512R1:
                case KeystoreEngine.EC_CURVE_ED448:
                case KeystoreEngine.EC_CURVE_P384:
                case KeystoreEngine.EC_CURVE_P521:
                case KeystoreEngine.EC_CURVE_X448:
                default:
                    throw new IllegalArgumentException("Curve is not supported");
            }

            if (aSettings.getUserAuthenticationRequired()) {
                builder.setUserAuthenticationRequired(true);
                long timeoutMillis = aSettings.getUserAuthenticationTimeoutMillis();
                if (timeoutMillis == 0) {
                    builder.setUserAuthenticationValidityDurationSeconds(-1);
                } else {
                    int timeoutSeconds = (int) Math.max(1, timeoutMillis/1000);
                    builder.setUserAuthenticationValidityDurationSeconds(timeoutSeconds);
                }
                builder.setInvalidatedByBiometricEnrollment(false);
            }
            if (aSettings.getUseStrongBox()) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true);
                }
            }
            if (aSettings.getAttestKeyAlias() != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    builder.setAttestKeyAlias(aSettings.getAttestKeyAlias());
                }
            }
            builder.setAttestationChallenge(aSettings.getAttestationChallenge());

            if (aSettings.getValidFrom() != null) {
                Date notBefore = new Date(aSettings.getValidFrom().toEpochMilli());
                Date notAfter = new Date(aSettings.getValidUntil().toEpochMilli());
                builder.setKeyValidityStart(notBefore);
                builder.setCertificateNotBefore(notBefore);
                builder.setKeyValidityEnd(notAfter);
                builder.setCertificateNotAfter(notAfter);
            }

            try {
                kpg.initialize(builder.build());
            } catch (InvalidAlgorithmParameterException e) {
                throw new IllegalStateException("Unexpected exception", e);
            }
            kpg.generateKeyPair();

        } catch (NoSuchAlgorithmException
                 | NoSuchProviderException e) {
            throw new IllegalStateException("Error creating key", e);
        }

        List<X509Certificate> attestation = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] certificates = ks.getCertificateChain(alias);
            for (Certificate certificate : certificates) {
                attestation.add((X509Certificate) certificate);
            }
        } catch (CertificateException
                | KeyStoreException
                | IOException
                | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error generate certificate chain", e);
        }
        Logger.d(TAG, "EC key with alias '" + alias + "' created");

        saveKeyMetadata(alias, aSettings, attestation);
    }

    @Override
    public void deleteKey(@NonNull String alias) {
        KeyStore ks;
        KeyStore.Entry entry;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (!ks.containsAlias(alias)) {
                Logger.w(TAG, "Key with alias '" + alias + "' doesn't exist");
                return;
            }
            ks.deleteEntry(alias);
            mStorageEngine.delete(PREFIX + alias);
        } catch (CertificateException
                 | IOException
                 | NoSuchAlgorithmException
                 | KeyStoreException e) {
            throw new IllegalStateException("Error loading keystore", e);
        }
        Logger.d(TAG, "EC key with alias '" + alias + "' deleted");
    }

    static String getSignatureAlgorithmName(@Algorithm int signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case ALGORITHM_ES256:
                return "SHA256withECDSA";

            case ALGORITHM_ES384:
                return "SHA384withECDSA";

            case ALGORITHM_ES512:
                return "SHA512withECDSA";

            default:
                throw new IllegalArgumentException(
                        "Unsupported signing algorithm with id " + signatureAlgorithm);
        }
    }

    @Override
    public @NonNull byte[] sign(@NonNull String alias,
                                @Algorithm int signatureAlgorithm,
                                @NonNull byte[] dataToSign,
                                @Nullable KeystoreEngine.KeyUnlockData keyUnlockData)
            throws KeystoreEngine.KeyLockedException {
        if (keyUnlockData != null) {
            KeyUnlockData unlockData = (KeyUnlockData) keyUnlockData;
            if (!unlockData.mAlias.equals(alias)) {
                throw new IllegalArgumentException(
                        String.format("keyUnlockData has alias %s which differs"
                                        + " from passed-in alias %s",
                                unlockData.mAlias,
                                alias));
            }
            if (unlockData.mSignature != null) {
                if (unlockData.mSignatureAlgorithm != signatureAlgorithm) {
                    throw new IllegalArgumentException(
                            String.format("keyUnlockData has signature algorithm %d which differs"
                            + " from passed-in algorithm %d",
                                    unlockData.mSignatureAlgorithm,
                                    signatureAlgorithm));
                }
                try {
                    unlockData.mSignature.update(dataToSign);
                    return unlockData.mSignature.sign();
                } catch (SignatureException e) {
                    throw new IllegalStateException("Unexpected exception while signing", e);
                }
            }
        }

        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);
            if (entry == null) {
                throw new IllegalArgumentException("No entry for alias");
            }
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            Signature s = Signature.getInstance(getSignatureAlgorithmName(signatureAlgorithm));
            s.initSign(privateKey);
            s.update(dataToSign);
            return s.sign();
        } catch (UserNotAuthenticatedException e) {
            throw new KeyLockedException("User not authenticated", e);
        } catch (UnrecoverableEntryException
                 | CertificateException
                 | KeyStoreException
                 | IOException
                 | NoSuchAlgorithmException
                 | SignatureException e) {
            // This is a work-around for Android Keystore throwing a SignatureException
            // when it should be throwing UserNotAuthenticatedException instead. b/282174161
            //
            if (e instanceof SignatureException &&
                    ((SignatureException) e).getMessage().startsWith(
                            "android.security.KeyStoreException: Key user not authenticated")) {
                throw new KeyLockedException("User not authenticated", e);
            }
            throw new IllegalStateException("Unexpected exception while signing", e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Key does not have purpose KEY_PURPOSE_SIGN", e);
        }
    }

    @Override
    public @NonNull byte[] keyAgreement(@NonNull String alias,
                                        @NonNull PublicKey otherKey,
                                        @Nullable KeystoreEngine.KeyUnlockData keyUnlockData)
            throws KeyLockedException {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);
            if (entry == null) {
                throw new IllegalArgumentException("No entry for alias");
            }
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "AndroidKeyStore");
            ka.init(privateKey);
            ka.doPhase(otherKey, true);
            return ka.generateSecret();
        } catch (UserNotAuthenticatedException e) {
            throw new KeyLockedException("User not authenticated", e);
        } catch (UnrecoverableEntryException
                 | CertificateException
                 | KeyStoreException
                 | IOException
                 | NoSuchAlgorithmException
                 | NoSuchProviderException e) {
            throw new IllegalStateException("Unexpected exception while doing key agreement", e);
        } catch (ProviderException e) {
            // This is a work-around for Android Keystore throwing a ProviderException
            // when it should be throwing UserNotAuthenticatedException instead. b/282174161
            //
            if (e.getCause() != null
                && e.getCause().getMessage().startsWith("Key user not authenticated")) {
                throw new KeyLockedException("User not authenticated", e);
            }
            throw new IllegalStateException("Unexpected exception while doing key agreement", e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Key does not have purpose KEY_PURPOSE_AGREE_KEY", e);
        }
    }

    /**
     * A class that can be used to provide information used for unlocking a key.
     *
     * <p>Currently only user-authentication is supported.
     */
    public static class KeyUnlockData implements KeystoreEngine.KeyUnlockData {

        private Signature mSignature;
        private final String mAlias;
        private BiometricPrompt.CryptoObject mCryptoObjectForSigning;
        private @Algorithm int mSignatureAlgorithm;

        /**
         * Constructs a new object used for unlocking a key.
         *
         * @param alias the alias of the key to unlock.
         */
        public KeyUnlockData(@NonNull String alias) {
            mAlias = alias;
        }

        /**
         * Gets a {@link BiometricPrompt.CryptoObject} for signing data.
         *
         * <p>This can be used with {@link BiometricPrompt} to unlock the key.
         * On successful authentication, this object should be passed to
         * {@link AndroidKeystore#sign(String, int, byte[], KeystoreEngine.KeyUnlockData)}.
         *
         * <p>Note that a {@link BiometricPrompt.CryptoObject} is returned only if the key is
         * configured to require authentication for every use of the key, that is, when the
         * key was created with a zero timeout as per
         * {@link AndroidKeystore.CreateKeySettings.Builder#setUserAuthenticationRequired(boolean, long)}.
         *
         * @param signatureAlgorithm the signature algorithm to use.
         * @return A {@link BiometricPrompt.CryptoObject} or {@code null}.
         */
        public @Nullable BiometricPrompt.CryptoObject getCryptoObjectForSigning(@Algorithm int signatureAlgorithm) {
            if (mCryptoObjectForSigning != null) {
                return mCryptoObjectForSigning;
            }
            try {
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                KeyStore.Entry entry = ks.getEntry(mAlias, null);
                if (entry == null) {
                    throw new IllegalArgumentException("No entry for alias");
                }
                PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();

                KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
                try {
                    android.security.keystore.KeyInfo keyInfo = factory.getKeySpec(privateKey, android.security.keystore.KeyInfo.class);
                    if (keyInfo.getUserAuthenticationValidityDurationSeconds() > 0) {
                        // Key is not auth-per-op, no CryptoObject required.
                        return null;
                    }
                } catch (InvalidKeySpecException e) {
                    throw new IllegalStateException("Given key is not an Android Keystore key", e);
                }

                mSignature = Signature.getInstance(getSignatureAlgorithmName(signatureAlgorithm));
                mSignature.initSign(privateKey);
                mCryptoObjectForSigning = new BiometricPrompt.CryptoObject(mSignature);
                mSignatureAlgorithm = signatureAlgorithm;
                return mCryptoObjectForSigning;
            } catch (UnrecoverableEntryException
                     | CertificateException
                     | KeyStoreException
                     | IOException
                     | NoSuchAlgorithmException
                     | InvalidKeyException
                     | NoSuchProviderException e) {
                throw new IllegalStateException("Unexpected exception", e);
            }
        }

        /**
         * Gets a {@link BiometricPrompt.CryptoObject} for ECDH.
         *
         * <p>This can be used with {@link BiometricPrompt} to unlock the key.
         * On successful authentication, this object should be passed to
         * {@link AndroidKeystore#keyAgreement(String, PublicKey, KeystoreEngine.KeyUnlockData)}.
         *
         * <p>Note that a {@link BiometricPrompt.CryptoObject} is returned only if the key is
         * configured to require authentication for every use of the key, that is, when the
         * key was created with a zero timeout as per
         * {@link AndroidKeystore.CreateKeySettings.Builder#setUserAuthenticationRequired(boolean, long)}.
         *
         * @return A {@link BiometricPrompt.CryptoObject} or {@code null}.
         */
        public @Nullable BiometricPrompt.CryptoObject getCryptoObjectForKeyAgreement() {
            if (mCryptoObjectForSigning != null) {
                return mCryptoObjectForSigning;
            }
            try {
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                KeyStore.Entry entry = ks.getEntry(mAlias, null);
                if (entry == null) {
                    throw new IllegalArgumentException("No entry for alias");
                }
                PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();

                KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
                try {
                    android.security.keystore.KeyInfo keyInfo = factory.getKeySpec(privateKey, android.security.keystore.KeyInfo.class);
                    if (keyInfo.getUserAuthenticationValidityDurationSeconds() > 0) {
                        // Key is not auth-per-op, no CryptoObject required.
                        return null;
                    }
                } catch (InvalidKeySpecException e) {
                    throw new IllegalStateException("Given key is not an Android Keystore key", e);
                }

                // TODO: Unfortunately we forgot to add support in CryptoObject for KeyAgreement
                //  when we added ECHD to AOSP so this will not work until the platform gains
                //  support for constructing a CryptoObject from a KeyAgreement object. See
                //  b/282058146 for details.
                throw new IllegalStateException("ECDH for keys with timeout 0 is not currently supported");

            } catch (UnrecoverableEntryException
                     | CertificateException
                     | KeyStoreException
                     | IOException
                     | NoSuchAlgorithmException
                     | NoSuchProviderException e) {
                throw new IllegalStateException("Unexpected exception", e);
            }
        }
    }

    /**
     * Android Keystore specific class for information about a key.
     */
    public static class KeyInfo extends KeystoreEngine.KeyInfo {

        private final boolean mUserAuthenticationRequired;
        private final boolean mIsStrongBoxBacked;
        private final long mUserAuthenticationTimeoutMillis;
        private final String mAttestKeyAlias;
        private final Timestamp mValidFrom;
        private final Timestamp mValidUntil;

        KeyInfo(@NonNull List<X509Certificate> attestation,
                @KeyPurpose int keyPurposes,
                @EcCurve int ecCurve,
                boolean isHardwareBacked,
                @Nullable String attestKeyAlias,
                boolean userAuthenticationRequired,
                long userAuthenticationTimeoutMillis,
                boolean isStrongBoxBacked,
                @Nullable Timestamp validFrom,
                @Nullable Timestamp validUntil) {
            super(attestation, keyPurposes, ecCurve, isHardwareBacked);
            mUserAuthenticationRequired = userAuthenticationRequired;
            mUserAuthenticationTimeoutMillis = userAuthenticationTimeoutMillis;
            mIsStrongBoxBacked = isStrongBoxBacked;
            mAttestKeyAlias = attestKeyAlias;
            mValidFrom = validFrom;
            mValidUntil = validUntil;
        }

        /**
         * Gets whether the key is StrongBox based.
         *
         * @return {@code true} if StrongBox based, {@code false} otherwise.
         */
        public boolean isStrongBoxBacked() {
            return mIsStrongBoxBacked;
        }

        /**
         * Gets whether the user authentication is required to use the key.
         *
         * @return {@code true} if authentication is required, {@code false} otherwise.
         */
        public boolean isUserAuthenticationRequired() {
            return mUserAuthenticationRequired;
        }

        /**
         * Gets the timeout for user authentication.
         *
         * @return the timeout in milliseconds or 0 if user authentication is needed for
         *         every use of the key.
         */
        public long getUserAuthenticationTimeoutMillis() {
            return mUserAuthenticationTimeoutMillis;
        }

        /**
         * Gets the attest key alias for the key, if any.
         *
         * @return the attest key alias or {@code null} if no attest key is used.
         */
        public @Nullable String getAttestKeyAlias() {
            return mAttestKeyAlias;
        }

        /**
         * Gets the point in time before which the key is not valid.
         *
         * @return the point in time before which the key is not valid or {@code null} if not set.
         */
        public @Nullable Timestamp getValidFrom() {
            return mValidFrom;
        }

        /**
         * Gets the point in time after which the key is not valid.
         *
         * @return the point in time after which the key is not valid or {@code null} if not set.
         */
        public @Nullable Timestamp getValidUntil() {
            return mValidUntil;
        }
    }

    @Override
    public @NonNull KeyInfo getKeyInfo(@NonNull String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);
            if (entry == null) {
                throw new IllegalArgumentException("No entry for alias");
            }
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
            android.security.keystore.KeyInfo keyInfo = factory.getKeySpec(privateKey, android.security.keystore.KeyInfo.class);

            byte[] data = mStorageEngine.get(PREFIX + alias);
            if (data == null) {
                throw new IllegalArgumentException("No key with given alias");
            }
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            List<DataItem> dataItems;
            try {
                dataItems = new CborDecoder(bais).decode();
            } catch (CborException e) {
                throw new IllegalStateException("Error decoded CBOR", e);
            }
            if (dataItems.size() != 1) {
                throw new IllegalStateException("Expected 1 item, found " + dataItems.size());
            }
            if (!(dataItems.get(0) instanceof co.nstant.in.cbor.model.Map)) {
                throw new IllegalStateException("Item is not a map");
            }

            co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) dataItems.get(0);

            int ecCurve = (int) Util.cborMapExtractNumber(map, "curve");
            int keyPurposes = (int) Util.cborMapExtractNumber(map, "keyPurposes");
            boolean userAuthenticationRequired = Util.cborMapExtractBoolean(map, "userAuthenticationRequired");
            long userAuthenticationTimeoutMillis = Util.cborMapExtractNumber(map, "userAuthenticationTimeoutMillis");
            boolean isStrongBoxBacked = Util.cborMapExtractBoolean(map, "useStrongBox");
            String attestKeyAlias = null;
            if (Util.cborMapHasKey(map, "attestKeyAlias")) {
                attestKeyAlias = Util.cborMapExtractString(map, "attestKeyAlias");
            }
            boolean isHardwareBacked = keyInfo.isInsideSecureHardware();
            Timestamp validFrom = null;
            Timestamp validUntil = null;
            if (keyInfo.getKeyValidityStart() != null) {
                validFrom = Timestamp.ofEpochMilli(keyInfo.getKeyValidityStart().getTime());
            }
            if (keyInfo.getKeyValidityForOriginationEnd() != null) {
                validUntil = Timestamp.ofEpochMilli(keyInfo.getKeyValidityForOriginationEnd().getTime());
            }

            DataItem attestationDataItem = map.get(new UnicodeString("attestation"));
            if (!(attestationDataItem instanceof Array)) {
                throw new IllegalStateException("attestation not found or not array");
            }
            List<X509Certificate> attestation = new ArrayList<>();
            for (DataItem item : ((Array) attestationDataItem).getDataItems()) {
                byte[] encodedCert = ((ByteString) item).getBytes();
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream certBais = new ByteArrayInputStream(encodedCert);
                    attestation.add((X509Certificate) cf.generateCertificate(certBais));
                } catch (CertificateException e) {
                    throw new IllegalStateException("Error decoding certificate blob", e);
                }
            }

            return new KeyInfo(
                    attestation,
                    keyPurposes,
                    ecCurve,
                    isHardwareBacked,
                    attestKeyAlias,
                    userAuthenticationRequired,
                    userAuthenticationTimeoutMillis,
                    isStrongBoxBacked,
                    validFrom,
                    validUntil);
        } catch (UnrecoverableEntryException
                 | CertificateException
                 | KeyStoreException
                 | IOException
                 | NoSuchAlgorithmException
                 | NoSuchProviderException
                 | InvalidKeySpecException e) {
            throw new IllegalStateException("Unexpected exception", e);
        }
    }

    private void saveKeyMetadata(@NonNull String alias,
                                 @NonNull CreateKeySettings settings,
                                 @NonNull List<X509Certificate> attestation) {
        CborBuilder builder = new CborBuilder();
        MapBuilder<CborBuilder> map = builder.addMap();
        map.put("curve", settings.getEcCurve());
        map.put("keyPurposes", settings.getKeyPurposes());
        String attestKeyAlias = settings.getAttestKeyAlias();
        if (attestKeyAlias != null) {
            map.put("attestKeyAlias", attestKeyAlias);
        }
        map.put("userAuthenticationRequired", settings.getUserAuthenticationRequired());
        map.put("userAuthenticationTimeoutMillis", settings.getUserAuthenticationTimeoutMillis());
        map.put("useStrongBox", settings.getUseStrongBox());

        ArrayBuilder<MapBuilder<CborBuilder>> attestationBuilder = map.putArray("attestation");
        for (X509Certificate certificate : attestation) {
            try {
                attestationBuilder.add(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Error encoding certificate chain", e);
            }
        }
        attestationBuilder.end();

        mStorageEngine.put(PREFIX + alias, Util.cborEncode(builder.build().get(0)));
    }

    /**
     * Class for holding Android Keystore-specific settings related to key creation.
     */
    public static class CreateKeySettings extends KeystoreEngine.CreateKeySettings {
        private final @KeyPurpose int mKeyPurposes;
        private final @EcCurve int mEcCurve;
        private final byte[] mAttestationChallenge;
        private final boolean mUserAuthenticationRequired;
        private final long mUserAuthenticationTimeoutMillis;
        private final boolean mUseStrongBox;
        private final String mAttestKeyAlias;
        private final Timestamp mValidFrom;
        private final Timestamp mValidUntil;

        private CreateKeySettings(@KeyPurpose int keyPurpose,
                                  @EcCurve int ecCurve,
                                  @NonNull byte[] attestationChallenge,
                                  boolean userAuthenticationRequired,
                                  long userAuthenticationTimeoutMillis,
                                  boolean useStrongBox,
                                  @Nullable String attestKeyAlias,
                                  @Nullable Timestamp validFrom,
                                  @Nullable Timestamp validUntil) {
            super(AndroidKeystore.class);
            mKeyPurposes = keyPurpose;
            mEcCurve = ecCurve;
            mAttestationChallenge = attestationChallenge;
            mUserAuthenticationRequired = userAuthenticationRequired;
            mUserAuthenticationTimeoutMillis = userAuthenticationTimeoutMillis;
            mUseStrongBox = useStrongBox;
            mAttestKeyAlias = attestKeyAlias;
            mValidFrom = validFrom;
            mValidUntil = validUntil;
        }

        /**
         * Gets the attestation challenge.
         *
         * @return the attestation challenge.
         */
        public @NonNull byte[] getAttestationChallenge() {
            return mAttestationChallenge;
        }

        /**
         * Gets whether user authentication is required.
         *
         * @return whether user authentication is required.
         */
        public boolean getUserAuthenticationRequired() {
            return mUserAuthenticationRequired;
        }

        /**
         * Gets user authentication timeout, if any.
         *
         * @return timeout in milliseconds, or 0 if authentication is required on every use.
         */
        public long getUserAuthenticationTimeoutMillis() {
            return mUserAuthenticationTimeoutMillis;
        }

        /**
         * Gets whether StrongBox is used.
         *
         * @return whether StrongBox is used.
         */
        public boolean getUseStrongBox() {
            return mUseStrongBox;
        }

        /**
         * Gets the attest key alias, if any.
         *
         * @return the attest key alias or {@code null} if an attest key is not used.
         */
        public @Nullable String getAttestKeyAlias() {
            return mAttestKeyAlias;
        }

        /**
         * Gets the key purposes.
         *
         * @return the key purposes.
         */
        public @KeyPurpose int getKeyPurposes() {
            return mKeyPurposes;
        }

        /**
         * Gets the curve used.
         *
         * @return the curve used.
         */
        public @EcCurve int getEcCurve() {
            return mEcCurve;
        }

        /**
         * Gets the point in time before which the key is not valid.
         *
         * @return the point in time before which the key is not valid or {@code null} if not set.
         */
        public @Nullable Timestamp getValidFrom() {
            return mValidFrom;
        }

        /**
         * Gets the point in time after which the key is not valid.
         *
         * @return the point in time after which the key is not valid or {@code null} if not set.
         */
        public @Nullable Timestamp getValidUntil() {
            return mValidUntil;
        }

        /**
         * A builder for {@link CreateKeySettings}.
         */
        public static class Builder {
            private @KeyPurpose int mKeyPurposes = KEY_PURPOSE_SIGN;
            private @EcCurve int mEcCurve = EC_CURVE_P256;
            private final byte[] mAttestationChallenge;
            private boolean mUserAuthenticationRequired;
            private long mUserAuthenticationTimeoutMillis;
            private boolean mUseStrongBox;
            private String mAttestKeyAlias;
            private Timestamp mValidFrom;
            private Timestamp mValidUntil;

            /**
             * Constructor.
             *
             * @param attestationChallenge challenge to include in attestation for the key.
             */
            public Builder(@NonNull byte[] attestationChallenge) {
                mAttestationChallenge = attestationChallenge;
            }

            /**
             * Sets the key purpose.
             *
             * <p>By default the key purpose is {@link AndroidKeystore#KEY_PURPOSE_SIGN}.
             *
             * @param keyPurposes one or more purposes.
             * @return the builder.
             * @throws IllegalArgumentException if no purpose is set.
             */
            public @NonNull CreateKeySettings.Builder setKeyPurposes(@KeyPurpose int keyPurposes) {
                if (keyPurposes == 0) {
                    throw new IllegalArgumentException("Purpose cannot be empty");
                }
                mKeyPurposes = keyPurposes;
                return this;
            }

            /**
             * Sets the curve to use for EC keys.
             *
             * <p>By default {@link AndroidKeystore#EC_CURVE_P256} is used.
             *
             * @param curve the curve to use.
             * @return the builder.
             */
            public @NonNull CreateKeySettings.Builder setEcCurve(@EcCurve int curve) {
                mEcCurve = curve;
                return this;
            }

            /**
             * Method to specify if user authentication is required to use the key.
             *
             * <p>By default, no user authentication is required.
             *
             * @param required True if user authentication is required, false otherwise.
             * @param timeoutMillis If 0, user authentication is required for every use of
             *                      the key, otherwise it's required within the given amount
             *                      of milliseconds.
             * @return the builder.
             */
            public @NonNull Builder setUserAuthenticationRequired(boolean required, long timeoutMillis) {
                mUserAuthenticationRequired = required;
                mUserAuthenticationTimeoutMillis = timeoutMillis;
                return this;
            }

            /**
             * Method to specify if StrongBox Android Keystore should be used, if available.
             *
             * By default StrongBox isn't used.
             *
             * @param useStrongBox Whether to use StrongBox.
             * @return the builder.
             */
            public @NonNull Builder setUseStrongBox(boolean useStrongBox) {
                mUseStrongBox = useStrongBox;
                return this;
            }

            /**
             * Method to specify if an attest key should be used.
             *
             * <p>By default no attest key is used. See
             * <a href="https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestKeyAlias(java.lang.String)">setAttestKeyAlias() method</a>
             * for more information about attest keys.
             *
             * @param attestKeyAlias the Android Keystore alias of the attest key or {@code null} to not use an attest key.
             * @return the builder.
             */
            public @NonNull Builder setAttestKeyAlias(@Nullable String attestKeyAlias) {
                mAttestKeyAlias = attestKeyAlias;
                return this;
            }

            /**
             * Sets the key validity period.
             *
             * <p>By default the key validity period is unbounded.
             *
             * @param validFrom the point in time before which the key is not valid.
             * @param validUntil the point in time after which the key is not valid.
             * @return the builder.
             */
            public @NonNull Builder setValidityPeriod(@NonNull Timestamp validFrom,
                                                      @NonNull Timestamp validUntil) {
                mValidFrom = validFrom;
                mValidUntil = validUntil;
                return this;
            }

            /**
             * Builds the {@link CreateKeySettings}.
             *
             * @return a new {@link CreateKeySettings}.
             */
            public @NonNull CreateKeySettings build() {
                return new CreateKeySettings(
                        mKeyPurposes,
                        mEcCurve,
                        mAttestationChallenge,
                        mUserAuthenticationRequired,
                        mUserAuthenticationTimeoutMillis,
                        mUseStrongBox,
                        mAttestKeyAlias,
                        mValidFrom,
                        mValidUntil);
            }
        }

    }
}
