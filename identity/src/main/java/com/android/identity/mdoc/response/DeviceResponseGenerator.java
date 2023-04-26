/*
 * Copyright 2022 The Android Open Source Project
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

package com.android.identity.mdoc.response;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.identity.credential.Credential;
import com.android.identity.credential.CredentialRequest;
import com.android.identity.keystore.KeystoreEngine;
import com.android.identity.credential.NameSpacedData;
import com.android.identity.util.Constants;
import com.android.identity.internal.Util;
import com.android.identity.util.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * Helper class for building <code>DeviceResponse</code> <a href="http://cbor.io/">CBOR</a>
 * as specified in <em>ISO/IEC 18013-5</em> section 8.3 <em>Device Retrieval</em>.
 */
public final class DeviceResponseGenerator {
    private static final String TAG = "DeviceResponseGenerator";
    private final ArrayBuilder<CborBuilder> mDocumentsBuilder;
    @Constants.DeviceResponseStatus private final long mStatusCode;

    /**
     * Creates a new {@link DeviceResponseGenerator}.
     *
     * @param statusCode the status code to use which must be one of
     * {@link Constants#DEVICE_RESPONSE_STATUS_OK},
     * {@link Constants#DEVICE_RESPONSE_STATUS_GENERAL_ERROR},
     * {@link Constants#DEVICE_RESPONSE_STATUS_CBOR_DECODING_ERROR}, or
     * {@link Constants#DEVICE_RESPONSE_STATUS_CBOR_VALIDATION_ERROR}.
     */
    public DeviceResponseGenerator(@Constants.DeviceResponseStatus long statusCode) {
        mStatusCode = statusCode;
        mDocumentsBuilder = new CborBuilder().addArray();
    }

    /**
     * Adds a new document to the device response.
     *
     * <p>Issuer-signed data is provided in <code>issuerSignedData</code> which
     * maps from namespaces into a list of bytes of IssuerSignedItem CBOR as
     * defined in 18013-5 where each contains the digest-id, element name,
     * issuer-generated random value and finally the element value. Each IssuerSignedItem
     * must be encoded so the digest of them in a #6.24 bstr matches with the digests in
     * the <code>MobileSecurityObject</code> in the <code>issuerAuth</code> parameter.
     *
     * <p>The <code>encodedIssuerAuth</code> parameter contains the bytes of the
     * <code>IssuerAuth</code> CBOR as defined in <em>ISO/IEC 18013-5</em>
     * section 9.1.2.4 <em>Signing method and structure for MSO</em>. That is,
     * the payload for this <code>COSE_Sign1</code> must be set to the
     * <code>MobileSecurityObjectBytes</code> and the public key used to
     * sign the payload must be included in a <code>x5chain</code> unprotected
     * header element.
     *
     * <p>For device-signed data, the parameters <code>encodedDeviceNamespaces</code>,
     * <code>encodedDeviceSignature</code>, and <code>encodedDeviceMac</code> are
     * used. Of the latter two, exactly one of them must be non-<code>null</code>.
     * The <code>DeviceNameSpaces</code> CBOR specified in <em>ISO/IEC 18013-5</em>
     * section 8.3.2.1 <em>Device retrieval</em> is to be set in
     * <code>encodedDeviceNamespaces</code>, and either a ECDSA signature or a MAC
     * over the <code>DeviceAuthentication</code> CBOR as defined in section 9.1.3
     * <em>mdoc authentication</em> should be set in <code>encodedDeviceSignature</code>
     * or <code>encodedDeviceMac</code> respectively. Values for all parameters can be
     * obtained from the <code>ResultData</code> class from either the Framework
     * or this library.
     *
     * <p>If present, the <code>errors</code> parameter is a map from namespaces where each
     * value is a map from data elements in said namespace to an error code from
     * ISO/IEC 18013-5:2021 Table 9.
     *
     * @param docType the document type, for example <code>org.iso.18013.5.1.mDL</code>.
     * @param encodedDeviceNamespaces bytes of the <code>DeviceNameSpaces</code> CBOR.
     * @param encodedDeviceSignature bytes of a COSE_Sign1 for authenticating the device data.
     * @param encodedDeviceMac bytes of a COSE_Mac0 for authenticating the device data.
     * @param issuerSignedData the map described above.
     * @param errors a map with errors as described above.
     * @param encodedIssuerAuth the bytes of the <code>COSE_Sign1</code> described above.
     * @return the passed-in {@link DeviceResponseGenerator}.
     */
    public @NonNull DeviceResponseGenerator addDocument(@NonNull String docType,
            @NonNull byte[] encodedDeviceNamespaces,
            @Nullable byte[] encodedDeviceSignature,
            @Nullable byte[] encodedDeviceMac,
            @NonNull Map<String, List<byte[]>> issuerSignedData,
            @Nullable Map<String, Map<String, Long>> errors,
            @NonNull byte[] encodedIssuerAuth) {

        CborBuilder issuerNameSpacesBuilder = new CborBuilder();
        MapBuilder<CborBuilder> insOuter = issuerNameSpacesBuilder.addMap();
        for (String ns : issuerSignedData.keySet()) {
            ArrayBuilder<MapBuilder<CborBuilder>> insInner = insOuter.putArray(ns);
            for (byte[] encodedIssuerSignedItem : issuerSignedData.get(ns)) {
                // We'll do the #6.24 wrapping here.
                insInner.add(Util.cborBuildTaggedByteString(encodedIssuerSignedItem));
            }
            insInner.end();
        }
        insOuter.end();

        DataItem issuerSigned = new CborBuilder()
                .addMap()
                .put(new UnicodeString("nameSpaces"), issuerNameSpacesBuilder.build().get(0))
                .put(new UnicodeString("issuerAuth"), Util.cborDecode(encodedIssuerAuth))
                .end()
                .build().get(0);

        String deviceAuthType = "";
        DataItem deviceAuthDataItem = null;
        if (encodedDeviceSignature != null && encodedDeviceMac != null) {
            throw new IllegalArgumentException("Cannot specify both Signature and MAC");
        } else if (encodedDeviceSignature != null) {
            deviceAuthType = "deviceSignature";
            deviceAuthDataItem = Util.cborDecode(encodedDeviceSignature);
        } else if (encodedDeviceMac != null) {
            deviceAuthType = "deviceMac";
            deviceAuthDataItem = Util.cborDecode(encodedDeviceMac);
        } else {
            throw new IllegalArgumentException("No authentication mechanism used");
        }

        DataItem deviceSigned = new CborBuilder()
                .addMap()
                .put(new UnicodeString("nameSpaces"),
                        Util.cborBuildTaggedByteString(encodedDeviceNamespaces))
                .putMap("deviceAuth")
                .put(new UnicodeString(deviceAuthType), deviceAuthDataItem)
                .end()
                .end()
                .build().get(0);

        CborBuilder builder = new CborBuilder();
        MapBuilder<CborBuilder> mapBuilder = builder.addMap();
        mapBuilder.put("docType", docType);
        mapBuilder.put(new UnicodeString("issuerSigned"), issuerSigned);
        mapBuilder.put(new UnicodeString("deviceSigned"), deviceSigned);
        if (errors != null) {
            CborBuilder errorsBuilder = new CborBuilder();
            MapBuilder<CborBuilder> errorsOuterMapBuilder = errorsBuilder.addMap();
            for (String namespaceName : errors.keySet()) {
                MapBuilder<MapBuilder<CborBuilder>> errorsInnerMapBuilder =
                        errorsOuterMapBuilder.putMap(namespaceName);
                Map<String, Long> innerMap = errors.get(namespaceName);
                for (String dataElementName : innerMap.keySet()) {
                    long value = innerMap.get(dataElementName).longValue();
                    errorsInnerMapBuilder.put(dataElementName, value);
                }
            }
            mapBuilder.put(new UnicodeString("errors"), errorsBuilder.build().get(0));
        }
        mDocumentsBuilder.add(builder.build().get(0));
        return this;
    }

    private static class DecodedStaticAuthData {
        private DecodedStaticAuthData(@NonNull Map<String, List<byte[]>> digestIdMapping,
                                      @NonNull byte[] encodedIssuerAuth) {
            this.digestIdMapping = digestIdMapping;
            this.encodedIssuerAuth = encodedIssuerAuth;
        }
        Map<String, List<byte[]>> digestIdMapping;
        byte[] encodedIssuerAuth;
    }

    // TODO: Replace with StaticAuthDataParser once Issue 284 is resolved.
    private static @NonNull
    DecodedStaticAuthData
    decodeStaticAuthData(@NonNull byte[] staticAuthData) {
        DataItem topMapItem = Util.cborDecode(staticAuthData);
        if (!(topMapItem instanceof co.nstant.in.cbor.model.Map)) {
            throw new IllegalArgumentException("Top-level is not a map");
        }
        co.nstant.in.cbor.model.Map topMap = (co.nstant.in.cbor.model.Map) topMapItem;
        DataItem issuerAuthItem = topMap.get(new UnicodeString("issuerAuth"));
        if (issuerAuthItem == null) {
            throw new IllegalArgumentException("issuerAuth item does not exist");
        }
        byte[] encodedIssuerAuth = Util.cborEncode(issuerAuthItem);

        Map<String, List<byte[]>> buildOuterMap = new HashMap<>();

        DataItem outerMapItem = topMap.get(new UnicodeString("digestIdMapping"));
        if (!(outerMapItem instanceof co.nstant.in.cbor.model.Map)) {
            throw new IllegalArgumentException(
                    "digestIdMapping value is not a map or does not exist");
        }
        co.nstant.in.cbor.model.Map outerMap = (co.nstant.in.cbor.model.Map) outerMapItem;
        for (DataItem outerKey : outerMap.getKeys()) {
            if (!(outerKey instanceof UnicodeString)) {
                throw new IllegalArgumentException("Outer key is not a string");
            }
            String ns = ((UnicodeString) outerKey).getString();

            List<byte[]> buildInnerArray = new ArrayList<>();
            buildOuterMap.put(ns, buildInnerArray);

            DataItem outerValue = outerMap.get(outerKey);
            if (!(outerValue instanceof co.nstant.in.cbor.model.Array)) {
                throw new IllegalArgumentException("Outer value is not an array");
            }
            co.nstant.in.cbor.model.Array innerArray = (co.nstant.in.cbor.model.Array) outerValue;
            for (DataItem innerKey : innerArray.getDataItems()) {
                if (!(innerKey instanceof ByteString)) {
                    throw new IllegalArgumentException("Inner key is not a bstr");
                }
                if (innerKey.getTag().getValue() != 24) {
                    throw new IllegalArgumentException("Inner key does not have tag 24");
                }
                byte[] encodedIssuerSignedItemBytes = ((ByteString) innerKey).getBytes();

                // Strictly not necessary but check that elementValue is NULL. This is to
                // avoid applications (or issuers) sending the value in issuerSignedMapping
                // which is part of staticAuthData. This would be bad because then the
                // data element value would be available without any access control checks.
                //
                DataItem issuerSignedItem = Util.cborExtractTaggedAndEncodedCbor(innerKey);
                DataItem value = Util.cborMapExtract(issuerSignedItem, "elementValue");
                if (!(value instanceof SimpleValue)
                        || ((SimpleValue) value).getSimpleValueType() != SimpleValueType.NULL) {
                    String name = Util.cborMapExtractString(issuerSignedItem, "elementIdentifier");
                    throw new IllegalArgumentException("elementValue for nameSpace " + ns
                            + " elementName " + name + " is not NULL");
                }

                buildInnerArray.add(
                        Util.cborEncode(Util.cborBuildTaggedByteString(encodedIssuerSignedItemBytes)));
            }
        }
        return new DecodedStaticAuthData(buildOuterMap, encodedIssuerAuth);
    }

    private static @NonNull
    Map<String, Map<String, byte[]>> calcIssuerSignedItemMap(
            @NonNull  Map<String, List<byte[]>> issuerNameSpaces) {
        Map<String, Map<String, byte[]>> ret = new LinkedHashMap<>();
        for (String nameSpaceName : issuerNameSpaces.keySet()) {
            Map<String, byte[]> innerMap = new LinkedHashMap<>();
            for (byte[] encodedIssuerSignedItemBytes : issuerNameSpaces.get(nameSpaceName)) {
                byte[] encodedIssuerSignedItem = Util.cborExtractTaggedCbor(encodedIssuerSignedItemBytes);
                DataItem map = Util.cborDecode(encodedIssuerSignedItem);
                String elementIdentifier = Util.cborMapExtractString(map, "elementIdentifier");
                innerMap.put(elementIdentifier, encodedIssuerSignedItem);
            }
            ret.put(nameSpaceName, innerMap);
        }
        return ret;
    }

    private static @Nullable
    byte[] lookupIssuerSignedMap(@NonNull Map<String, Map<String, byte[]>> issuerSignedMap,
                                 @NonNull String nameSpaceName,
                                 @NonNull String dataElementName) {
        Map<String, byte[]> innerMap = issuerSignedMap.get(nameSpaceName);
        if (innerMap == null) {
            return null;
        }
        return innerMap.get(dataElementName);
    }

    private @NonNull
    DeviceResponseGenerator addDocumentResponse(
            @NonNull CredentialRequest request,
            @NonNull Credential credential,
            @NonNull String docType,
            @NonNull byte[] encodedSessionTranscript,
            @Nullable NameSpacedData deviceSignedData,
            @NonNull Credential.AuthenticationKey authenticationKey,
            @Nullable KeystoreEngine.KeyUnlockData keyUnlockData,
            @KeystoreEngine.Algorithm int signatureAlgorithm,
            @NonNull PublicKey eReaderKey)
            throws KeystoreEngine.KeyLockedException {

        DecodedStaticAuthData decodedStaticAuthData = decodeStaticAuthData(
                authenticationKey.getIssuerProvidedData());

        Map<String, Map<String, byte[]>> issuerSignedItemMap =
                calcIssuerSignedItemMap(decodedStaticAuthData.digestIdMapping);

        NameSpacedData credentialData = credential.getNameSpacedData();

        Map<String, List<byte[]>> issuerSignedData = new LinkedHashMap<>();
        for (CredentialRequest.DataElement element : request.getRequestedDataElements()) {
            if (element.getIgnored()) {
                continue;
            }
            String nameSpaceName = element.getNameSpaceName();
            String dataElementName = element.getDataElementName();
            if (!credentialData.hasDataElement(nameSpaceName, dataElementName)) {
                Logger.w(TAG, "No data element in credential for nameSpace "
                        + nameSpaceName + " dataElementName " + dataElementName);
                continue;
            }
            byte[] value = credentialData.getDataElement(nameSpaceName, dataElementName);

            byte[] encodedIssuerSignedItemWithoutValue =
                    lookupIssuerSignedMap(issuerSignedItemMap, nameSpaceName, dataElementName);
            if (encodedIssuerSignedItemWithoutValue == null) {
                Logger.w(TAG, "No IssuerSignedItem for " + nameSpaceName + " " + dataElementName);
                continue;
            }

            byte[] encodedIssuerSignedItem = Util.issuerSignedItemSetValue(encodedIssuerSignedItemWithoutValue, value);

            List<byte[]> list = issuerSignedData.computeIfAbsent(element.getNameSpaceName(), k -> new ArrayList<>());
            list.add(encodedIssuerSignedItem);
        }

        CborBuilder deviceNameSpacesBuilder = new CborBuilder();
        MapBuilder<CborBuilder> mapBuilder = deviceNameSpacesBuilder.addMap();
        if (deviceSignedData != null) {
            for (String nameSpaceName : deviceSignedData.getNameSpaceNames()) {
                MapBuilder<MapBuilder<CborBuilder>> nsBuilder = mapBuilder.putMap(nameSpaceName);
                for (String dataElementName : deviceSignedData.getDataElementNames(nameSpaceName)) {
                    nsBuilder.put(
                            new UnicodeString(dataElementName),
                            Util.cborDecode(deviceSignedData.getDataElement(nameSpaceName, dataElementName)));
                }
            }
        }
        mapBuilder.end();
        byte[] encodedDeviceNameSpaces = Util.cborEncode(deviceNameSpacesBuilder.build().get(0));

        byte[] deviceAuthentication = Util.cborEncode(new CborBuilder()
                .addArray()
                .add("DeviceAuthentication")
                .add(Util.cborDecode(encodedSessionTranscript))
                .add(docType)
                .add(Util.cborBuildTaggedByteString(encodedDeviceNameSpaces))
                .end()
                .build().get(0));

        byte[] deviceAuthenticationBytes =
                Util.cborEncode(Util.cborBuildTaggedByteString(deviceAuthentication));

        byte[] encodedDeviceSignature = null;
        byte[] encodedDeviceMac = null;
        if (signatureAlgorithm != KeystoreEngine.ALGORITHM_UNSET) {
            encodedDeviceSignature = Util.cborEncode(Util.coseSign1Sign(
                    authenticationKey.getKeystoreEngine(),
                    authenticationKey.getAlias(),
                    signatureAlgorithm,
                    keyUnlockData,
                    null,
                    deviceAuthenticationBytes,
                    null));
        } else {
            byte[] sharedSecret = authenticationKey.getKeystoreEngine()
                    .keyAgreement(authenticationKey.getAlias(),
                            eReaderKey,
                            keyUnlockData);

            byte[] sessionTranscriptBytes =
                    Util.cborEncode(Util.cborBuildTaggedByteString(encodedSessionTranscript));

            byte[] salt;
            try {
                salt = MessageDigest.getInstance("SHA-256").digest(sessionTranscriptBytes);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Unexpected exception", e);
            }
            byte[] info = "EMacKey".getBytes(StandardCharsets.UTF_8);
            byte[] derivedKey = Util.computeHkdf("HmacSha256", sharedSecret, salt, info, 32);
            SecretKey secretKey = new SecretKeySpec(derivedKey, "");

            encodedDeviceMac = Util.cborEncode(
                    Util.coseMac0(secretKey,
                            new byte[0],                 // payload
                            deviceAuthenticationBytes));  // detached content
        }

        return addDocument(docType,
                encodedDeviceNameSpaces,
                encodedDeviceSignature,
                encodedDeviceMac,
                issuerSignedData,
                null,
                decodedStaticAuthData.encodedIssuerAuth);
    }

    /**
     * Adds a credential presentation to the device response being built.
     *
     * <p>This builds up {@code Document} CBOR as specified in ISO/IEC 18013-5
     * section 8.3.2.1.2.2. The {@code request} parameter is used to specify
     * the data elements to select from the given {@code credential} parameter
     * and if present in the credential, the value will be included as an
     * issuer-signed data element. The credential must have its issuer-provided
     * data in a format that conforms with the CDDL defined in
     * {@link StaticAuthData}. Device-signed data elements to include can
     * be set in the {@code deviceSignedData} parameter
     *
     * <p>This uses <em>mdoc ECDSA / EdDSA Authentication</em> as defined
     * in ISO/IEC 18013-5 section 9.1.3.6. To use <em>mdoc MAC Authentication</em>
     * authentication, see
     * {@link #addDocumentResponseWithMdocMacAuthentication(CredentialRequest, Credential, String, byte[], NameSpacedData, Credential.AuthenticationKey, KeystoreEngine.KeyUnlockData, PublicKey)}.
     *
     * @param request an object describing which data elements to include in the response.
     * @param credential the credential to use for retrieving the data elements.
     * @param docType the document type.
     * @param deviceSignedData data elements to include in {@code DeviceSigned} or {@code null}.
     * @param encodedSessionTranscript the bytes of the {@code SessionTranscript} CBOR.
     * @param authenticationKey the key to use for producing {@code DeviceAuth} CBOR.
     * @param keyUnlockData data used for unlocking the key or {@code null} if not needed.
     * @param signatureAlgorithm the signature algorithm to use.
     * @return the generator.
     * @throws KeystoreEngine.KeyLockedException if the key is locked.
     */
    public @NonNull
    DeviceResponseGenerator addDocumentResponseWithMdocSignatureAuthentication(
            @NonNull CredentialRequest request,
            @NonNull Credential credential,
            @NonNull String docType,
            @NonNull byte[] encodedSessionTranscript,
            @Nullable NameSpacedData deviceSignedData,
            @NonNull Credential.AuthenticationKey authenticationKey,
            @Nullable KeystoreEngine.KeyUnlockData keyUnlockData,
            @KeystoreEngine.Algorithm int signatureAlgorithm)
            throws KeystoreEngine.KeyLockedException {
        return addDocumentResponse(request,
                credential,
                docType,
                encodedSessionTranscript,
                deviceSignedData,
                authenticationKey,
                keyUnlockData,
                signatureAlgorithm,
                null);
    }

    /**
     * Adds a credential presentation to the device response being built.
     *
     * <p>Like<
     * {@link #addDocumentResponseWithMdocSignatureAuthentication(CredentialRequest, Credential, String, byte[], NameSpacedData, Credential.AuthenticationKey, KeystoreEngine.KeyUnlockData, int)}
     * but uses <em>mdoc MAC Authentication</em> as defined
     * in ISO/IEC 18013-5 section 9.1.3.5 instead of <em>mdoc ECDSA / EdDSA Authentication</em>.
     *
     * <p>Note that for this to work, the passed-in {@code eReaderKey} and {@code authenticationKey}
     * must use the same curve.
     *
     * @param request an object describing which data elements to include in the response.
     * @param credential the credential to use for retrieving the data elements.
     * @param docType the document type.
     * @param deviceSignedData data elements to include in {@code DeviceSigned} or {@code null}.
     * @param encodedSessionTranscript the bytes of the {@code SessionTranscript} CBOR.
     * @param authenticationKey the key to use for producing {@code DeviceAuth} CBOR.
     * @param keyUnlockData data used for unlocking the key or {@code null} if not needed.
     * @param eReaderKey the ephemeral reader key.
     * @return the generator.
     * @throws KeystoreEngine.KeyLockedException if the key is locked.
     */
    public @NonNull
    DeviceResponseGenerator addDocumentResponseWithMdocMacAuthentication(
            @NonNull CredentialRequest request,
            @NonNull Credential credential,
            @NonNull String docType,
            @NonNull byte[] encodedSessionTranscript,
            @Nullable NameSpacedData deviceSignedData,
            @NonNull Credential.AuthenticationKey authenticationKey,
            @Nullable KeystoreEngine.KeyUnlockData keyUnlockData,
            @NonNull PublicKey eReaderKey)
            throws KeystoreEngine.KeyLockedException {
        return addDocumentResponse(request,
                credential,
                docType,
                encodedSessionTranscript,
                deviceSignedData,
                authenticationKey,
                keyUnlockData,
                KeystoreEngine.ALGORITHM_UNSET,
                eReaderKey);
    }

    /**
     * Builds the <code>DeviceResponse</code> CBOR.
     *
     * @return the bytes of <code>DeviceResponse</code> CBOR.
     */
    public @NonNull byte[] generate() {
        CborBuilder deviceResponseBuilder = new CborBuilder();
        MapBuilder<CborBuilder> mapBuilder = deviceResponseBuilder.addMap();
        mapBuilder.put("version", "1.0");
        mapBuilder.put(new UnicodeString("documents"), mDocumentsBuilder.end().build().get(0));
        // TODO: The documentErrors map entry should only be present if there is a non-zero
        //  number of elements in the array. Right now we don't have a way for the application
        //  to convey document errors but when we add that API we'll need to do something so
        //  it is included here.
        mapBuilder.put("status", mStatusCode);
        mapBuilder.end();

        return Util.cborEncode(deviceResponseBuilder.build().get(0));
    }
}
