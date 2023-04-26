package com.android.identity.mdoc.util;

import androidx.annotation.NonNull;

import com.android.identity.TestVectors;
import com.android.identity.internal.Util;
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator;
import com.android.identity.mdoc.mso.MobileSecurityObjectParser;
import com.android.identity.mdoc.response.DeviceResponseGenerator;
import com.android.identity.mdoc.response.DeviceResponseParser;
import com.android.identity.keystore.BouncyCastleKeystore;
import com.android.identity.credential.Credential;
import com.android.identity.credential.CredentialRequest;
import com.android.identity.credential.CredentialStore;
import com.android.identity.storage.EphemeralStorageEngine;
import com.android.identity.keystore.KeystoreEngine;
import com.android.identity.keystore.KeystoreEngineRepository;
import com.android.identity.credential.NameSpacedData;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.CborUtil;
import com.android.identity.util.Timestamp;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.UnicodeString;

public class MdocUtilTest {

    private static final String TAG = "MdocUtilTest";
    StorageEngine mStorageEngine;

    KeystoreEngine mKeystoreEngine;

    KeystoreEngineRepository mKeystoreEngineRepository;

    @Before
    public void setup() {
        mStorageEngine = new EphemeralStorageEngine();

        mKeystoreEngineRepository = new KeystoreEngineRepository();
        mKeystoreEngine = new BouncyCastleKeystore(mStorageEngine);
        mKeystoreEngineRepository.addImplementation(mKeystoreEngine);
    }

    private static KeyPair generateIssuingAuthorityKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec);
        return kpg.generateKeyPair();
    }


    private static X509Certificate getSelfSignedIssuerAuthorityCertificate(
            KeyPair issuerAuthorityKeyPair) throws Exception {
        X500Name issuer = new X500Name("CN=State Of Utopia");
        X500Name subject = new X500Name("CN=State Of Utopia Issuing Authority Signing Key");

        // Valid from now to five years from now.
        Date now = new Date();
        final long kMilliSecsInOneYear = 365L * 24 * 60 * 60 * 1000;
        Date expirationDate = new Date(now.getTime() + 5 * kMilliSecsInOneYear);
        BigInteger serial = new BigInteger("42");
        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer,
                        serial,
                        now,
                        expirationDate,
                        subject,
                        issuerAuthorityKeyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(issuerAuthorityKeyPair.getPrivate());

        X509CertificateHolder certHolder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public static @NonNull
    byte[] generateStaticAuthData(
            @NonNull Map<String, List<byte[]>> issuerNameSpaces,
            @NonNull byte[] encodedIssuerAuth) {

        CborBuilder builder = new CborBuilder();
        MapBuilder<CborBuilder> outerBuilder = builder.addMap();
        for (Map.Entry<String, List<byte[]>> oe : issuerNameSpaces.entrySet()) {
            String ns = oe.getKey();
            ArrayBuilder<MapBuilder<CborBuilder>> innerBuilder = outerBuilder.putArray(ns);
            for (byte[] encodedIssuerSignedItem : oe.getValue()) {
                DataItem issuerSignedItemBytes = Util.cborDecode(encodedIssuerSignedItem);
                DataItem issuerSignedItem = Util.cborExtractTaggedAndEncodedCbor(issuerSignedItemBytes);

                // Ensure that elementValue is NULL to avoid applications or issuers that send
                // the raw DataElementValue in the IssuerSignedItem. If we allowed non-NULL
                // values, then PII would be exposed that would otherwise be guarded by
                // access control checks.
                DataItem value = Util.cborMapExtract(issuerSignedItem, "elementValue");
                if (!(value instanceof SimpleValue)
                        || ((SimpleValue) value).getSimpleValueType() != SimpleValueType.NULL) {
                    String name = Util.cborMapExtractString(issuerSignedItem, "elementIdentifier");
                    throw new IllegalArgumentException("elementValue for nameSpace " + ns
                            + " elementName " + name + " is not NULL");
                }
                innerBuilder.add(issuerSignedItemBytes);
            }
        }
        DataItem digestIdMappingItem = builder.build().get(0);

        byte[] staticAuthData = Util.cborEncode(new CborBuilder()
                .addMap()
                .put(new UnicodeString("digestIdMapping"), digestIdMappingItem)
                .put(new UnicodeString("issuerAuth"), Util.cborDecode(encodedIssuerAuth))
                .end()
                .build().get(0));
        return staticAuthData;
    }


    @Test
    public void testGenerateDeviceResponse() throws Exception {
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        final String DOC_TYPE = "com.example.credential_xyz";

        // Create the credential...
        Credential credential = credentialStore.createCredential(
                "testCredential",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        NameSpacedData nameSpacedData = new NameSpacedData.Builder()
                .putEntryString("ns1", "foo1", "bar1")
                .putEntryString("ns1", "foo2", "bar2")
                .putEntryString("ns1", "foo3", "bar3")
                .putEntryString("ns2", "bar1", "foo1")
                .putEntryString("ns2", "bar2", "foo2")
                .build();
        credential.setNameSpacedData(nameSpacedData);

        // Create an authentication key... make sure the authKey used supports both
        // mdoc ECDSA and MAC authentication.
        long nowMillis = (Calendar.getInstance().getTimeInMillis() / 1000) * 1000;
        Timestamp timeSigned = Timestamp.ofEpochMilli(nowMillis);
        Timestamp timeValidityBegin = Timestamp.ofEpochMilli(nowMillis + 3600*1000);
        Timestamp timeValidityEnd = Timestamp.ofEpochMilli(nowMillis + 10*86400*1000);
        Credential.PendingAuthenticationKey pendingAuthKey =
                credential.createPendingAuthenticationKey(
                        new BouncyCastleKeystore.CreateKeySettings.Builder()
                                .setKeyPurposes(KeystoreEngine.KEY_PURPOSE_SIGN
                                        | KeystoreEngine.KEY_PURPOSE_AGREE_KEY)
                                .build(),
                        null);

        // Generate an MSO and issuer-signed data for this authentication key.
        MobileSecurityObjectGenerator msoGenerator = new MobileSecurityObjectGenerator(
                "SHA-256",
                DOC_TYPE,
                pendingAuthKey.getAttestation().get(0).getPublicKey());
        msoGenerator.setValidityInfo(timeSigned, timeValidityBegin, timeValidityEnd, null);

        Random deterministicRandomProvider = new Random(42);
        Map<String, List<byte[]>> issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
                nameSpacedData,
                deterministicRandomProvider,
                16);

        for (String nameSpaceName : issuerNameSpaces.keySet()) {
            Map<Long, byte[]> digests = MdocUtil.calculateDigestsForNameSpace(
                    nameSpaceName,
                    issuerNameSpaces,
                    "SHA-256");
            msoGenerator.addDigestIdsForNamespace(nameSpaceName, digests);
        }

        KeyPair issuerKeyPair = generateIssuingAuthorityKeyPair();
        X509Certificate issuerCert = getSelfSignedIssuerAuthorityCertificate(issuerKeyPair);

        byte[] mso = msoGenerator.generate();
        byte[] taggedEncodedMso = Util.cborEncode(Util.cborBuildTaggedByteString(mso));

        // IssuerAuth is a COSE_Sign1 where payload is MobileSecurityObjectBytes
        //
        // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
        //
        ArrayList<X509Certificate> issuerCertChain = new ArrayList<>();
        issuerCertChain.add(issuerCert);
        byte[] encodedIssuerAuth = Util.cborEncode(Util.coseSign1Sign(issuerKeyPair.getPrivate(),
                "SHA256withECDSA", taggedEncodedMso,
                null,
                issuerCertChain));

        // TODO: Replace with StaticAuthDataGenerator.setDigestIdMapping().generate()
        //       once Issue 284 is resolved.
        byte[] issuerProvidedAuthenticationData = generateStaticAuthData(
                MdocUtil.stripIssuerNameSpaces(issuerNameSpaces),
                encodedIssuerAuth);

        // Now that we have issuer-provided authentication data we certify the authentication key.
        Credential.AuthenticationKey authKey = pendingAuthKey.certify(
                issuerProvidedAuthenticationData,
                timeValidityBegin,
                timeValidityEnd);

        // OK, now do the request... request a strict subset of the data in the credential
        // and also request data not in the credential.
        List<CredentialRequest.DataElement> dataElements = Arrays.asList(
                new CredentialRequest.DataElement("ns1", "foo1", false),
                new CredentialRequest.DataElement("ns1", "foo2", false),
                new CredentialRequest.DataElement("ns1", "foo3", false),
                new CredentialRequest.DataElement("ns2", "bar1", false),
                new CredentialRequest.DataElement("ns2", "does_not_exist", false),
                new CredentialRequest.DataElement("ns_does_not_exist", "boo", false)
        );
        CredentialRequest request = new CredentialRequest(dataElements);

        byte[] encodedSessionTranscript = Util.cborEncodeString("Doesn't matter");

        DeviceResponseGenerator deviceResponseGenerator = new DeviceResponseGenerator(0);
        deviceResponseGenerator.addDocumentResponseWithMdocSignatureAuthentication(
                request,
                credential,
                DOC_TYPE,
                encodedSessionTranscript,
                null,
                authKey,
                null,
                KeystoreEngine.ALGORITHM_ES256);
        byte[] encodedDeviceResponse = deviceResponseGenerator.generate();

        // To verify, parse the response...
        DeviceResponseParser parser = new DeviceResponseParser();
        parser.setDeviceResponse(encodedDeviceResponse);
        parser.setSessionTranscript(encodedSessionTranscript);
        DeviceResponseParser.DeviceResponse deviceResponse = parser.parse();

        Assert.assertEquals(1, deviceResponse.getDocuments().size());
        DeviceResponseParser.Document doc = deviceResponse.getDocuments().get(0);

        // Check the MSO was properly signed.
        Assert.assertEquals(1, doc.getIssuerCertificateChain().size());
        Assert.assertEquals(issuerCert, doc.getIssuerCertificateChain().get(0));

        Assert.assertEquals(DOC_TYPE, doc.getDocType());
        Assert.assertEquals(timeSigned, doc.getValidityInfoSigned());
        Assert.assertEquals(timeValidityBegin, doc.getValidityInfoValidFrom());
        Assert.assertEquals(timeValidityEnd, doc.getValidityInfoValidUntil());
        Assert.assertNull(doc.getValidityInfoExpectedUpdate());

        // Check DeviceSigned data (TODO: have the credential return some data...)
        Assert.assertEquals(0, doc.getDeviceNamespaces().size());
        // Check the key which signed DeviceSigned was the expected one.
        Assert.assertEquals(authKey.getAttestation().get(0).getPublicKey(), doc.getDeviceKey());
        // Check DeviceSigned was correctly authenticated.
        Assert.assertTrue(doc.getDeviceSignedAuthenticated());
        Assert.assertTrue(doc.getDeviceSignedAuthenticatedViaSignature());

        // Check IssuerSigned data didn't have any digest failures (meaning all the hashes were correct).
        Assert.assertEquals(0, doc.getNumIssuerEntryDigestMatchFailures());
        // Check IssuerSigned data was correctly authenticated.
        Assert.assertTrue(doc.getIssuerSignedAuthenticated());

        // Check Issuer Signed data
        Assert.assertEquals(2, doc.getIssuerNamespaces().size());
        Assert.assertEquals("ns1", doc.getIssuerNamespaces().get(0));
        Assert.assertEquals(3, doc.getIssuerEntryNames("ns1").size());
        Assert.assertEquals("bar1", doc.getIssuerEntryString("ns1", "foo1"));
        Assert.assertEquals("bar2", doc.getIssuerEntryString("ns1", "foo2"));
        Assert.assertEquals("ns2", doc.getIssuerNamespaces().get(1));
        Assert.assertEquals(1, doc.getIssuerEntryNames("ns2").size());
        Assert.assertEquals("foo1", doc.getIssuerEntryString("ns2", "bar1"));

        // Also check that Mac authentication works. This requires creating an ephemeral
        // reader key... we generate a new response, parse it, and check that the
        // DeviceSigned part is as expected.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec);
        KeyPair eReaderKeyPair = kpg.generateKeyPair();
        deviceResponseGenerator = new DeviceResponseGenerator(0);
        deviceResponseGenerator.addDocumentResponseWithMdocMacAuthentication(
                request,
                credential,
                DOC_TYPE,
                encodedSessionTranscript,
                null,
                authKey,
                null,
                eReaderKeyPair.getPublic());
        encodedDeviceResponse = deviceResponseGenerator.generate();
        parser = new DeviceResponseParser();
        parser.setDeviceResponse(encodedDeviceResponse);
        parser.setSessionTranscript(encodedSessionTranscript);
        parser.setEphemeralReaderKey(eReaderKeyPair.getPrivate());
        deviceResponse = parser.parse();
        Assert.assertEquals(1, deviceResponse.getDocuments().size());
        doc = deviceResponse.getDocuments().get(0);
        Assert.assertTrue(doc.getDeviceSignedAuthenticated());
        Assert.assertFalse(doc.getDeviceSignedAuthenticatedViaSignature());

        // Check that DeviceSigned works.
        NameSpacedData deviceSignedData = new NameSpacedData.Builder()
                .putEntryString("ns1", "foo1", "bar1_override")
                .putEntryString("ns3", "baz1", "bah1")
                .putEntryString("ns4", "baz2", "bah2")
                .putEntryString("ns4", "baz3", "bah3")
                .build();
        deviceResponseGenerator = new DeviceResponseGenerator(0);
        deviceResponseGenerator.addDocumentResponseWithMdocSignatureAuthentication(
                request,
                credential,
                DOC_TYPE,
                encodedSessionTranscript,
                deviceSignedData,
                authKey,
                null,
                KeystoreEngine.ALGORITHM_ES256);
        encodedDeviceResponse = deviceResponseGenerator.generate();
        parser = new DeviceResponseParser();
        parser.setDeviceResponse(encodedDeviceResponse);
        parser.setSessionTranscript(encodedSessionTranscript);
        parser.setEphemeralReaderKey(eReaderKeyPair.getPrivate());
        deviceResponse = parser.parse();
        Assert.assertEquals(1, deviceResponse.getDocuments().size());
        doc = deviceResponse.getDocuments().get(0);
        Assert.assertTrue(doc.getDeviceSignedAuthenticated());
        Assert.assertTrue(doc.getDeviceSignedAuthenticatedViaSignature());
        // Check all Issuer Signed data is still there
        Assert.assertEquals(2, doc.getIssuerNamespaces().size());
        Assert.assertEquals("ns1", doc.getIssuerNamespaces().get(0));
        Assert.assertEquals(3, doc.getIssuerEntryNames("ns1").size());
        Assert.assertEquals("bar1", doc.getIssuerEntryString("ns1", "foo1"));
        Assert.assertEquals("bar2", doc.getIssuerEntryString("ns1", "foo2"));
        Assert.assertEquals("ns2", doc.getIssuerNamespaces().get(1));
        Assert.assertEquals(1, doc.getIssuerEntryNames("ns2").size());
        Assert.assertEquals("foo1", doc.getIssuerEntryString("ns2", "bar1"));
        // Check all Device Signed data is there
        Assert.assertEquals(3, doc.getDeviceNamespaces().size());
        Assert.assertEquals("ns1", doc.getDeviceNamespaces().get(0));
        Assert.assertEquals(1, doc.getDeviceEntryNames("ns1").size());
        Assert.assertEquals("bar1_override", doc.getDeviceEntryString("ns1", "foo1"));
        Assert.assertEquals("ns3", doc.getDeviceNamespaces().get(1));
        Assert.assertEquals(1, doc.getDeviceEntryNames("ns3").size());
        Assert.assertEquals("bah1", doc.getDeviceEntryString("ns3", "baz1"));
        Assert.assertEquals("ns4", doc.getDeviceNamespaces().get(2));
        Assert.assertEquals(2, doc.getDeviceEntryNames("ns4").size());
        Assert.assertEquals("bah2", doc.getDeviceEntryString("ns4", "baz2"));
        Assert.assertEquals("bah3", doc.getDeviceEntryString("ns4", "baz3"));
    }

    @Test
    public void testGenerateIssuerNameSpaces() {
        Random deterministicRandomProvider = new Random(42);
        NameSpacedData nameSpacedData = new NameSpacedData.Builder()
                .putEntryString("ns1", "foo1", "bar1")
                .putEntryString("ns1", "foo2", "bar2")
                .putEntryString("ns1", "foo3", "bar3")
                .putEntryString("ns2", "bar1", "foo1")
                .putEntryString("ns2", "bar2", "foo2")
                .build();
        Map<String, List<byte[]>> issuerNameSpaces = MdocUtil.generateIssuerNameSpaces(
                nameSpacedData,
                deterministicRandomProvider,
                16);

        Assert.assertEquals(2, issuerNameSpaces.size());

        List<byte[]> ns1Values = issuerNameSpaces.get("ns1");
        Assert.assertEquals(3, ns1Values.size());
        List<byte[]> ns2Values = issuerNameSpaces.get("ns2");
        Assert.assertEquals(2, ns2Values.size());

        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 1,\n" +
                        "  \"random\": h'e43c084f4bbb2bf1839dee466d852cb5',\n" +
                        "  \"elementIdentifier\": \"foo1\",\n" +
                        "  \"elementValue\": \"bar1\"\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns1Values.get(0),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 2,\n" +
                        "  \"random\": h'be6a61aa9a0c6117bd6743e7dc978573',\n" +
                        "  \"elementIdentifier\": \"foo2\",\n" +
                        "  \"elementValue\": \"bar2\"\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns1Values.get(1),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 3,\n" +
                        "  \"random\": h'998e685e885cb361f86c974620bebfb0',\n" +
                        "  \"elementIdentifier\": \"foo3\",\n" +
                        "  \"elementValue\": \"bar3\"\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns1Values.get(2),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));

        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 4,\n" +
                        "  \"random\": h'1100b276545718c30f406cc8e3a188ff',\n" +
                        "  \"elementIdentifier\": \"bar1\",\n" +
                        "  \"elementValue\": \"foo1\"\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns2Values.get(0),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 0,\n" +
                        "  \"random\": h'f11059eb6fbce62655dfbd6f83b89670',\n" +
                        "  \"elementIdentifier\": \"bar2\",\n" +
                        "  \"elementValue\": \"foo2\"\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns2Values.get(1),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));

        // Compare with digests above.
        Map<Long, byte[]> digests;

        digests = MdocUtil.calculateDigestsForNameSpace("ns1", issuerNameSpaces, "SHA-256");
        Assert.assertEquals(3, digests.size());
        Assert.assertEquals("3d4228384d110861f56b9b69e2720617d891cbb081393ead7aa972d37526f9db",
                Util.toHex(digests.get(1L)));
        Assert.assertEquals("1acacd599066a8408afcbba6d5ea87a03317a7a84ac5ac0d186a5e0a7ac53ca9",
                Util.toHex(digests.get(2L)));
        Assert.assertEquals("1607f36c8f84817d1db82ad685be4ac47d0345c2a8cec5f8e7785c9527723a07",
                Util.toHex(digests.get(3L)));

        digests = MdocUtil.calculateDigestsForNameSpace("ns2", issuerNameSpaces, "SHA-256");
        Assert.assertEquals(2, digests.size());
        Assert.assertEquals("a1c590a4ea4de1b2c975277ade6f191b6ecdabcef8262beb83e6d923ac841e0b",
                Util.toHex(digests.get(4L)));
        Assert.assertEquals("d585cb8cd6dc901ac1e4f47b804792364f1ec067aa9acd4c5664a155b35bd081",
                Util.toHex(digests.get(0L)));

        // Check stripping
        Map<String, List<byte[]>> issuerNameSpacesStripped =
                MdocUtil.stripIssuerNameSpaces(issuerNameSpaces);
        ns1Values = issuerNameSpacesStripped.get("ns1");
        Assert.assertEquals(3, ns1Values.size());
        ns2Values = issuerNameSpacesStripped.get("ns2");
        Assert.assertEquals(2, ns2Values.size());
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 1,\n" +
                        "  \"random\": h'e43c084f4bbb2bf1839dee466d852cb5',\n" +
                        "  \"elementIdentifier\": \"foo1\",\n" +
                        "  \"elementValue\": null\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns1Values.get(0),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 2,\n" +
                        "  \"random\": h'be6a61aa9a0c6117bd6743e7dc978573',\n" +
                        "  \"elementIdentifier\": \"foo2\",\n" +
                        "  \"elementValue\": null\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns1Values.get(1),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 3,\n" +
                        "  \"random\": h'998e685e885cb361f86c974620bebfb0',\n" +
                        "  \"elementIdentifier\": \"foo3\",\n" +
                        "  \"elementValue\": null\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns1Values.get(2),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 4,\n" +
                        "  \"random\": h'1100b276545718c30f406cc8e3a188ff',\n" +
                        "  \"elementIdentifier\": \"bar1\",\n" +
                        "  \"elementValue\": null\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns2Values.get(0),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
        Assert.assertEquals("24(<< {\n" +
                        "  \"digestID\": 0,\n" +
                        "  \"random\": h'f11059eb6fbce62655dfbd6f83b89670',\n" +
                        "  \"elementIdentifier\": \"bar2\",\n" +
                        "  \"elementValue\": null\n" +
                        "} >>)",
                CborUtil.toDiagnostics(
                        ns2Values.get(1),
                        CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT
                                | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));
    }

    @Test
    public void testGetDigestsForNameSpaceInTestVectors() {
        DataItem deviceResponse = Util.cborDecode(Util.fromHex(
                TestVectors.ISO_18013_5_ANNEX_D_DEVICE_RESPONSE));
        DataItem documentDataItem = Util.cborMapExtractArray(deviceResponse, "documents").get(0);

        DataItem issuerSigned = Util.cborMapExtractMap(documentDataItem, "issuerSigned");

        DataItem issuerAuthDataItem = Util.cborMapExtract(issuerSigned, "issuerAuth");
        DataItem mobileSecurityObjectBytes = Util.cborDecode(
                Util.coseSign1GetData(issuerAuthDataItem));
        DataItem mobileSecurityObject = Util.cborExtractTaggedAndEncodedCbor(
                mobileSecurityObjectBytes);
        byte[] encodedMobileSecurityObject = Util.cborEncode(mobileSecurityObject);
        MobileSecurityObjectParser.MobileSecurityObject mso = new MobileSecurityObjectParser()
                .setMobileSecurityObject(encodedMobileSecurityObject).parse();

        DataItem nameSpaces = Util.cborMapExtractMap(issuerSigned, "nameSpaces");
        List<DataItem> arrayOfIssuerSignedItemBytes = Util.cborMapExtractArray(nameSpaces, "org.iso.18013.5.1");
        List<byte[]> issuerNamespacesForMdlNamespace = new ArrayList<>();
        for (DataItem di : arrayOfIssuerSignedItemBytes) {
            //Logger.dCbor(TAG, "di", Util.cborEncode(di));
            issuerNamespacesForMdlNamespace.add(Util.cborEncode(di));
        }
        Map<String, List<byte[]>> issuerNameSpacesFromTestVector = new LinkedHashMap<>();
        issuerNameSpacesFromTestVector.put("org.iso.18013.5.1", issuerNamespacesForMdlNamespace);

        Map<Long, byte[]> digestsCalculatedFromResponseInTestVector = MdocUtil.calculateDigestsForNameSpace(
                "org.iso.18013.5.1",
                issuerNameSpacesFromTestVector,
                "SHA-256");

        Map<Long, byte[]> digestsListedInMsoInTestVector = mso.getDigestIDs("org.iso.18013.5.1");

        // Note: Because of selective disclosure, the response doesn't contain all the data
        // elements listed in the MSO... and we can only test what's in the response. So we
        // need to start from there
        //
        for (long digestId : digestsCalculatedFromResponseInTestVector.keySet()) {
            byte[] calculatedDigest = digestsCalculatedFromResponseInTestVector.get(digestId);
            byte[] digestInMso = digestsListedInMsoInTestVector.get(digestId);
            Assert.assertArrayEquals(calculatedDigest, digestInMso);
        }
    }
}
