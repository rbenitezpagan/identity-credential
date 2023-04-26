package com.android.identity.mdoc.util;

import androidx.annotation.NonNull;

import com.android.identity.internal.Util;
import com.android.identity.credential.NameSpacedData;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;

public class MdocUtil {

    private static final String TAG = "MdocUtil";

    /**
     * Generates randoms and digest identifiers for data.
     *
     * <p>This generates data similar to {@code IssuerNameSpaces} CBOR as defined in ISO 18013-5:
     *
     * <pre>
     * IssuerNameSpaces = { ; Returned data elements for each namespace
     *   + NameSpace => [ + IssuerSignedItemBytes ]
     * }
     *
     * IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
     *
     * IssuerSignedItem = {
     *   "digestID" : uint, ; Digest ID for issuer data authentication
     *   "random" : bstr, ; Random value for issuer data authentication
     *   "elementIdentifier" : DataElementIdentifier, ; Data element identifier
     *   "elementValue" : DataElementValue ; Data element value
     * }
     * </pre>
     *
     * <p>except that the data is returned using a native maps and lists. The returned
     * data is a map from name spaces into a list of the bytes of the
     * {@code IssuerSignedItemBytes} CBOR.
     *
     * TODO: See Issue 284 for adding code to encode the returned value into StaticAuthData
     *       CBOR for use at provisioning and MSO refresh time.
     *
     * @param data The name spaced data.
     * @param randomProvider A random provider used for generating digest identifiers and salts.
     * @param dataElementRandomSize The number of bytes to use for the salt for each data elements,
     *                              must be at least 16.
     * @return The data described above.
     * @throws IllegalArgumentException if {@code dataElementRandomSize} is less than 16.
     */
    public static @NonNull Map<String, List<byte[]>> generateIssuerNameSpaces(
            NameSpacedData data,
            Random randomProvider,
            int dataElementRandomSize) {

        if (dataElementRandomSize < 16) {
            // ISO 18013-5 section 9.1.2.5 Message digest function says that random must
            // be at least 16 bytes long.
            throw new IllegalArgumentException("Random size must be at least 16 bytes");
        }

        LinkedHashMap<String, List<byte[]>> ret = new LinkedHashMap<>();

        // Count number of data elements first.
        int numDataElements = 0;
        for (String nsName : data.getNameSpaceNames()) {
            numDataElements += data.getDataElementNames(nsName).size();
        }
        List<Long> digestIds = new ArrayList<>();
        for (long n = 0L; n < numDataElements; n++) {
            digestIds.add(n);
        }
        Collections.shuffle(digestIds, randomProvider);

        Iterator<Long> digestIt = digestIds.iterator();
        for (String nsName : data.getNameSpaceNames()) {
            List<byte[]> list = new ArrayList<>();
            for (String elemName : data.getDataElementNames(nsName)) {

                byte[] encodedValue = data.getDataElement(nsName, elemName);
                long digestId = digestIt.next();
                byte[] random = new byte[dataElementRandomSize];
                randomProvider.nextBytes(random);
                DataItem value = Util.cborDecode(encodedValue);

                DataItem issuerSignedItem = new CborBuilder()
                        .addMap()
                        .put("digestID", digestId)
                        .put("random", random)
                        .put("elementIdentifier", elemName)
                        .put(new UnicodeString("elementValue"), value)
                        .end()
                        .build().get(0);
                byte[] encodedIssuerSignedItem = Util.cborEncode(issuerSignedItem);

                byte[] encodedIssuerSignedItemBytes =
                        Util.cborEncode(Util.cborBuildTaggedByteString(
                                encodedIssuerSignedItem));

                list.add(encodedIssuerSignedItemBytes);
            }
            ret.put(nsName, list);
        }
        return ret;
    }

    /**
     * Strips issuer name spaces.
     *
     * This takes a IssuerNameSpaces value calculated by
     * {@link #generateIssuerNameSpaces(NameSpacedData, Random, int)}
     * and returns a similar structure except where all {@code elementValue} values
     * in {@code IssuerSignedItem} is set to {@code null}.
     *
     * @param issuerNameSpaces a map from name spaces into a list of {@code IssuerSignedItemBytes}.
     * @return A copy of the passed-in structure where data element value is set to {@code null}.
     *         for every data element.
     */
    public static @NonNull Map<String, List<byte[]>> stripIssuerNameSpaces(
            @NonNull Map<String, List<byte[]>> issuerNameSpaces) {
        Map<String, List<byte[]>> ret = new LinkedHashMap<>();

        for (String nameSpaceName : issuerNameSpaces.keySet()) {
            List<byte[]> list = new ArrayList<>();
            for (byte[] encodedIssuerSignedItemBytes : issuerNameSpaces.get(nameSpaceName)) {
                byte[] encodedIssuerSignedItem = Util.cborExtractTaggedCbor(encodedIssuerSignedItemBytes);
                byte[] modifiedEncodedIssuerSignedItem = Util.issuerSignedItemClearValue(encodedIssuerSignedItem);
                byte[] modifiedEncodedIssuerSignedItemBytes = Util.cborEncode(
                        Util.cborBuildTaggedByteString(modifiedEncodedIssuerSignedItem));
                list.add(modifiedEncodedIssuerSignedItemBytes);
            }
            ret.put(nameSpaceName, list);
        }
        return ret;
    }


    /**
     * Calculates all digests in a given name space.
     *
     * @param nameSpaceName the name space to pick from the {@code issuerNameSpaces} mao.
     * @param issuerNameSpaces a map from name spaces into a list of {@code IssuerSignedItemBytes}.
     * @param digestAlgorithm the digest algorithm to use, for example {@code SHA-256}.
     * @return a map from digest identifiers to the calculated digest.
     */
    public static @NonNull
    Map<Long, byte[]> calculateDigestsForNameSpace(@NonNull String nameSpaceName,
                                                   @NonNull Map<String, List<byte[]>> issuerNameSpaces,
                                                   @NonNull String digestAlgorithm) {
        List<byte[]> list = issuerNameSpaces.get(nameSpaceName);
        if (list == null) {
            throw new IllegalArgumentException("No namespace " + nameSpaceName + " in IssuerNameSpaces");
        }
        Map<Long, byte[]> ret = new LinkedHashMap<>();
        for (byte[] encodedIssuerSignedItemBytes : list) {
            DataItem map = Util.cborDecode(Util.cborExtractTaggedCbor(encodedIssuerSignedItemBytes));
            long digestId = Util.cborMapExtractNumber(map, "digestID");
            try {
                byte[] digest = MessageDigest.getInstance(digestAlgorithm).digest(encodedIssuerSignedItemBytes);
                ret.put(digestId, digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("Failed creating digester", e);
            }
        }
        return ret;
    }


}
