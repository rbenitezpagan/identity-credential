package com.android.identity.credential;

import com.android.identity.keystore.BouncyCastleKeystore;
import com.android.identity.keystore.KeystoreEngine;
import com.android.identity.keystore.KeystoreEngineRepository;
import com.android.identity.storage.EphemeralStorageEngine;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.Timestamp;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CredentialUtilTest {
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

    @Test
    public void testManagedAuthenticationKeyHelper() {
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());

        Assert.assertEquals(0, credential.getAuthenticationKeys().size());
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        KeystoreEngine.CreateKeySettings authKeySettings =
                new BouncyCastleKeystore.CreateKeySettings.Builder()
                        .build();

        int numAuthKeys = 10;
        int maxUsesPerKey = 5;
        long minValidTimeMillis = 10;
        int count;
        int numKeysCreated;
        String managedKeyDomain = "managedAuthenticationKeys";

        // Start the process at time 100 and certify all those keys so they're
        // valid until time 200.
        numKeysCreated = CredentialUtil.managedAuthenticationKeyHelper(
                credential,
                authKeySettings,
                managedKeyDomain,
                Timestamp.ofEpochMilli(100),
                numAuthKeys,
                maxUsesPerKey,
                minValidTimeMillis);
        Assert.assertEquals(numAuthKeys, numKeysCreated);
        Assert.assertEquals(numAuthKeys, credential.getPendingAuthenticationKeys().size());
        count = 0;
        for (Credential.PendingAuthenticationKey pak : credential.getPendingAuthenticationKeys()) {
            pak.certify(new byte[] {0, (byte) count++},
                    Timestamp.ofEpochMilli(100),
                    Timestamp.ofEpochMilli(200));
        }
        // We should now have |numAuthKeys| certified keys and none pending
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());
        Assert.assertEquals(numAuthKeys, credential.getAuthenticationKeys().size());

        // Certifying again at this point should not make a difference.
        numKeysCreated = CredentialUtil.managedAuthenticationKeyHelper(
                credential,
                authKeySettings,
                managedKeyDomain,
                Timestamp.ofEpochMilli(100),
                numAuthKeys,
                maxUsesPerKey,
                minValidTimeMillis);
        Assert.assertEquals(0, numKeysCreated);
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        // Use up until just before the limit, and check it doesn't make a difference
        for (Credential.AuthenticationKey ak : credential.getAuthenticationKeys()) {
            for (int n = 0; n < maxUsesPerKey - 1; n++) {
                ak.increaseUsageCount();
            }
        }
        numKeysCreated = CredentialUtil.managedAuthenticationKeyHelper(
                credential,
                authKeySettings,
                managedKeyDomain,
                Timestamp.ofEpochMilli(100),
                numAuthKeys,
                maxUsesPerKey,
                minValidTimeMillis);
        Assert.assertEquals(0, numKeysCreated);
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        // For the first 5, use one more time and check replacements are generated for those
        // Let the replacements expire just a tad later
        count = 0;
        for (Credential.AuthenticationKey ak : credential.getAuthenticationKeys()) {
            ak.increaseUsageCount();
            if (++count >= 5) {
                break;
            }
        }
        numKeysCreated = CredentialUtil.managedAuthenticationKeyHelper(
                credential,
                authKeySettings,
                managedKeyDomain,
                Timestamp.ofEpochMilli(100),
                numAuthKeys,
                maxUsesPerKey,
                minValidTimeMillis);
        Assert.assertEquals(5, numKeysCreated);
        Assert.assertEquals(5, credential.getPendingAuthenticationKeys().size());
        count = 0;
        for (Credential.PendingAuthenticationKey pak : credential.getPendingAuthenticationKeys()) {
            pak.certify(new byte[] {1, (byte) count++},
                    Timestamp.ofEpochMilli(100),
                    Timestamp.ofEpochMilli(210));
        }
        // We should now have |numAuthKeys| certified keys and none pending
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());
        Assert.assertEquals(numAuthKeys, credential.getAuthenticationKeys().size());
        // Check that the _right_ ones were removed by inspecting issuer-provided data.
        // We rely on some implementation details on how ordering works... also cross-reference
        // with data passed into certify() functions above.
        count = 0;
        for (Credential.AuthenticationKey authKey : credential.getAuthenticationKeys()) {
            byte[][] expectedData = {
                    new byte[] {0, 5},
                    new byte[] {0, 6},
                    new byte[] {0, 7},
                    new byte[] {0, 8},
                    new byte[] {0, 9},
                    new byte[] {1, 0},
                    new byte[] {1, 1},
                    new byte[] {1, 2},
                    new byte[] {1, 3},
                    new byte[] {1, 4},
            };
            Assert.assertArrayEquals(expectedData[count++], authKey.getIssuerProvidedData());
        }

        // Now move close to the expiration date of the original five auth keys.
        // This should trigger just them for replacement
        numKeysCreated = CredentialUtil.managedAuthenticationKeyHelper(
                credential,
                authKeySettings,
                managedKeyDomain,
                Timestamp.ofEpochMilli(195),
                numAuthKeys,
                maxUsesPerKey,
                minValidTimeMillis);
        Assert.assertEquals(5, numKeysCreated);
        Assert.assertEquals(5, credential.getPendingAuthenticationKeys().size());
        count = 0;
        for (Credential.PendingAuthenticationKey pak : credential.getPendingAuthenticationKeys()) {
            pak.certify(new byte[] {2, (byte) count++},
                    Timestamp.ofEpochMilli(100),
                    Timestamp.ofEpochMilli(210));
        }
        // We should now have |numAuthKeys| certified keys and none pending
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());
        Assert.assertEquals(numAuthKeys, credential.getAuthenticationKeys().size());
        // Check that the _right_ ones were removed by inspecting issuer-provided data.
        // We rely on some implementation details on how ordering works... also cross-reference
        // with data passed into certify() functions above.
        count = 0;
        for (Credential.AuthenticationKey authKey : credential.getAuthenticationKeys()) {
            byte[][] expectedData = {
                    new byte[] {1, 0},
                    new byte[] {1, 1},
                    new byte[] {1, 2},
                    new byte[] {1, 3},
                    new byte[] {1, 4},
                    new byte[] {2, 0},
                    new byte[] {2, 1},
                    new byte[] {2, 2},
                    new byte[] {2, 3},
                    new byte[] {2, 4},
            };
            Assert.assertArrayEquals(expectedData[count++], authKey.getIssuerProvidedData());
        }
    }
}
