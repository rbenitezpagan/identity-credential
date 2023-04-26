package com.android.identity.credential;

import androidx.annotation.NonNull;

import java.util.List;

public class CredentialRequest {

    private final List<DataElement> mRequestedDataElements;

    // TODO: docType
    // TODO: requested identity

    public CredentialRequest(@NonNull List<DataElement> requestedDataElements) {
        mRequestedDataElements = requestedDataElements;
    }

    public @NonNull List<DataElement> getRequestedDataElements() {
        return mRequestedDataElements;
    }

    public static class DataElement {
        private final String mNameSpaceName;
        private final String mDataElementName;
        private final boolean mIntentToRetain;
        private boolean mIgnored;

        public DataElement(@NonNull String nameSpaceName,
                           @NonNull String dataElementName,
                           boolean intentToRetain) {
            mNameSpaceName = nameSpaceName;
            mDataElementName = dataElementName;
            mIntentToRetain = intentToRetain;
            mIgnored = false;
        }

        public @NonNull String getNameSpaceName() {
            return mNameSpaceName;
        }

        public @NonNull String getDataElementName() {
            return mDataElementName;
        }

        public boolean getIntentToRetain() {
            return mIntentToRetain;
        }

        public boolean getIgnored() {
            return mIgnored;
        }

        public void setIgnored(boolean ignored) {
            mIgnored = ignored;
        }
    }

}
