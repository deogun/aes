package se.deogun.aes.modes.common;

import se.deogun.aes.api.RejectReason;

public enum InternalRejectReason {
    NO_SECURE_RANDOM_ALGORITHM(RejectReason.NO_SECURE_RANDOM_ALGORITHM_AVAILABLE_ON_THIS_SYSTEM),
    UNABLE_TO_DECRYPT(RejectReason.UNABLE_TO_DECRYPT_DATA),
    UNABLE_TO_ENCRYPT(RejectReason.UNABLE_TO_ENCRYPT_DATA),
    GCM_NOT_AVAILABLE(RejectReason.GCM_NOT_AVAILABLE_ON_THIS_SYSTEM),
    GCM_INVALID_KEY(RejectReason.GCM_INVALID_KEY),
    GCM_INVALID_PARAMETERS(RejectReason.GCM_INVALID_PARAMETERS),
    GCM_INVALID_TAG(RejectReason.GCM_INVALID_TAG);

    private final RejectReason rejectReason;

    InternalRejectReason(final RejectReason rejectReason) {
        this.rejectReason = rejectReason;
    }

    public RejectReason toAPI() {
        return rejectReason;
    }
}
