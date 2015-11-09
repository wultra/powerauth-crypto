package io.getlime.security.repository.model;

public enum ActivationStatus {

    CREATED((byte) 1),
    OTP_USED((byte) 2),
    ACTIVE((byte) 3),
    BLOCKED((byte) 4),
    REMOVED((byte) 5);

    final byte value;

    ActivationStatus(final byte value) {
        this.value = value;
    }

    public byte getByte() {
        return value;
    }
}
