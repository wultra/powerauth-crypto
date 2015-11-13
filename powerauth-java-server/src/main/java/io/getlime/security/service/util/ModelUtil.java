package io.getlime.security.service.util;

public class ModelUtil {

    public static io.getlime.security.powerauth.ActivationStatus toServiceStatus(
            io.getlime.security.repository.model.ActivationStatus repositoryStatus) {
        switch (repositoryStatus) {
            case CREATED:
                return io.getlime.security.powerauth.ActivationStatus.CREATED;
            case OTP_USED:
                return io.getlime.security.powerauth.ActivationStatus.OTP_USED;
            case ACTIVE:
                return io.getlime.security.powerauth.ActivationStatus.ACTIVE;
            case BLOCKED:
                return io.getlime.security.powerauth.ActivationStatus.BLOCKED;
            case REMOVED:
                return io.getlime.security.powerauth.ActivationStatus.REMOVED;
        }
        return io.getlime.security.powerauth.ActivationStatus.REMOVED;
    }

}
