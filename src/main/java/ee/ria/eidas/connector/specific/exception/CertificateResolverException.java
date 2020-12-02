package ee.ria.eidas.connector.specific.exception;

import lombok.Getter;
import org.opensaml.security.credential.UsageType;

@Getter
public class CertificateResolverException extends TechnicalException {

    private UsageType usageType;

    public CertificateResolverException(UsageType usageType, String message) {
        this(usageType, message, null);
    }

    public CertificateResolverException(UsageType usageType, Throwable cause) {
        this(usageType, cause.getMessage(), cause);
    }

    public CertificateResolverException(UsageType usageType, String message, Throwable cause) {
        super(message, cause);
        this.usageType = usageType;
    }
}
