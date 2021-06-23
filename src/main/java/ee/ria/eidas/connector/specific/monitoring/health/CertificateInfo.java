package ee.ria.eidas.connector.specific.monitoring.health;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Builder
@Getter
public class CertificateInfo {
    private final Instant validTo;
    private final String subjectDN;
    private final String serialNumber;
}
