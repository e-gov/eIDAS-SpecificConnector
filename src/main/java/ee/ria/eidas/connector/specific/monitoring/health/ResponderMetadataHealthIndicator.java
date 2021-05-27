package ee.ria.eidas.connector.specific.monitoring.health;


import ee.ria.eidas.connector.specific.config.ResponderMetadataConfiguration.FailedSigningEvent;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import ee.ria.eidas.connector.specific.responder.metadata.EntityDescriptorFactory;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataSigner;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.opensaml.security.x509.BasicX509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.Period;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.String.format;
import static java.time.OffsetDateTime.now;
import static java.time.ZoneOffset.UTC;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Component
public class ResponderMetadataHealthIndicator extends AbstractHealthIndicator {
    public static final String SIGNING_CERTIFICATE_EXPIRATION_WARNING = "Responder metadata signing certificate '%s' with serial number '%s' is expiring at %s";
    private static final String SIGNING_CERTIFICATE_IVALID_WARNING = "Responder metadata signing certificate '{}' with serial number '{}' is not valid. Validity period {} - {}";
    private static final String SIGNING_OPERATION_FAILED_WARNING = "Signing with credential '{}' failed";
    private static final String SIGNING_OPERATION_RECOVERED = "Signing with credential '{}' recovered";
    private final AtomicBoolean credentialInFailedState = new AtomicBoolean();

    @Getter
    private Clock systemClock;

    @Autowired
    private BasicX509Credential signingCredential;

    @Autowired
    private ResponderMetadataSigner responderMetadataSigner;

    @Autowired
    private ResponderMetadata responderMetadata;

    @Value("${eidas.connector.health.key-store-expiration-warning:30d}")
    private Period keyStoreExpirationWarningPeriod;

    public ResponderMetadataHealthIndicator() {
        super("Responder metadata health check failed");
        systemClock = Clock.systemUTC();
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        if (isSigningCertificateExpired()) {
            X509Certificate x509 = signingCredential.getEntityCertificate();
            log.warn(SIGNING_CERTIFICATE_IVALID_WARNING, signingCredential.getEntityId(),
                    value("x509.serial_number", x509.getSerialNumber()),
                    value("x509.not_before", x509.getNotBefore().toInstant()),
                    value("x509.not_after", x509.getNotAfter().toInstant()));
            builder.down().build();
        } else if (isSigningCredentialInFailedState()) {
            builder.down().build();
        } else {
            builder.up().build();
        }
    }

    private boolean isSigningCredentialInFailedState() {
        if (credentialInFailedState.get()) {
            X509Certificate x509 = signingCredential.getEntityCertificate();
            LogstashMarker marker = append("x509.serial_number", x509.getSerialNumber())
                    .and(append("x509.not_before", x509.getNotBefore().toInstant()))
                    .and(append("x509.not_after", x509.getNotAfter().toInstant()));
            try {
                responderMetadataSigner.sign(EntityDescriptorFactory.create(responderMetadata, signingCredential));
                log.info(marker, SIGNING_OPERATION_RECOVERED, signingCredential.getEntityId());
                credentialInFailedState.set(false);
                return false;
            } catch (Exception ex) {
                log.warn(marker, SIGNING_OPERATION_FAILED_WARNING, signingCredential.getEntityId());
                return true;
            }
        } else {
            return false;
        }
    }

    private boolean isSigningCertificateExpired() {
        OffsetDateTime currentDateTime = now(getSystemClock());
        X509Certificate x509 = signingCredential.getEntityCertificate();
        return currentDateTime.isAfter(x509.getNotAfter().toInstant().atOffset(UTC)) ||
                currentDateTime.isBefore(x509.getNotBefore().toInstant().atOffset(UTC));
    }

    public Optional<String> getSigningCertificateExpirationWarning() {
        OffsetDateTime currentDateTime = now(getSystemClock());
        X509Certificate x509 = signingCredential.getEntityCertificate();
        OffsetDateTime certificateExpiry = x509.getNotAfter().toInstant().atOffset(UTC);
        if (currentDateTime.plus(keyStoreExpirationWarningPeriod).isAfter(certificateExpiry)) {
            return of(format(SIGNING_CERTIFICATE_EXPIRATION_WARNING,
                    x509.getSubjectDN(),
                    x509.getSerialNumber(),
                    x509.getNotAfter().toInstant()));
        } else {
            return empty();
        }
    }

    @EventListener
    public void onFailedCredentialEvent(FailedSigningEvent event) {
        if (!credentialInFailedState.get()) {
            credentialInFailedState.set(true);
        }
    }
}
