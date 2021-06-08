package ee.ria.eidas.connector.specific.monitoring.health;

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
import org.springframework.context.ApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.String.format;
import static java.time.Instant.now;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Component
public class ResponderMetadataHealthIndicator extends AbstractHealthIndicator {
    public static final String SIGNING_CERTIFICATE_EXPIRATION_WARNING = "Responder metadata signing certificate '%s' with serial number '%s' is expiring at %s";
    private static final String SIGNING_CERTIFICATE_INVALID_WARNING = "Responder metadata signing certificate '{}' with serial number '{}' is not valid. Validity period {} - {}";
    private static final String SIGNING_OPERATION_FAILED_WARNING = "Signing with credential '{}' failed";
    private static final String SIGNING_OPERATION_RECOVERED = "Signing with credential '{}' recovered";
    private final AtomicBoolean credentialInFailedState = new AtomicBoolean();
    private final Map<String, CertificateInfo> signingCertificateInfo = new HashMap<>();

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
        if (isSigningCertificateExpired() || isSigningCredentialInFailedState()) {
            builder.down().withDetails(signingCertificateInfo).build();
        } else {
            builder.up().withDetails(signingCertificateInfo).build();
        }
    }

    private boolean isSigningCertificateExpired() {
        Instant currentDateTime = now(getSystemClock());
        X509Certificate x509 = signingCredential.getEntityCertificate();
        if (currentDateTime.isAfter(x509.getNotAfter().toInstant()) || currentDateTime.isBefore(x509.getNotBefore().toInstant())) {
            log.warn(SIGNING_CERTIFICATE_INVALID_WARNING, signingCredential.getEntityId(),
                    value("x509.serial_number", x509.getSerialNumber()),
                    value("x509.not_before", x509.getNotBefore().toInstant()),
                    value("x509.not_after", x509.getNotAfter().toInstant()));
            return true;
        } else {
            return false;
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
                log.error(marker, SIGNING_OPERATION_FAILED_WARNING, signingCredential.getEntityId(), ex);
                return true;
            }
        } else {
            return false;
        }
    }

    @EventListener
    public void onFailedSigningEvent(FailedSigningEvent event) {
        if (!credentialInFailedState.get()) {
            credentialInFailedState.set(true);
        }
    }

    public Optional<String> getSigningCertificateExpirationWarning() {
        Instant currentDateTime = now(getSystemClock());
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiry = x509.getNotAfter().toInstant();
        if (currentDateTime.plus(keyStoreExpirationWarningPeriod).isAfter(certificateExpiry)) {
            return of(format(SIGNING_CERTIFICATE_EXPIRATION_WARNING,
                    x509.getSubjectDN(),
                    x509.getSerialNumber(),
                    x509.getNotAfter().toInstant()));
        } else {
            return empty();
        }
    }

    @PostConstruct
    private void setupSigningCertificatesInfo() {
        X509Certificate x509 = signingCredential.getEntityCertificate();
        signingCertificateInfo.put(signingCredential.getEntityId(), CertificateInfo.builder()
                .validTo(x509.getNotAfter().toInstant())
                .subjectDN(x509.getSubjectDN().getName())
                .serialNumber(x509.getSerialNumber().toString())
                .build());
    }

    @Getter
    public static class FailedSigningEvent extends ApplicationEvent {

        public FailedSigningEvent() {
            super("");
        }
    }
}
