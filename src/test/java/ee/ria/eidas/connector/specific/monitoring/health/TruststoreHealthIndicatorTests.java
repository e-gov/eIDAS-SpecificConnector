package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Optional;

import static java.time.ZoneId.of;
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
class TruststoreHealthIndicatorTests extends ApplicationHealthTest {
    private static final String CERTIFICATE_EXPIRY_TIME = "2031-04-19T11:20:37Z";

    @Value("${eidas.connector.health.trust-store-expiration-warning:30d}")
    private Period trustStoreExpirationWarningPeriod;

    @Test
    void noTruststoreWarningsWhen_WarningPeriodNotMet() {
        Instant noWarningTime = Instant.parse(CERTIFICATE_EXPIRY_TIME).minus(trustStoreExpirationWarningPeriod);
        Mockito.doReturn(Clock.fixed(noWarningTime, of("UTC"))).when(truststoreHealthIndicator).getSystemClock();
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.TRUSTSTORE);
    }

    @Test
    void truststoreWarningWhen_CertificateAboutToExpire() {
        Instant warningTime = Instant.parse(CERTIFICATE_EXPIRY_TIME).minus(trustStoreExpirationWarningPeriod).plus(1, SECONDS);
        Mockito.doReturn(Clock.fixed(warningTime, of("UTC"))).when(truststoreHealthIndicator).getSystemClock();
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNotNull(warnings);
        Optional<String> authenticationService = warnings.stream()
                .filter(w -> w.contains("1618831237"))
                .findFirst();
        assertEquals("Truststore certificate 'CN=localhost, OU=test, O=test, L=test, ST=test, C=EE' with serial number '1618831237' is expiring at 2031-04-19T11:20:37Z", authenticationService.get());
        assertDependenciesUp(healthResponse, Dependencies.TRUSTSTORE);
    }

    @Test
    void truststoreWarningAndHealthStatusDownWhen_CertificateExpired() {
        Instant expiredTime = Instant.parse(CERTIFICATE_EXPIRY_TIME).plus(1, SECONDS);
        Mockito.doReturn(Clock.fixed(expiredTime, of("UTC"))).when(truststoreHealthIndicator).getSystemClock();
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNotNull(warnings);
        Optional<String> authenticationService = warnings.stream()
                .filter(w -> w.contains("1618831237"))
                .findFirst();
        assertEquals("Truststore certificate 'CN=localhost, OU=test, O=test, L=test, ST=test, C=EE' with serial number '1618831237' is expiring at 2031-04-19T11:20:37Z", authenticationService.get());
        assertDependenciesDown(healthResponse, Dependencies.TRUSTSTORE);
    }
}
