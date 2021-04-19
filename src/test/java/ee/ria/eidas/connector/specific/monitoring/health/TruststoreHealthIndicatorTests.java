package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static java.time.ZoneId.of;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
class TruststoreHealthIndicatorTests extends ApplicationHealthTest {

    @SpyBean
    TruststoreHealthIndicator truststoreHealthIndicator;

    @Test
    void noTruststoreWarningsWhen_WarningPeriodNotMet() {
        Instant expectedTime = Instant.parse("2021-04-13T08:50:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.TRUSTSTORE);
    }

    @Test
    void truststoreWarningWhen_CertificateAboutToExpire() {
        Instant expectedTime = Instant.parse("2031-04-14T08:50:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));
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
        Instant expectedTime = Instant.parse("2031-05-13T08:51:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));
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
