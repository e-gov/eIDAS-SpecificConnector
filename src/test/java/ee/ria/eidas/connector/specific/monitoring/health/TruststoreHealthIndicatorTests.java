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

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
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
    public void noTruststoreWarningsWhenWarningPeriodNotMet() {
        Instant expectedTime = Instant.parse("2021-04-13T08:50:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.TRUSTSTORE);
    }

    @Test
    public void truststoreWarningWhenCertificateAboutToExpire() {
        Instant expectedTime = Instant.parse("2021-04-14T08:50:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNotNull(warnings);
        Optional<String> authenticationService = warnings.stream()
                .filter(w -> w.contains("1589359800"))
                .findFirst();
        assertEquals("Truststore certificate 'CN=localhost, OU=test, O=test, L=test, ST=test, C=EE' with serial number '1589359800' is expiring at 2021-05-13T08:50:00Z", authenticationService.get());
        assertDependenciesUp(healthResponse, Dependencies.TRUSTSTORE);
    }

    @Test
    public void truststoreWarningAndHealthStatusDownWhenCertificateExpired() {
        Instant expectedTime = Instant.parse("2021-05-13T08:51:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));
        Response healthResponse = getHealthResponse();

        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNotNull(warnings);
        Optional<String> authenticationService = warnings.stream()
                .filter(w -> w.contains("1589359800"))
                .findFirst();
        assertEquals("Truststore certificate 'CN=localhost, OU=test, O=test, L=test, ST=test, C=EE' with serial number '1589359800' is expiring at 2021-05-13T08:50:00Z", authenticationService.get());
        assertDependenciesDown(healthResponse, Dependencies.TRUSTSTORE);
    }
}
