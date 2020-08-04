package ee.ria.eidas.connector.specific.monitoring;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import io.micrometer.core.instrument.TimeGauge;
import io.restassured.response.Response;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.lang.Double.valueOf;
import static java.time.Instant.ofEpochMilli;
import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;
import static org.junit.jupiter.api.Assertions.*;

public abstract class ApplicationHealthTest extends SpecificConnectorTest {
    protected static final String APPLICATION_HEALTH_ENDPOINT_REQUEST = "/heartbeat";
    protected static final WireMockServer mockSPClient1Server = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/sp-client.jks")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("JKS")
            .httpsPort(7070)
    );

    @BeforeAll
    static void beforeAllHealthTests() {
        startSPClientServer();
    }

    @AfterAll
    static void afterAllHealthTests() {
        mockSPClient1Server.stop();
    }

    private static void startSPClientServer() {
        mockSPClient1Server.start();
        mockSPClient1Server.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse()
                .withHeader("Content-Type", "application/xml;charset=UTF-8")
                .withStatus(200)
                .withBodyFile("sp-client-metadata.xml")));
    }

    protected static void setClusterStateInactive() {
        eidasNodeIgnite.cluster().active(false);
    }

    protected static void setClusterStateActive() {
        eidasNodeIgnite.cluster().active(true);
    }

    protected void assertAllDependenciesUp(Response healthResponse) {
        assertEquals("UP", healthResponse.jsonPath().get("status"));
        assertDependencies(healthResponse, "UP", Dependencies.values());
    }

    protected void assertDependenciesUp(Response healthResponse, Dependencies... dependenciesUp) {
        assertDependencies(healthResponse, "UP", dependenciesUp);
    }

    protected void assertDependenciesDown(Response healthResponse, Dependencies... dependenciesDown) {
        assertEquals("DOWN", healthResponse.jsonPath().get("status"), "Compound health status");
        assertDependencies(healthResponse, "DOWN", dependenciesDown);
    }

    private void assertDependencies(Response healthResponse, String expectedStatus, Dependencies... expectedDependencies) {
        List<HashMap<String, String>> dependencies = healthResponse.jsonPath().getList("dependencies");
        Map<String, String> healthDependencies = dependencies.stream()
                .map(m -> new AbstractMap.SimpleEntry<>(m.get("name"), m.get("status")))
                .collect(toMap(entry -> entry.getKey(), entry -> entry.getValue()));
        List<Dependencies> expectedDependenciesList = asList(expectedDependencies);
        expectedDependenciesList
                .forEach(d -> assertTrue(healthDependencies.containsKey(d.getName()), "Health dependency not found: " + d.getName()));
        expectedDependenciesList.stream()
                .filter(d -> healthDependencies.containsKey(d.getName()))
                .forEach(d -> assertEquals(expectedStatus, healthDependencies.get(d.getName()), "Expected status for dependency: " + d.getName()));
    }

    protected void assertStartAndUptime(Response healthResponse) {
        Instant startTime = Instant.parse(healthResponse.jsonPath().get("startTime"));
        TimeGauge startTimeGauge = meterRegistry.find("process.start.time").timeGauge();
        assertEquals(ofEpochMilli(valueOf(startTimeGauge.value(MILLISECONDS)).longValue()), startTime);

        Instant currentTime = Instant.parse(healthResponse.jsonPath().get("currentTime"));
        assertTrue(currentTime.isAfter(startTime));
        assertTrue(currentTime.isBefore(Instant.now()));

        long upTime = Duration.parse(healthResponse.jsonPath().get("upTime")).getSeconds();
        long expectedUpTime = Duration.between(startTime, currentTime).withNanos(0).getSeconds();
        assertEquals(expectedUpTime, upTime, 1, "upTime");
    }

    @RequiredArgsConstructor
    public enum Dependencies {
        IGNITE_CLUSTER("igniteCluster"),
        CONNECTOR_METADATA("connectorMetadata"),
        SP_CLIENT("sp-client1-metadata"),
        TRUSTSTORE("truststore");
        @Getter
        public final String name;


    }
}
