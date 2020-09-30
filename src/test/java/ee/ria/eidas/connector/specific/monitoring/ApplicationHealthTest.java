package ee.ria.eidas.connector.specific.monitoring;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.metadata.sp.ServiceProviderMetadataResolver;
import io.micrometer.core.instrument.TimeGauge;
import io.restassured.response.Response;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static java.lang.Double.valueOf;
import static java.time.Instant.ofEpochMilli;
import static java.util.Arrays.asList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.stream.Collectors.toMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class ApplicationHealthTest extends SpecificConnectorTest {
    protected static final String APPLICATION_HEALTH_ENDPOINT_REQUEST = "/heartbeat";

    @Autowired
    protected ServiceProviderMetadataResolver serviceProviderMetadataResolver;

    @BeforeAll
    static void beforeAllHealthTests() {
        startServiceProviderMetadataServer();
        updateServiceProviderMetadata("valid-metadata.xml");
    }

    @AfterAll
    static void afterAllHealthTests() {
        mockSPMetadataServer.stop();
    }

    protected static void setClusterStateInactive() {
        eidasNodeIgnite.cluster().active(false);
    }

    protected static void setClusterStateActive() {
        eidasNodeIgnite.cluster().active(true);
    }

    protected Response getHealthResponse() {
        return given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
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
        SP_METADATA("sp-service-provider-metadata"),
        TRUSTSTORE("truststore");
        @Getter
        public final String name;
    }
}
