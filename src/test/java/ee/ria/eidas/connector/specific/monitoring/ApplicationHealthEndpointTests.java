package ee.ria.eidas.connector.specific.monitoring;

import io.micrometer.core.instrument.search.Search;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat",
                "eidas.connector.service-providers[0].id=client1",
                "eidas.connector.service-providers[0].entity-id=https://localhost:7070/metadata",
                "eidas.connector.service-providers[0].url=https://localhost:7070/metadata",
                "eidas.connector.service-providers[0].public-key=MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETy4hXQ65cMD7UaV1eKhLEkCGzXK7QWJA2KUkNgMc0iXwEX3e" +
                        "URJLNA0ZaaH+A9pfnIXLWeZ499IQ5NK4U4gEDVagEH4aXRCzZYjyYWRq9hOjEYzS84I/vsMQrt1kRQn7",
                "eidas.connector.service-providers[0].type=public"
        })
public class ApplicationHealthEndpointTests extends ApplicationHealthTest {

    @Test
    public void healthyApplicationState() {
        Instant testTime = Instant.now();
        when(gitProperties.getCommitId()).thenReturn("commit-id");
        when(gitProperties.getBranch()).thenReturn("branch");
        when(buildProperties.getName()).thenReturn("ee-specific-connector");
        when(buildProperties.getVersion()).thenReturn("0.0.1-SNAPSHOT");
        when(buildProperties.getTime()).thenReturn(testTime);

        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();

        assertEquals("UP", healthResponse.jsonPath().get("status"));
        assertEquals("ee-specific-connector", healthResponse.jsonPath().get("name"));
        assertEquals("0.0.1-SNAPSHOT", healthResponse.jsonPath().get("version"));
        assertEquals(testTime.toString(), healthResponse.jsonPath().get("buildTime"));
        assertEquals("commit-id", healthResponse.jsonPath().get("commitId"));
        assertEquals("branch", healthResponse.jsonPath().get("commitBranch"));
        assertNull(healthResponse.jsonPath().get("warnings"));
        assertStartAndUptime(healthResponse);
        assertAllDependenciesUp(healthResponse);
    }

    @Test
    public void healthyApplicationStateWhenMissingBuildAndGitInfo() {
        when(gitProperties.getCommitId()).thenReturn(null);
        when(gitProperties.getBranch()).thenReturn(null);
        when(buildProperties.getName()).thenReturn(null);
        when(buildProperties.getVersion()).thenReturn(null);
        when(buildProperties.getTime()).thenReturn(null);

        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();

        assertEquals("UP", healthResponse.jsonPath().get("status"));
        assertNull(healthResponse.jsonPath().get("commitId"));
        assertNull(healthResponse.jsonPath().get("commitBranch"));
        assertNull(healthResponse.jsonPath().get("name"));
        assertNull(healthResponse.jsonPath().get("version"));
        assertNull(healthResponse.jsonPath().get("buildTime"));
        assertNull(healthResponse.jsonPath().get("warnings"));
        assertStartAndUptime(healthResponse);
        assertAllDependenciesUp(healthResponse);
    }

    @Test
    public void healthyApplicationStateWhenMissingMetrics() {
        Search nonExistentMetric = meterRegistry.find("non-existent");
        Mockito.when(meterRegistry.find("process.start.time")).thenReturn(nonExistentMetric);
        Mockito.when(meterRegistry.find("process.uptime")).thenReturn(nonExistentMetric);
        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertNull(healthResponse.jsonPath().get("startTime"));
        assertNull(healthResponse.jsonPath().get("upTime"));
        assertAllDependenciesUp(healthResponse);
    }
}
