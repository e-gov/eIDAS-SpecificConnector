package ee.ria.eidas.connector.specific.monitoring;

import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import io.micrometer.core.instrument.search.Search;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[0].type=public"
        })
public class ApplicationHealthEndpointTests extends ApplicationHealthTest {

    @Autowired
    protected ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @BeforeEach
    void resetSPMetadata() throws ResolverException {
        updateServiceProviderMetadata("sp-valid-metadata.xml");
        serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
    }

    @Test
    void healthyApplicationState() {
        Instant testTime = Instant.now();
        when(gitProperties.getCommitId()).thenReturn("commit-id");
        when(gitProperties.getBranch()).thenReturn("branch");
        when(buildProperties.getName()).thenReturn("ms-specific-connector");
        when(buildProperties.getVersion()).thenReturn("1.0.0-SNAPSHOT");
        when(buildProperties.getTime()).thenReturn(testTime);

        Response healthResponse = getHealthResponse();

        assertEquals("UP", healthResponse.jsonPath().get("status"));
        assertEquals("ms-specific-connector", healthResponse.jsonPath().get("name"));
        assertEquals("1.0.0-SNAPSHOT", healthResponse.jsonPath().get("version"));
        assertEquals(testTime.toString(), healthResponse.jsonPath().get("buildTime"));
        assertEquals("commit-id", healthResponse.jsonPath().get("commitId"));
        assertEquals("branch", healthResponse.jsonPath().get("commitBranch"));
        assertNull(healthResponse.jsonPath().get("warnings"));
        assertStartAndUptime(healthResponse);
        assertAllDependenciesUp(healthResponse);
    }

    @Test
    void healthyApplicationStateWhen_MissingBuildAndGitInfo() {
        updateServiceProviderMetadata("sp-valid-metadata.xml");
        when(gitProperties.getCommitId()).thenReturn(null);
        when(gitProperties.getBranch()).thenReturn(null);
        when(buildProperties.getName()).thenReturn(null);
        when(buildProperties.getVersion()).thenReturn(null);
        when(buildProperties.getTime()).thenReturn(null);

        Response healthResponse = getHealthResponse();

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
    void healthyApplicationStateWhen_MissingMetrics() {
        updateServiceProviderMetadata("sp-valid-metadata.xml");
        Search nonExistentMetric = meterRegistry.find("non-existent");
        Mockito.when(meterRegistry.find("process.start.time")).thenReturn(nonExistentMetric);
        Mockito.when(meterRegistry.find("process.uptime")).thenReturn(nonExistentMetric);
        Response healthResponse = getHealthResponse();

        assertNull(healthResponse.jsonPath().get("startTime"));
        assertNull(healthResponse.jsonPath().get("upTime"));
        assertAllDependenciesUp(healthResponse);
    }
}
