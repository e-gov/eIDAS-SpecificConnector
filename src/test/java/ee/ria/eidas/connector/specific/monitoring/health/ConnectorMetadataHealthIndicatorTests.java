package ee.ria.eidas.connector.specific.monitoring.health;


import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
public class ConnectorMetadataHealthIndicatorTests extends ApplicationHealthTest {

    @Test
    void healthStatusDownWhen_EidasNodeDown() {
        mockEidasNodeMetadataServer.stubFor(get(urlEqualTo("/EidasNode/ConnectorMetadata"))
                .willReturn(aResponse()
                        .withStatus(404)));
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.CONNECTOR_METADATA);
    }
}
