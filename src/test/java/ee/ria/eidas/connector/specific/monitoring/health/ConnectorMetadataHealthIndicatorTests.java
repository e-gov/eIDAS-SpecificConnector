package ee.ria.eidas.connector.specific.monitoring.health;


import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
public class ConnectorMetadataHealthIndicatorTests extends ApplicationHealthTest {

    @Test
    public void healthStatusDownWhenEidasNodeDown() {
        mockEidasNodeServer.stubFor(get(urlEqualTo("/EidasNode/ConnectorMetadata"))
                .willReturn(aResponse()
                        .withStatus(404)));
        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertDependenciesDown(healthResponse, Dependencies.CONNECTOR_METADATA);
    }
}
