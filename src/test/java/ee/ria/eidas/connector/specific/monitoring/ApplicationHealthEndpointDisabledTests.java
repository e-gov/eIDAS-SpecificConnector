package ee.ria.eidas.connector.specific.monitoring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static io.restassured.RestAssured.given;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.jmx.exposure.exclude=*",
                "management.endpoints.web.exposure.exclude=*"
        })
class ApplicationHealthEndpointDisabledTests extends ApplicationHealthTest {

    @Test
    void healthEndpointNotAccessibleWhen_EndpointDisabled() {
        given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(404);
    }
}
