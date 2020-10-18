package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.XML;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "eidas.connector.responder-metadata.path=/CustomResponderMetadataPath"
        })
public class ResponderMetadataEnpointPathTest extends SpecificConnectorTest {

    @Test
    void metadataAvailableWhen_CustomEndpointPathIsSet() {
        Response response = given()
                .when()
                .get("/CustomResponderMetadataPath")
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(XML).extract().response();
        String entityId = response.xmlPath().getString("EntityDescriptor.@entityID");
        assertEquals(specificConnectorProperties.getResponderMetadata().getEntityId(), entityId);
    }
}
