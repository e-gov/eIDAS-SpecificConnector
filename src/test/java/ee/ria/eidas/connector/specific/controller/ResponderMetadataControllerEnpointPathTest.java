package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.XML;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "eidas.connector.responder-metadata.entity-id=https://localhost:8443/SpecificConnector/ConnectorResponderMetadata",
                "eidas.connector.responder-metadata.path=/CustomResponderMetadataPath"
        })
public class ResponderMetadataControllerEnpointPathTest extends SpecificConnectorTest {

    @Autowired
    SpecificConnectorProperties connectorProperties;

    @Test
    void metadataAvailableWhen_CustomEndpointPathIsSet() throws XMLParserException, UnmarshallingException {
        Response response = given()
                .when()
                .get("/CustomResponderMetadataPath")
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(XML).extract().response();
        EntityDescriptor entityDescriptor = OpenSAMLUtils.unmarshall(response.asByteArray(), EntityDescriptor.class);
        assertEquals("https://localhost:8443/SpecificConnector/ConnectorResponderMetadata", entityDescriptor.getEntityID());
    }
}
