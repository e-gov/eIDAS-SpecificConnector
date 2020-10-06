package ee.ria.eidas.connector.specific.metadata.responder;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SigningMethod;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import io.restassured.path.xml.element.NodeChildren;
import io.restassured.response.Response;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.joda.time.Hours;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.XML;
import static java.lang.Integer.parseInt;
import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class ResponderMetadataDefaultValueTests extends SpecificConnectorTest {
    private DateTime metadataRequestTime;
    private Response metadataResponse;

    @Autowired
    private SpecificConnectorProperties specificConnectorProperties;

    @BeforeEach
    public void setUp() {
        metadataRequestTime = DateTime.now();
        metadataResponse = given()
                .when()
                .get("/ConnectorResponderMetadata")
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(XML).extract().response();
    }

    @Test
    public void defaultSPTypeIsPublic() {
        String spType = metadataResponse.xmlPath().getString("EntityDescriptor.Extensions.SPType");
        assertEquals("public", spType);
    }

    @Test
    public void defaultValidUntilIs24hours() {
        DateTime validUntil = DateTime.parse(metadataResponse.xmlPath().getString("EntityDescriptor.@validUntil"));
        assertEquals(24, Hours.hoursBetween(metadataRequestTime, validUntil).getHours());
    }

    @Test
    public void defaultDigestMethodsAreSet() {
        List<String> metadataDigestMethods = metadataResponse.xmlPath().getList("EntityDescriptor.Extensions.DigestMethod.@Algorithm");
        Set<String> referenceList = SpecificConnectorProperties.ResponderMetadata.DEFAULT_DIGEST_METHODS;
        assertThat(metadataDigestMethods).containsExactlyElementsOf(referenceList);
    }

    @Test
    public void defaultSigningMethodsAreSet() {
        NodeChildren nodeChildren = metadataResponse.xmlPath().getNodeChildren("EntityDescriptor.Extensions.SigningMethod");
        assertNotNull(nodeChildren);
        List<SigningMethod> signingMethods = nodeChildren.list().stream().map(n -> new SigningMethod(n.getAttribute("Algorithm"),
                parseInt(n.getAttribute("MinKeySize")),
                parseInt(n.getAttribute("MaxKeySize")))).collect(toList());
        List<SigningMethod> referenceList = SpecificConnectorProperties.ResponderMetadata.DEFAULT_SIGNING_METHODS;
        assertThat(signingMethods).containsExactlyElementsOf(referenceList);
    }

    @Test
    public void defaultSupportedBindingsAreSet() {
        List<String> metadataSupportedBindings = metadataResponse.xmlPath().getList("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Binding");
        Set<String> referenceList = SpecificConnectorProperties.ResponderMetadata.DEFAULT_SUPPORTED_BINDINGS;
        assertThat(metadataSupportedBindings).containsExactlyElementsOf(referenceList);

        String ssoServiceUrl = specificConnectorProperties.getResponderMetadata().getSsoServiceUrl();
        List<String> metadataBindingLocations = metadataResponse.xmlPath().getList("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Location");
        assertEquals("https://localhost:8443/SpecificConnector/ServiceProvider", ssoServiceUrl);
        assertThat(metadataBindingLocations).containsExactly(ssoServiceUrl, ssoServiceUrl);
    }

    @Test
    public void defaultSupportedAttributesAreSet() {
        NodeChildren nodeChildren = metadataResponse.xmlPath().getNodeChildren("EntityDescriptor.IDPSSODescriptor.Attribute");
        assertNotNull(nodeChildren);
        List<SupportedAttribute> signingMethods = nodeChildren.list().stream().map(n -> new SupportedAttribute(n.getAttribute("Name"), n.getAttribute("FriendlyName")))
                .collect(toList());
        List<SupportedAttribute> referenceList = SpecificConnectorProperties.ResponderMetadata.DEFAULT_SUPPORTED_ATTRIBUTES;
        assertThat(signingMethods).containsExactlyElementsOf(referenceList);
    }

    @Test
    public void defaultWantAuthnRequestsSignedIsTrue() {
        boolean isWantAuthnRequestsSigned = metadataResponse.xmlPath().getBoolean("EntityDescriptor.IDPSSODescriptor.@WantAuthnRequestsSigned");
        assertTrue(isWantAuthnRequestsSigned);
    }

    @Test
    public void defaultProtocolSupportEnumeration() {
        String protocol = metadataResponse.xmlPath().getString("EntityDescriptor.IDPSSODescriptor.@protocolSupportEnumeration");
        assertEquals("urn:oasis:names:tc:SAML:2.0:protocol", protocol);
    }

    @Test
    public void defaultNameIdFormatNotSet() {
        NodeChildren nameIDFormat = metadataResponse.xmlPath().getNodeChildren("EntityDescriptor.IDPSSODescriptor.NameIDFormat");
        assertTrue(nameIDFormat.isEmpty());
    }
}
