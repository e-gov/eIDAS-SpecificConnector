package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataSigner;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import io.restassured.response.Response;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ClasspathResolver;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.XML;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.responder-metadata.name-id-format=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "eidas.connector.responder-metadata.sp-type=public",
                "eidas.connector.responder-metadata.supported-member-states=LV,LT",
                "eidas.connector.responder-metadata.contacts[0].surname=SupportSurName",
                "eidas.connector.responder-metadata.contacts[0].given-name=SupportGivenName",
                "eidas.connector.responder-metadata.contacts[0].company=SupportCompany",
                "eidas.connector.responder-metadata.contacts[0].phone=+372 111 1111",
                "eidas.connector.responder-metadata.contacts[0].email=support@ria.ee",
                "eidas.connector.responder-metadata.contacts[0].type=support",
                "eidas.connector.responder-metadata.contacts[1].surname=TechnicalSurName",
                "eidas.connector.responder-metadata.contacts[1].given-name=TechnicalGivenName",
                "eidas.connector.responder-metadata.contacts[1].company=TechnicalCompany",
                "eidas.connector.responder-metadata.contacts[1].phone=+372 222 2222",
                "eidas.connector.responder-metadata.contacts[1].email=technical@ria.ee",
                "eidas.connector.responder-metadata.contacts[1].type=technical",
                "eidas.connector.responder-metadata.organization.name=Estonian Information System Authority",
                "eidas.connector.responder-metadata.organization.display-name=RIA",
                "eidas.connector.responder-metadata.organization.url=https://www.ria.ee"
        })
public class ResponderMetadataControllerTests extends SpecificConnectorTest {

    private Response metadataResponse;

    @Autowired
    SpecificConnectorProperties specificConnectorProperties;

    @Autowired
    ResponderMetadataSigner responderMetadataSigner;

    @BeforeEach
    void setUp() {
        metadataResponse = given()
                .when()
                .get("/ConnectorResponderMetadata")
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(XML).extract().response();
    }

    @Test
    void metadataXmlValidWhen_MetadataRequested() throws SAXException, IOException {
        String language = XMLConstants.W3C_XML_SCHEMA_NS_URI;
        SchemaFactory factory = SchemaFactory.newInstance(language);
        factory.setResourceResolver((type, namespaceURI, publicId, systemId, baseURI)
                -> new ClasspathResolver().resolveResource(type, namespaceURI, publicId, systemId, baseURI));
        Schema schema = factory.newSchema(getFile("classpath:__files/saml/saml-schema-metadata-2.0.xsd"));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new ByteArrayInputStream(metadataResponse.asString().getBytes())));
    }

    @Test
    void metadataIsSignedAndContainsSigningCertificateWhen_MetadataRequested() throws CertificateEncodingException, UnmarshallingException, XMLParserException, SignatureException {
        String signingCertificate = metadataResponse.xmlPath().getString("EntityDescriptor.Signature.KeyInfo.X509Data.X509Certificate");
        BasicX509Credential signingCredential = (BasicX509Credential) responderMetadataSigner.getSigningCredential();
        byte[] expectedSigningCertificate = signingCredential.getEntityCertificate().getEncoded();
        assertArrayEquals(expectedSigningCertificate, Base64.decode(signingCertificate));
        EntityDescriptor responderMetadata = OpenSAMLUtils.unmarshall(metadataResponse.getBody().asByteArray(), EntityDescriptor.class);
        responderMetadataSigner.validate(responderMetadata.getSignature());
    }
}
