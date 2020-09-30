package ee.ria.eidas.connector.specific.metadata.responder;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SigningMethod;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import ee.ria.eidas.connector.specific.saml.OpenSAMLUtils;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import io.restassured.path.xml.element.NodeChildren;
import io.restassured.response.Response;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.joda.time.DateTime;
import org.joda.time.Hours;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.List;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.XML;
import static java.lang.Integer.parseInt;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "eidas.connector.responder-metadata.sp-type=private",
                "eidas.connector.responder-metadata.validity-in-days=2",
                "eidas.connector.responder-metadata.sso-service-url=https://localhost:8443/SpecificConnector/ServiceProvider",
                "eidas.connector.responder-metadata.name-id-format=urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "eidas.connector.responder-metadata.digest-methods[0]=http://www.w3.org/2000/09/xmldsig#sha1",
                "eidas.connector.responder-metadata.digest-methods[1]=http://www.w3.org/2001/04/xmldsig-more#sha224",
                "eidas.connector.responder-metadata.signing-methods[0].name=http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                "eidas.connector.responder-metadata.signing-methods[0].minKeySize=128",
                "eidas.connector.responder-metadata.signing-methods[0].maxKeySize=128",
                "eidas.connector.responder-metadata.signing-methods[1].name=http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                "eidas.connector.responder-metadata.signing-methods[1].minKeySize=256",
                "eidas.connector.responder-metadata.signing-methods[1].maxKeySize=256",
                "eidas.connector.responder-metadata.supported-attributes[0].name=http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                "eidas.connector.responder-metadata.supported-attributes[0].friendlyName=PersonIdentifier",
                "eidas.connector.responder-metadata.supported-attributes[1].name=http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
                "eidas.connector.responder-metadata.supported-attributes[1].friendlyName=DateOfBirth",
                "eidas.connector.responder-metadata.supported-bindings[0]=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        })
public class ResponderMetadataTests extends SpecificConnectorTest {

    private DateTime metadataRequestTime;
    private Response metadataResponse;

    @Autowired
    private SpecificConnectorProperties specificConnectorProperties;

    @Autowired
    private ResponderMetadataSigner responderMetadataSigner;

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
    public void metadataIsSignedAndContainsSigningCertificate() throws CertificateEncodingException, UnmarshallingException, XMLParserException, SignatureException {
        String X509Certificate = metadataResponse.xmlPath().getString("EntityDescriptor.Signature.KeyInfo.X509Data.X509Certificate");
        BasicX509Credential signingCredential = (BasicX509Credential) responderMetadataSigner.getSigningCredential();
        byte[] derEncoded = signingCredential.getEntityCertificate().getEncoded();
        assertEquals(Base64.getEncoder().encodeToString(derEncoded), X509Certificate.replaceAll("\n", ""));

        EntityDescriptor responderMetadata = OpenSAMLUtils.unmarshall(metadataResponse.getBody().asByteArray(), EntityDescriptor.class);
        responderMetadataSigner.validate(responderMetadata.getSignature());
    }

    @Test
    public void entityIdIsSet() {
        String entityID = metadataResponse.xmlPath().getString("EntityDescriptor.@entityID");
        assertEquals(specificConnectorProperties.getResponderMetadata().getEntityId(), entityID);
    }

    @Test
    public void defaultSPTypeCanBeOverridden() {
        assertEquals("private", specificConnectorProperties.getResponderMetadata().getSpType());
        String spType = metadataResponse.xmlPath().getString("EntityDescriptor.Extensions.SPType");
        assertEquals("private", spType);
    }

    @Test
    public void defaultValidityInDaysCanBeOverridden() {
        assertEquals(2, specificConnectorProperties.getResponderMetadata().getValidityInDays());
        DateTime validUntil = DateTime.parse(metadataResponse.xmlPath().getString("EntityDescriptor.@validUntil"));
        assertEquals(48, Hours.hoursBetween(metadataRequestTime, validUntil).getHours());
    }

    @Test
    public void defaultDigestMethodsCanBeOverridden() {
        List<String> referenceList = asList("http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmldsig-more#sha224");
        List<String> metadataDigestMethods = metadataResponse.xmlPath().getList("EntityDescriptor.Extensions.DigestMethod.@Algorithm");
        assertThat(specificConnectorProperties.getResponderMetadata().getDigestMethods()).containsExactlyElementsOf(referenceList);
        assertThat(metadataDigestMethods).containsExactlyElementsOf(referenceList);
    }

    @Test
    public void defaultSigningMethodsCanBeOverridden() {
        List<SigningMethod> referenceList = asList(SigningMethod.builder().name(ALGO_ID_SIGNATURE_ECDSA_SHA512).minKeySize(128).maxKeySize(128).build(),
                SigningMethod.builder().name(ALGO_ID_SIGNATURE_ECDSA_SHA256).minKeySize(256).maxKeySize(256).build());
        NodeChildren nodeChildren = metadataResponse.xmlPath().getNodeChildren("EntityDescriptor.Extensions.SigningMethod");
        assertNotNull(nodeChildren);
        List<SigningMethod> signingMethods = nodeChildren.list().stream().map(n -> SigningMethod.builder()
                .name(n.getAttribute("Algorithm"))
                .minKeySize(parseInt(n.getAttribute("MinKeySize")))
                .maxKeySize(parseInt(n.getAttribute("MaxKeySize"))).build()).collect(toList());
        assertThat(signingMethods).containsExactlyElementsOf(referenceList);
    }

    @Test
    public void defaultSupportedBindingsCanBeOverridden() {
        List<String> referenceBindingList = singletonList(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        List<String> metadataSupportedBindings = metadataResponse.xmlPath().getList("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Binding");
        assertThat(specificConnectorProperties.getResponderMetadata().getSupportedBindings()).containsExactlyElementsOf(referenceBindingList);
        assertThat(metadataSupportedBindings).containsExactlyElementsOf(referenceBindingList);

        String ssoServiceUrl = specificConnectorProperties.getResponderMetadata().getSsoServiceUrl();
        List<String> metadataBindingLocations = metadataResponse.xmlPath().getList("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Location");
        assertEquals("https://localhost:8443/SpecificConnector/ServiceProvider", ssoServiceUrl);
        assertThat(metadataBindingLocations).containsExactly(ssoServiceUrl);
    }

    @Test
    public void defaultSupportedAttributesCanBeOverridden() {
        List<SupportedAttribute> referenceList = of(NaturalPersonSpec.Definitions.PERSON_IDENTIFIER, NaturalPersonSpec.Definitions.DATE_OF_BIRTH)
                .map(def -> SupportedAttribute.builder().name(def.getNameUri().toString()).friendlyName(def.getFriendlyName()).build())
                .collect(toList());
        NodeChildren nodeChildren = metadataResponse.xmlPath().getNodeChildren("EntityDescriptor.IDPSSODescriptor.Attribute");
        assertNotNull(nodeChildren);
        List<SupportedAttribute> signingMethods = nodeChildren.list().stream().map(n -> SupportedAttribute.builder()
                .name(n.getAttribute("Name"))
                .friendlyName(n.getAttribute("FriendlyName"))
                .build()).collect(toList());
        assertThat(signingMethods).containsExactlyElementsOf(referenceList);
    }

    @Test
    public void defaultNameIdFormatCanBeOverridden() {
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", specificConnectorProperties.getResponderMetadata().getNameIDFormat());
        String nameIDFormat = metadataResponse.xmlPath().getString("EntityDescriptor.IDPSSODescriptor.NameIDFormat");
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", nameIDFormat);
    }
}
