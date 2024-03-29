package ee.ria.eidas.connector.specific.responder.serviceprovider;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.OpenSAMLConfiguration;
import ee.ria.eidas.connector.specific.config.ResponderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.util.TestUtils;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.impl.LevelOfAssurance;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.util.ResourceUtils.getFile;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {OpenSAMLConfiguration.class, ResponderMetadataConfiguration.class, LightRequestFactory.class}, initializers = SpecificConnectorTest.TestContextInitializer.class)
@EnableConfigurationProperties(value = SpecificConnectorProperties.ResponderMetadata.class)
@TestPropertySource(value = "classpath:application-test.properties")
class LightRequestFactoryTest {

    @Autowired
    LightRequestFactory lightRequestFactory;

    @Autowired
    AttributeRegistry supportedAttributesRegistry;

    @Test
    void createValidLightRequest() throws IOException, UnmarshallingException, XMLParserException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        ILightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "CA", "_5a5a7cd4616f46813fda1cd350cab476");

        String correlationId = lightRequestFactory.getCorrelationId(authnRequest);
        assertEquals(correlationId, lightRequest.getId());
        assertEquals(authnRequest.getIssuer().getValue(), lightRequest.getIssuer());
        assertEquals(authnRequest.getProviderName(), lightRequest.getProviderName());
        assertEquals(authnRequest.getNameIDPolicy().getFormat(), lightRequest.getNameIdFormat());

        Optional<LevelOfAssurance> levelOfAssurance = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().stream()
                .map(ref -> LevelOfAssurance.build(ref.getAuthnContextClassRef()))
                .findFirst();
        assertTrue(levelOfAssurance.isPresent());
        assertEquals(levelOfAssurance.get().getValue(), lightRequest.getLevelOfAssurance());

        ImmutableAttributeMap requestedAttributes = getRequestedAttributes(authnRequest);
        assertThat(requestedAttributes.getDefinitions()).containsExactlyInAnyOrderElementsOf(lightRequest.getRequestedAttributes().getDefinitions());
        assertEquals("public", lightRequest.getSpType());
        assertEquals("CA", lightRequest.getCitizenCountryCode());
        assertEquals("_5a5a7cd4616f46813fda1cd350cab476", lightRequest.getRelayState());
    }

    @Test
    void createValidCorrelationId() throws IOException, UnmarshallingException, XMLParserException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        ILightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "CA", "_5a5a7cd4616f46813fda1cd350cab476");

        String correlationId = lightRequestFactory.getCorrelationId(authnRequest);
        assertEquals("5a968926a873fc52e65e6e87a2fbe0f7918cc0d18401ec3da366f2066a5c87ab07a497adffa521f16d3d7a0801d088819511c8f39beebb60a44b409851c64ca7", correlationId);
        assertEquals(correlationId, lightRequest.getId());
    }

    private ImmutableAttributeMap getRequestedAttributes(AuthnRequest authn) {
        Extensions extensions = authn.getExtensions();
        assertNotNull(extensions);
        QName requestedAttributesQName = new QName("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");
        List<XMLObject> bindings = extensions.getUnknownXMLObjects(requestedAttributesQName);
        assertFalse(bindings.isEmpty());
        XMLObject requestedAttributes = bindings.get(0);
        assertNotNull(requestedAttributes.getOrderedChildren());
        ImmutableAttributeMap.Builder requestedAttributesBuilder = ImmutableAttributeMap.builder();
        requestedAttributes.getOrderedChildren().forEach(requestedAttribute -> {
            Element element = requestedAttribute.getDOM();
            if (element != null) {
                AttributeDefinition<?> attribute = supportedAttributesRegistry.getByName(element.getAttribute("Name"));
                assertNotNull(attribute);
                requestedAttributesBuilder.put(attribute);
            }
        });
        return requestedAttributesBuilder.build();
    }
}
