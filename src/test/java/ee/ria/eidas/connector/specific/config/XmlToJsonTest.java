package ee.ria.eidas.connector.specific.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.jayway.jsonpath.JsonPath;
import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static ee.ria.eidas.connector.specific.config.OpenSAMLConfiguration.DEFAULT_TEXT_ELEMENT_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {OpenSAMLConfiguration.class, ResponderMetadataConfiguration.class}, initializers = SpecificConnectorTest.TestContextInitializer.class)
@EnableConfigurationProperties(value = SpecificConnectorProperties.ResponderMetadata.class)
@TestPropertySource(value = "classpath:application-test.properties")
public class XmlToJsonTest {

    @Autowired
    MappingJackson2XmlHttpMessageConverter xmlMapper;

    @Test
    void defaultTextElementNameUsedWhen_XmlElementContainsSimultaneouslyAttributeAndElementValue() throws JsonProcessingException {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://localhost:8443/SpecificConnector/ConnectorResponderMetadata</saml2:Issuer></saml2p:Response>";
        JsonNode samResponseJson = xmlMapper.getObjectMapper().readTree(xml);
        String expectedProperty = "$.Issuer." + DEFAULT_TEXT_ELEMENT_NAME;
        assertEquals("https://localhost:8443/SpecificConnector/ConnectorResponderMetadata", JsonPath.read(samResponseJson.toString(), expectedProperty));
    }
}
