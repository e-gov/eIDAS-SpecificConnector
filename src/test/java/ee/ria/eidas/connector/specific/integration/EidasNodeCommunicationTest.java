package ee.ria.eidas.connector.specific.integration;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.LightRequestFactory;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.test.context.TestPropertySource;

import javax.cache.Cache;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import java.io.IOException;

import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false)
class EidasNodeCommunicationTest extends SpecificConnectorTest {

    @Value("${lightToken.connector.request.issuer.name}")
    String lightTokenRequestIssuerName;

    @Value("${lightToken.connector.request.secret}")
    String lightTokenRequestSecret;

    @Value("${lightToken.connector.request.algorithm}")
    String lightTokenRequestAlgorithm;

    @Autowired
    EidasNodeCommunication eidasNodeCommunication;

    @Autowired
    LightRequestFactory lightRequestFactory;

    @Autowired
    Cache<String, String> specificNodeConnectorRequestCache;

    @Autowired
    MappingJackson2XmlHttpMessageConverter xmlMapper;

    @Test
    void lightRequestRetrieavableByLightTokenWhen_putLightRequest() throws IOException, UnmarshallingException, XMLParserException, SpecificCommunicationException, JAXBException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        ILightRequest lightRequest = lightRequestFactory.createLightRequest(authnRequest, "CA", "_5a5a7cd4616f46813fda1cd350cab476", "public");
        BinaryLightToken binaryLightToken = eidasNodeCommunication.putLightRequest(lightRequest);
        String tokenId = binaryLightToken.getToken().getId();

        String lightRequestFromCache = specificNodeConnectorRequestCache.getAndRemove(tokenId);
        assertNotNull(lightRequestFromCache);

        EidasNodeCommunication.LightJAXBCodec codec = new EidasNodeCommunication.LightJAXBCodec(JAXBContext.newInstance(LightRequest.class, LightResponse.class,
                ImmutableAttributeMap.class, AttributeDefinition.class));
        String originalLightRequest = codec.marshall(lightRequest);
        assertEquals(originalLightRequest, lightRequestFromCache);
    }
}