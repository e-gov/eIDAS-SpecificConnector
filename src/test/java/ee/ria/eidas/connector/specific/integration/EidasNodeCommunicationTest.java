package ee.ria.eidas.connector.specific.integration;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.LightRequestFactory;
import ee.ria.eidas.connector.specific.util.TestUtils;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.cache.Cache;
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

    @Test
    void lightRequestRetrieavableByLightTokenWhen_putLightRequest() throws IOException, UnmarshallingException, XMLParserException, SpecificCommunicationException, JAXBException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        ILightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "CA", "_5a5a7cd4616f46813fda1cd350cab476");
        BinaryLightToken binaryLightToken = eidasNodeCommunication.putLightRequest(lightRequest);
        String tokenId = binaryLightToken.getToken().getId();

        String lightRequestFromCache = specificNodeConnectorRequestCache.getAndRemove(tokenId);
        assertNotNull(lightRequestFromCache);

        LightJAXBCodec codec = LightJAXBCodec.buildDefault();
        String originalLightRequest = codec.marshall(lightRequest);
        assertEquals(originalLightRequest, lightRequestFromCache);
    }
}
