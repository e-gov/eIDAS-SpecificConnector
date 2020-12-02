package ee.ria.eidas.connector.specific.responder.serviceprovider;

import ee.ria.eidas.connector.specific.config.OpenSAMLConfiguration;
import ee.ria.eidas.connector.specific.config.ResponderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.ServiceProviderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.exception.CertificateResolverException;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.awaitility.Durations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;

import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = SpecificConnectorProperties.class)
@ContextConfiguration(classes = {ServiceProviderMetadataConfiguration.class, ResponderMetadataConfiguration.class, OpenSAMLConfiguration.class})
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.service-provider-metadata-min-refresh-delay=1000",
                "eidas.connector.service-provider-metadata-max-refresh-delay=60000",
                "eidas.connector.service-provider-metadata-refresh-delay-factor=0.99",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[0].type=public",
                "eidas.connector.service-providers[1].id=service-provider-1",
                "eidas.connector.service-providers[1].entity-id=https://localhost:9999/metadata",
                "eidas.connector.service-providers[1].key-alias=service-provider-1-metadata-signing",
                "eidas.connector.service-providers[1].type=public"
        })
public class ServiceProviderMetadataInitializationTests extends ServiceProviderTest {

    @BeforeAll
    static void beforeAll() {
        mockSP1MetadataServer.resetAll();
    }

    @AfterEach
    void afterEach() {
        mockSP1MetadataServer.resetAll();
    }

    @ParameterizedTest
    @ValueSource(strings = {"sp1-expired-valid-until.xml", "sp1-untrusted-metadata-signing-cert.xml", "sp1-expired-metadata-signing-cert.xml", "sp1-expired-request-signing-cert.xml", "sp1-expired-response-encryption-cert.xml"})
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.BEFORE_METHOD)
    void responseValidationFails(String invalidMetadataState) throws ResolverException, XMLParserException, UnmarshallingException, IOException, SignatureException {
        updateServiceProvider1Metadata(invalidMetadataState);
        assertInvalidMetadataState(!invalidMetadataState.equals("sp1-expired-valid-until.xml"));
        assertRequestSignatureValidationFails();
        updateServiceProvider1Metadata("sp1-valid-metadata.xml");
        assertRequestSignatureValidationSucceeds();
    }

    private void assertRequestSignatureValidationFails() throws IOException, net.shibboleth.utilities.java.support.xml.XMLParserException, org.opensaml.core.xml.io.UnmarshallingException {
        ServiceProviderMetadata sp1Metadata = serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID);
        assertNotNull(sp1Metadata);
        assertFalse(sp1Metadata.isUpdatedAndValid());

        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        CertificateResolverException resolverException = assertThrows(CertificateResolverException.class, () -> sp1Metadata.validate(authnRequest.getSignature()));
        assertEquals(UsageType.SIGNING, resolverException.getUsageType());
        assertEquals("Metadata SIGNING certificate missing or invalid", resolverException.getMessage());
    }

    private void assertRequestSignatureValidationSucceeds() throws IOException, net.shibboleth.utilities.java.support.xml.XMLParserException, org.opensaml.core.xml.io.UnmarshallingException, SignatureException, ResolverException {
        ServiceProviderMetadata sp1Metadata = serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID);
        assertNotNull(sp1Metadata);

        await()
                .atMost(Durations.TEN_SECONDS)
                .untilAsserted(() -> assertTrue(sp1Metadata.isUpdatedAndValid()));

        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        sp1Metadata.validate(authnRequest.getSignature());
    }
}

