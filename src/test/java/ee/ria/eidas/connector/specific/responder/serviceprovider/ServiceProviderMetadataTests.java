package ee.ria.eidas.connector.specific.responder.serviceprovider;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.OpenSAMLConfiguration;
import ee.ria.eidas.connector.specific.config.ResponderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.ServiceProviderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorTestConfiguration;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataGenerator;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataSigner;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.util.TestUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {OpenSAMLConfiguration.class, SpecificConnectorConfiguration.class, ResponderMetadataConfiguration.class,
        ServiceProviderMetadataConfiguration.class, SpecificConnectorTestConfiguration.class,
        ServiceProviderMetadataRegistry.class, ResponderMetadataGenerator.class, ResponderMetadataSigner.class}, initializers = SpecificConnectorTest.TestContextInitializer.class)
@TestPropertySource(value = "classpath:application-test.properties",
        properties = {
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[1].id=service-provider-1",
                "eidas.connector.service-providers[1].entity-id=https://localhost:9999/metadata",
                "eidas.connector.service-providers[1].key-alias=service-provider-1-metadata-signing",
        })
public class ServiceProviderMetadataTests extends ServiceProviderTest {

    @Autowired
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @Autowired
    ResponderMetadataSigner responderMetadataSigner;

    @BeforeAll
    static void beforeAll() {
        startServiceProviderMetadataServer();
        startServiceProvider1MetadataServer();
    }

    @AfterAll
    static void afterAll() {
        mockSPMetadataServer.stop();
        mockSP1MetadataServer.stop();
    }

    @Test
    @SneakyThrows
    void requestSignatureValidationSucceedsWhen_ValidRequestSignature() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.get(SP_ENTITY_ID);
        assertNotNull(spMetadata);
        assertTrue(spMetadata.isUpdatedAndValid());
        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        spMetadata.validate(signedAuthnRequest.getSignature());

        ServiceProviderMetadata sp1Metadata = serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID);
        assertNotNull(sp1Metadata);
        assertTrue(sp1Metadata.isUpdatedAndValid());
        byte[] decodedAuthnRequest1 = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-valid-request-signature.xml"));
        AuthnRequest authnRequest1 = OpenSAMLUtils.unmarshall(decodedAuthnRequest1, AuthnRequest.class);
        sp1Metadata.validate(authnRequest1.getSignature());
    }

    @Test
    @SneakyThrows
    void signatureValidationFailsWhen_InvalidRequestSignature() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.get(SP_ENTITY_ID);
        assertNotNull(spMetadata);
        assertTrue(spMetadata.isUpdatedAndValid());
        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-expired-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        SignatureException signatureException = assertThrows(SignatureException.class, () -> {
            spMetadata.validate(authnRequest.getSignature());
        });
        assertEquals("Signature cryptographic validation not successful", signatureException.getMessage());

        ServiceProviderMetadata spMetadata1 = serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID);
        assertNotNull(spMetadata1);
        assertTrue(spMetadata1.isUpdatedAndValid());
        byte[] decodedAuthnRequest1 = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-expired-request-signature.xml"));
        AuthnRequest authnRequest1 = OpenSAMLUtils.unmarshall(decodedAuthnRequest1, AuthnRequest.class);
        SignatureException signatureException1 = assertThrows(SignatureException.class, () -> {
            spMetadata1.validate(authnRequest1.getSignature());
        });
        assertEquals("Signature cryptographic validation not successful", signatureException1.getMessage());
    }
}
