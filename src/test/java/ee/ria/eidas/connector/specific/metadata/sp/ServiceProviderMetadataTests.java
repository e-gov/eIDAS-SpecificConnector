package ee.ria.eidas.connector.specific.metadata.sp;

import ee.ria.eidas.connector.specific.metadata.responder.ResponderMetadataSigner;
import ee.ria.eidas.connector.specific.saml.OpenSAMLUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[0].type=public",
                "eidas.connector.service-providers[1].id=service-provider-1",
                "eidas.connector.service-providers[1].entity-id=https://localhost:9999/metadata",
                "eidas.connector.service-providers[1].key-alias=service-provider-1-metadata-signing",
                "eidas.connector.service-providers[1].type=public"
        })
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class ServiceProviderMetadataTests extends ServiceProviderTest {

    @Autowired
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @Autowired
    ResponderMetadataSigner responderMetadataSigner;

    @BeforeAll
    static void beforeAll() {
        startServiceProviderMetadataServer();
        startServiceProvider1MetadataServer("sp1-valid-metadata.xml");
    }

    @AfterAll
    static void afterAll() {
        mockSPMetadataServer.stop();
        mockSP1MetadataServer.stop();
    }

    @Test
    @SneakyThrows
    void requestSignatureValidationSucceedsWhen_ValidRequestSignature() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.getByEntityId(SP_ENTITY_ID);
        assertNotNull(spMetadata);
        assertTrue(spMetadata.isUpdatedAndValid());
        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        spMetadata.validate(authnRequest.getSignature());

        ServiceProviderMetadata sp1Metadata = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
        assertNotNull(sp1Metadata);
        assertTrue(sp1Metadata.isUpdatedAndValid());
        byte[] decodedAuthnRequest1 = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-valid-request-signature.xml"));
        AuthnRequest authnRequest1 = OpenSAMLUtils.unmarshall(decodedAuthnRequest1, AuthnRequest.class);
        sp1Metadata.validate(authnRequest1.getSignature());
    }

    @Test
    @SneakyThrows
    void signatureValidationFailsWhen_InvalidRequestSignature() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.getByEntityId(SP_ENTITY_ID);
        assertNotNull(spMetadata);
        assertTrue(spMetadata.isUpdatedAndValid());
        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-expired-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        SignatureException signatureException = assertThrows(SignatureException.class, () -> {
            spMetadata.validate(authnRequest.getSignature());
        });
        assertEquals("Signature cryptographic validation not successful", signatureException.getMessage());

        ServiceProviderMetadata spMetadata1 = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
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
