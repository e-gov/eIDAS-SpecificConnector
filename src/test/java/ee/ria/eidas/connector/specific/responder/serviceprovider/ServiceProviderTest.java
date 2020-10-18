package ee.ria.eidas.connector.specific.responder.serviceprovider;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.awaitility.Durations;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.lang.String.format;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.util.ResourceUtils.getFile;

abstract class ServiceProviderTest extends SpecificConnectorTest {
    static final String SP_1_ENTITY_ID = "https://localhost:9999/metadata";
    static final WireMockServer mockSP1MetadataServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/service-provider-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(9999)
    );

    @Autowired
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @BeforeAll
    static void beforeAll() {
        startServiceProviderMetadataServer();
    }

    @AfterAll
    static void afterAll() {
        mockSPMetadataServer.stop();
        mockSP1MetadataServer.stop();
    }

    static void startServiceProvider1MetadataServer(String metadataFileName) {
        mockSP1MetadataServer.start();
        mockSP1MetadataServer.resetAll();
        mockSP1MetadataServer.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse()
                .withHeader("Content-Type", "application/xml;charset=UTF-8")
                .withStatus(200)
                .withBodyFile("sp_metadata/" + metadataFileName)));
    }

    static void updateServiceProvider1Metadata(String metadataFile) {
        updateServiceProviderMetadata(mockSP1MetadataServer, metadataFile);
    }

    protected void assertValidMetadataAfterServiceProviderMetadataUpdate() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.getByEntityId(SP_ENTITY_ID);
        assertSuccessfulInitialization(spMetadata);

        ServiceProviderMetadata spMetadata1 = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
        assertNotNull(spMetadata1);
        assertFalse(spMetadata1.isUpdatedAndValid());
        assertLogs(INFO, format("Initializing metadata resolver for: %s", spMetadata1));
        assertLogs(ERROR, "Metadata Resolver HTTPMetadataResolver service-provider-1: Error occurred while attempting to refresh metadata from 'https://localhost:9999/metadata'",
                "Metadata Resolver HTTPMetadataResolver service-provider-1: Metadata provider failed to properly initialize, fail-fast=false, continuing on in a degraded state");
        updateServiceProvider1Metadata("sp1-valid-metadata.xml");

        await()
                .pollInterval(Durations.ONE_SECOND)
                .pollDelay(Durations.ONE_SECOND)
                .atMost(Durations.TEN_SECONDS)
                .untilAsserted(() -> assertTrue(serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID).isUpdatedAndValid()));

        assertTestLogs(INFO, "Metadata Resolver HTTPMetadataResolver service-provider-1: New metadata successfully loaded for 'https://localhost:9999/metadata'",
                "Metadata Resolver HTTPMetadataResolver service-provider-1: Next refresh cycle for metadata provider 'https://localhost:9999/metadata' will occur on ");
    }

    protected void assertUnsuccessfulRequestSignatureValidation() throws IOException, net.shibboleth.utilities.java.support.xml.XMLParserException, org.opensaml.core.xml.io.UnmarshallingException {
        ServiceProviderMetadata sp1Metadata = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
        assertNotNull(sp1Metadata);
        assertFalse(sp1Metadata.isUpdatedAndValid());

        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        ConstraintViolationException constraintViolationException = assertThrows(ConstraintViolationException.class, () -> sp1Metadata.validate(authnRequest.getSignature()));
        assertEquals("Validation credential cannot be null", constraintViolationException.getMessage()); // TODO: More meaningful exception?
    }

    protected void assertSuccessfulRequestSignatureValidation() throws IOException, net.shibboleth.utilities.java.support.xml.XMLParserException, org.opensaml.core.xml.io.UnmarshallingException, SignatureException, ResolverException {
        ServiceProviderMetadata sp1Metadata = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
        assertNotNull(sp1Metadata);
        assertTrue(sp1Metadata.isUpdatedAndValid());

        byte[] decodedAuthnRequest = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp1-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        sp1Metadata.validate(authnRequest.getSignature());
    }

    void assertSuccessfulInitialization(ServiceProviderMetadata spMetadata) {
        assertNotNull(spMetadata);
        assertTrue(spMetadata.isUpdatedAndValid());
        assertLogs(INFO, format("Initializing metadata resolver for: %s", spMetadata),
                format("Metadata Resolver HTTPMetadataResolver service-provider: New metadata successfully loaded for '%s'", spMetadata.getEntityId()),
                format("Metadata Resolver HTTPMetadataResolver service-provider: Next refresh cycle for metadata provider '%s' will occur on ", spMetadata.getEntityId()));
    }

    void assertUnsuccessfulInitialization(ServiceProviderMetadata spMetadata) {
        assertNotNull(spMetadata);
        assertFalse(spMetadata.isUpdatedAndValid());
        assertLogs(INFO, format("Initializing metadata resolver for: %s", spMetadata));
        assertLogs(ERROR, format("Metadata Resolver HTTPMetadataResolver %s: Error retrieving metadata from %s", spMetadata.getId(),
                spMetadata.getEntityId()));
    }
}
