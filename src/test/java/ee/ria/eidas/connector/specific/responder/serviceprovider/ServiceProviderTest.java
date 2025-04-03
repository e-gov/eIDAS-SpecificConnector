package ee.ria.eidas.connector.specific.responder.serviceprovider;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

abstract class ServiceProviderTest {
    static final String SP_ENTITY_ID = "https://localhost:8888/metadata";
    static final WireMockServer mockSPMetadataServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/service-provider-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(8888)
    );
    static final String SP_1_ENTITY_ID = "https://localhost:9999/metadata";
    static final WireMockServer mockSP1MetadataServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/service-provider-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(9999)
    );

    static {
        System.setProperty("javax.net.ssl.trustStore", "src/test/resources/__files/mock_keys/specific-connector-tls-truststore.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    @MockitoBean
    HealthContributorRegistry healthContributorRegistry;

    @SpyBean
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @BeforeAll
    static void startMetadataServers() {
        startServiceProviderMetadataServer();
        startServiceProvider1MetadataServer();
    }

    @AfterAll
    static void stopMetadataServers() {
        mockSPMetadataServer.stop();
        mockSP1MetadataServer.stop();
    }

    protected static void startServiceProviderMetadataServer() {
        mockSPMetadataServer.start();
        updateServiceProviderMetadata("sp-valid-metadata.xml");
    }

    protected static void startServiceProvider1MetadataServer() {
        mockSP1MetadataServer.start();
        updateServiceProvider1Metadata("sp1-valid-metadata.xml");
    }

    protected static void updateServiceProviderMetadata(String metadataFile) {
        updateMetadata(mockSPMetadataServer, metadataFile);
    }

    protected static void updateServiceProvider1Metadata(String metadataFile) {
        updateMetadata(mockSP1MetadataServer, metadataFile);
    }

    private static void updateMetadata(WireMockServer mockMetadataServer, String metadataFile) {
        mockMetadataServer.resetAll();
        mockMetadataServer.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse()
                .withHeader("Content-Type", "application/xml;charset=UTF-8")
                .withStatus(200)
                .withBodyFile("sp_metadata/" + metadataFile)));
    }

    protected void assertInvalidMetadataState(boolean expectException) throws ResolverException {
        serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
        if (expectException) {
            assertThrows(ResolverException.class, () -> serviceProviderMetadataRegistry.refreshMetadata(SP_1_ENTITY_ID));
        } else {
            serviceProviderMetadataRegistry.refreshMetadata(SP_1_ENTITY_ID);
        }
        assertTrue(serviceProviderMetadataRegistry.get(SP_ENTITY_ID).isUpdatedAndValid());
        assertFalse(serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID).isUpdatedAndValid());
    }

    protected void assertValidMetadataState() throws ResolverException {
        serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
        serviceProviderMetadataRegistry.refreshMetadata(SP_1_ENTITY_ID);
        assertTrue(serviceProviderMetadataRegistry.get(SP_ENTITY_ID).isUpdatedAndValid());
        assertTrue(serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID).isUpdatedAndValid());
    }
}
