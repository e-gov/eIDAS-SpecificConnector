package ee.ria.eidas.connector.specific.responder.serviceprovider;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-1-metadata-signing",
                "eidas.connector.service-providers[0].type=public"
        })
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class ServiceProviderMetadataNotTrustedTest extends ServiceProviderTest {

    @Test
    void metadataInvalidStateWhen_TrustedMetadataSigningCertificateMismatch() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.getByEntityId(SP_ENTITY_ID);
        assertNotNull(spMetadata);
        assertFalse(spMetadata.isUpdatedAndValid());
        assertLogs(INFO, "Initializing metadata resolver for: SpecificConnectorProperties.ServiceProvider(id=service-provider, entityId=https://localhost:8888/metadata, keyAlias=service-provider-1-metadata-signing, type=public)");
        assertLogs(ERROR, "Signature trust establishment failed for metadata entry https://localhost:8888/metadata",
                "Metadata Resolver HTTPMetadataResolver service-provider: Error filtering metadata from https://localhost:8888/metadata",
                "Metadata Resolver HTTPMetadataResolver service-provider: Error occurred while attempting to refresh metadata from 'https://localhost:8888/metadata'",
                "Metadata Resolver HTTPMetadataResolver service-provider: Metadata provider failed to properly initialize, fail-fast=false, continuing on in a degraded state");
    }
}
