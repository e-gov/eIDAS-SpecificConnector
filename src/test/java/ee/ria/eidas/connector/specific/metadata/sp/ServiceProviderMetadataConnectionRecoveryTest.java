package ee.ria.eidas.connector.specific.metadata.sp;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.awaitility.Durations;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static java.lang.String.format;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(webEnvironment = RANDOM_PORT,
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
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class ServiceProviderMetadataConnectionRecoveryTest extends ServiceProviderTest {

    @Test
    @Order(1)
    @SneakyThrows
    void requestSignatureValidationFailsWhen_InvalidMetadataState() {
        assertUnsuccessfulRequestSignatureValidation();
    }

    @Test
    @Order(2)
    void serviceProviderMetadataIsUpdatedAndValidWhen_ConnectionToMetadataServiceIsRestored() {
        ServiceProviderMetadata spMetadata = serviceProviderMetadataRegistry.getByEntityId(SP_ENTITY_ID);
        assertSuccessfulInitialization(spMetadata);

        ServiceProviderMetadata spMetadata1 = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
        assertNotNull(spMetadata1);
        assertFalse(spMetadata1.isUpdatedAndValid());
        assertLogs(INFO, format("Initializing metadata resolver for: %s", spMetadata1));
        assertLogs(ERROR, "Metadata Resolver HTTPMetadataResolver service-provider-1: Error retrieving metadata from https://localhost:9999/metadata",
                "Metadata Resolver HTTPMetadataResolver service-provider-1: Error occurred while attempting to refresh metadata from 'https://localhost:9999/metadata'",
                "Metadata Resolver HTTPMetadataResolver service-provider-1: Metadata provider failed to properly initialize, fail-fast=false, continuing on in a degraded state");

        startServiceProvider1MetadataServer("sp1-valid-metadata.xml");

        await()
                .pollInterval(Durations.ONE_SECOND)
                .pollDelay(Durations.ONE_SECOND)
                .atMost(Durations.TEN_SECONDS)
                .untilAsserted(() -> assertTrue(serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID).isUpdatedAndValid()));

        assertLogs(INFO, "Metadata Resolver HTTPMetadataResolver service-provider-1: New metadata successfully loaded for 'https://localhost:9999/metadata'",
                "Metadata Resolver HTTPMetadataResolver service-provider-1: Next refresh cycle for metadata provider 'https://localhost:9999/metadata' will occur on ");
    }

    @Test
    @Order(3)
    @SneakyThrows
    void requestSignatureValidationSucceedsWhen_ValidMetadataState() {
        assertSuccessfulRequestSignatureValidation();
    }
}
