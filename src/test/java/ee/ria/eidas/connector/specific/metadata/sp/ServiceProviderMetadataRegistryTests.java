package ee.ria.eidas.connector.specific.metadata.sp;

import ee.ria.eidas.connector.specific.exception.SpecificConnectorException;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;
import java.util.Optional;

import static ch.qos.logback.classic.Level.INFO;
import static java.lang.String.format;
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
public class ServiceProviderMetadataRegistryTests extends ServiceProviderTest {

    @Autowired
    List<ServiceProviderMetadata> serviceProviders;

    @Test
    @Order(1)
    void initializedServiceProviderAvailableWhen_RequestedFromRegistry() throws ResolverException {
        Optional<ServiceProviderMetadata> metadata = serviceProviders.stream()
                .filter(sp -> SP_ENTITY_ID.equals(sp.getEntityId())).findFirst();
        assertTrue(metadata.isPresent());
        ServiceProviderMetadata spMetadata = metadata.get();
        assertSuccessfulInitialization(spMetadata);
        assertTrue(spMetadata.isUpdatedAndValid());
        EntityDescriptor entityDescriptor = spMetadata.getEntityDescriptor();
        assertEquals("2025-08-09T19:12:05.320Z", entityDescriptor.getValidUntil().toString());

        ServiceProviderMetadata spMetadataFromRegistry = serviceProviderMetadataRegistry.getByEntityId(SP_ENTITY_ID);
        assertNotNull(spMetadataFromRegistry);
        assertTrue(spMetadataFromRegistry.isUpdatedAndValid());
        assertEquals("service-provider", spMetadataFromRegistry.getId());
        assertEquals("https://localhost:8888/metadata", spMetadataFromRegistry.getEntityId());
        assertEquals("public", spMetadataFromRegistry.getType());
        assertEquals("https://localhost:8888/returnUrl", spMetadataFromRegistry.getAssertionConsumerServiceUrl());
        assertTrue(spMetadataFromRegistry.isWantAssertionsSigned());
    }

    @Test
    @Order(2)
    void uninitializedServiceProviderAvailableWhen_RequestedFromRegistry() throws ResolverException {
        Optional<ServiceProviderMetadata> metadata = serviceProviders.stream()
                .filter(sp -> SP_1_ENTITY_ID.equals(sp.getEntityId())).findFirst();
        assertTrue(metadata.isPresent());
        ServiceProviderMetadata sp1Metadata = metadata.get();
        assertUnsuccessfulInitialization(sp1Metadata);
        assertFalse(sp1Metadata.isUpdatedAndValid());

        ServiceProviderMetadata spMetadata1FromRegistry = serviceProviderMetadataRegistry.getByEntityId(SP_1_ENTITY_ID);
        assertNotNull(spMetadata1FromRegistry);
        assertFalse(spMetadata1FromRegistry.isUpdatedAndValid());
        assertEquals("service-provider-1", spMetadata1FromRegistry.getId());
        assertEquals("https://localhost:9999/metadata", spMetadata1FromRegistry.getEntityId());
        assertEquals("public", spMetadata1FromRegistry.getType());
        assertThrows(TechnicalException.class, spMetadata1FromRegistry::getAssertionConsumerServiceUrl);
        assertThrows(TechnicalException.class, spMetadata1FromRegistry::isWantAssertionsSigned);
    }

    @ParameterizedTest
    @Order(3)
    @ValueSource(strings = {SP_ENTITY_ID, SP_1_ENTITY_ID})
    void metadataUpdatedAndValidWhen_RefreshIsCalled(String serviceProviderEntityId) throws ResolverException {
        startServiceProvider1MetadataServer("sp1-valid-metadata.xml");
        ServiceProviderMetadata serviceProviderMetadata = serviceProviderMetadataRegistry.getByEntityId(serviceProviderEntityId);
        serviceProviderMetadata.refreshMetadata();
        assertTrue(serviceProviderMetadata.isUpdatedAndValid());
        String spId = serviceProviderMetadata.getId();
        String entityId = serviceProviderMetadata.getEntityId();
        assertTestLogs(INFO, format("Metadata Resolver HTTPMetadataResolver %s: New metadata successfully loaded for '%s'", spId, entityId),
                format("Metadata Resolver HTTPMetadataResolver %s: Next refresh cycle for metadata provider '%s' will occur on", spId, entityId));
    }

    @Test
    void technicalExceptionWhen_UnknownEntityIdRequestedFromRegistry() {
        SpecificConnectorException specificConnectorException = assertThrows(SpecificConnectorException.class, () -> serviceProviderMetadataRegistry.getByEntityId("unknown"));
        assertEquals("Service provider metadata resolver not found for entity id: unknown", specificConnectorException.getMessage());
    }
}
