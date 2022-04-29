package ee.ria.eidas.connector.specific.responder.serviceprovider;

import ee.ria.eidas.connector.specific.config.OpenSAMLConfiguration;
import ee.ria.eidas.connector.specific.config.ResponderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.ServiceProviderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = {SpecificConnectorProperties.class, SpecificConnectorProperties.ResponderMetadata.class})
@ContextConfiguration(classes = {ServiceProviderMetadataConfiguration.class, ResponderMetadataConfiguration.class, OpenSAMLConfiguration.class})
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[1].id=service-provider-1",
                "eidas.connector.service-providers[1].entity-id=https://localhost:9999/metadata",
                "eidas.connector.service-providers[1].key-alias=service-provider-1-metadata-signing",
        })
public class ServiceProviderMetadataRegistryTests extends ServiceProviderTest {

    @Autowired
    List<ServiceProviderMetadata> serviceProviders;

    @BeforeAll
    static void beforeAll() {
        updateServiceProvider1Metadata("sp1-expired-metadata-signing-cert.xml");
    }

    @Test
    void initializedServiceProviderAvailableAndInValidStateWhen_RequestedFromRegistry() throws ResolverException {
        ServiceProviderMetadata spMetadataFromRegistry = serviceProviderMetadataRegistry.get(SP_ENTITY_ID);
        assertNotNull(spMetadataFromRegistry);
        assertTrue(spMetadataFromRegistry.isUpdatedAndValid());
        assertEquals("service-provider", spMetadataFromRegistry.getId());
        assertEquals("https://localhost:8888/metadata", spMetadataFromRegistry.getEntityId());
        assertEquals("https://localhost:8888/returnUrl", spMetadataFromRegistry.getAssertionConsumerServiceUrl());
        assertTrue(spMetadataFromRegistry.isWantAssertionsSigned());
    }

    @Test
    void uninitializedServiceProviderAvailableAndInInvalidStateWhen_RequestedFromRegistry() {
        ServiceProviderMetadata spMetadata1FromRegistry = serviceProviderMetadataRegistry.get(SP_1_ENTITY_ID);
        assertNotNull(spMetadata1FromRegistry);
        assertFalse(spMetadata1FromRegistry.isUpdatedAndValid());
        assertEquals("service-provider-1", spMetadata1FromRegistry.getId());
        assertEquals("https://localhost:9999/metadata", spMetadata1FromRegistry.getEntityId());
        assertThrows(TechnicalException.class, spMetadata1FromRegistry::getEntityDescriptor);
        assertThrows(TechnicalException.class, spMetadata1FromRegistry::getAssertionConsumerServiceUrl);
        assertThrows(TechnicalException.class, spMetadata1FromRegistry::isWantAssertionsSigned);
    }
}
