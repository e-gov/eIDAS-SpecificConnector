package ee.ria.eidas.connector.specific.config;

import eu.eidas.auth.commons.attribute.AttributeRegistries;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.protocol.eidas.spec.LegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
public class ResponderMetadataConfiguration {

    @Bean
    public AttributeRegistry supportedAttributesRegistry() {
        return AttributeRegistries.copyOf(NaturalPersonSpec.REGISTRY, LegalPersonSpec.REGISTRY);
    }

    @Bean
    public KeyStore responderMetadataKeyStore(SpecificConnectorProperties connectorProperties, ResourceLoader resourceLoader) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(connectorProperties.getResponderMetadata().getKeyStoreType());
        Resource resource = resourceLoader.getResource(connectorProperties.getResponderMetadata().getKeyStore());
        keystore.load(resource.getInputStream(), connectorProperties.getResponderMetadata().getKeyStorePassword().toCharArray());
        return keystore;
    }

    @Bean
    public KeyStore responderMetadataTrustStore(SpecificConnectorProperties connectorProperties, ResourceLoader resourceLoader) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(connectorProperties.getResponderMetadata().getTrustStoreType());
        Resource resource = resourceLoader.getResource(connectorProperties.getResponderMetadata().getTrustStore());
        keystore.load(resource.getInputStream(), connectorProperties.getResponderMetadata().getTrustStorePassword().toCharArray());
        return keystore;
    }
}
