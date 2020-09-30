package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ServiceProvider;
import ee.ria.eidas.connector.specific.exception.SpecificConnectorException;
import ee.ria.eidas.connector.specific.metadata.sp.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.metadata.sp.ServiceProviderMetadataResolver;
import ee.ria.eidas.connector.specific.monitoring.health.ServiceProviderMetadataHealthIndicator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static java.lang.String.format;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ServiceProviderMetadataConfiguration {

    @Bean
    public ServiceProviderMetadataResolver serviceProviderMetadataResolver(SpecificConnectorProperties connectorProperties,
                                                                           KeyStore responderMetadataTrustStore,
                                                                           HealthContributorRegistry healthContributorRegistry) throws ResolverException,
            ComponentInitializationException, KeyStoreException {
        List<ServiceProviderMetadata> spMetadataResolvers = new ArrayList<>();
        if (connectorProperties.getServiceProviders() != null) {
            for (ServiceProvider serviceProvider : connectorProperties.getServiceProviders()) {
                String keyAlias = serviceProvider.getKeyAlias();
                ExplicitKeySignatureTrustEngine signatureTrustEngine = getSignatureTrustEngine(responderMetadataTrustStore, keyAlias);
                ServiceProviderMetadata serviceProviderMetadata = ServiceProviderMetadata.builder()
                        .serviceProvider(serviceProvider)
                        .metadataIssuerTrustEngine(signatureTrustEngine)
                        .build();
                spMetadataResolvers.add(serviceProviderMetadata);
                registerHealthIndicator(healthContributorRegistry, serviceProviderMetadata);
            }
        }
        return new ServiceProviderMetadataResolver(spMetadataResolvers);
    }

    private ExplicitKeySignatureTrustEngine getSignatureTrustEngine(KeyStore keyStore, String keyAlias) throws KeyStoreException {
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyAlias);
        if (certificate == null) {
            throw new SpecificConnectorException("Missing Service provider metadata trusted certificate with alias: %s", keyAlias);
        }
        X509Credential credential = CredentialSupport.getSimpleCredential(certificate, null);
        StaticCredentialResolver credentialResolver = new StaticCredentialResolver(credential);
        KeyInfoCredentialResolver keyInfoResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();
        return new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoResolver);
    }

    private void registerHealthIndicator(HealthContributorRegistry healthContributorRegistry, ServiceProviderMetadata serviceProviderMetadata) {
        String name = format("sp-%s-metadata", serviceProviderMetadata.getServiceProvider().getId());
        log.info("Registering {} health indicator", name);
        healthContributorRegistry.registerContributor(name, new ServiceProviderMetadataHealthIndicator(serviceProviderMetadata));
    }
}
