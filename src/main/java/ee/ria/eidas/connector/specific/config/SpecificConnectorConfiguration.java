package ee.ria.eidas.connector.specific.config;

import eu.eidas.auth.commons.attribute.AttributeRegistries;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.protocol.eidas.spec.LegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.FileUrlResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Slf4j
@Configuration
@ConfigurationPropertiesScan
public class SpecificConnectorConfiguration implements WebMvcConfigurer {

    @Override
    public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }

    @Bean
    public ViewResolver internalResourceViewResolver() {
        InternalResourceViewResolver bean = new InternalResourceViewResolver();
        bean.setViewClass(JstlView.class);
        bean.setPrefix("/WEB-INF/jsp/");
        bean.setSuffix(".jsp");
        return bean;
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/resources/**")
                .addResourceLocations("/resources/").setCachePeriod(3600)
                .resourceChain(true).addResolver(new PathResourceResolver());
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer properties(
            @Value("#{environment.SPECIFIC_CONNECTOR_CONFIG_REPOSITORY}/specificCommunicationDefinitionConnector.xml")
                    String specificCommunicationConfig,
            @Value("#{environment.EIDAS_CONFIG_REPOSITORY}/eidas.xml") String eidasConfig) throws MalformedURLException {
        Assert.isTrue(new File(specificCommunicationConfig).exists(), "Required configuration file not found: " + specificCommunicationConfig);
        Assert.isTrue(new File(eidasConfig).exists(), "Required configuration file not found: " + eidasConfig);
        PropertySourcesPlaceholderConfigurer ppc = new PropertySourcesPlaceholderConfigurer();
        ppc.setLocations(new FileUrlResource(specificCommunicationConfig), new FileUrlResource(eidasConfig));
        ppc.setIgnoreUnresolvablePlaceholders(false);
        return ppc;
    }

    @Bean
    public AttributeRegistry supportedAttributesRegistry() {
        return AttributeRegistries.copyOf(NaturalPersonSpec.REGISTRY, LegalPersonSpec.REGISTRY);
    }

    @Bean
    public String specificConnectorIP(SpecificConnectorProperties specificConnectorProperties) throws MalformedURLException, UnknownHostException {
        String issuerUrl = specificConnectorProperties.getResponderMetadata().getEntityId();
        return InetAddress.getByName(new URL(issuerUrl).getHost()).getHostAddress();
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
