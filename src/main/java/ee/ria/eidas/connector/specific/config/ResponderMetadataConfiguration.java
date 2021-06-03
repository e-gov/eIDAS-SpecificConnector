package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.HsmProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import eu.eidas.auth.commons.attribute.AttributeRegistries;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.protocol.eidas.spec.LegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.RepresentativeLegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.RepresentativeNaturalPersonSpec;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.x509.BasicX509Credential;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import sun.security.pkcs11.SunPKCS11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@Configuration
public class ResponderMetadataConfiguration {

    @Bean
    public AttributeRegistry supportedAttributesRegistry(ResponderMetadata responderMetadata) {
        List<SupportedAttribute> supportedAttributes = responderMetadata.getSupportedAttributes();
        AttributeRegistry eidasAttributeRegistry = eidasAttributesRegistry();
        return AttributeRegistries.of(supportedAttributes.stream().map(attr -> eidasAttributeRegistry.getByName(attr.getName())).collect(Collectors.toList()));
    }

    @Bean
    public AttributeRegistry eidasAttributesRegistry() {
        return AttributeRegistries.copyOf(NaturalPersonSpec.REGISTRY, LegalPersonSpec.REGISTRY, RepresentativeNaturalPersonSpec.REGISTRY, RepresentativeLegalPersonSpec.REGISTRY);
    }

    @Bean
    public KeyStore responderMetadataKeyStore(ResponderMetadata responderMetadata, ResourceLoader resourceLoader) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(responderMetadata.getKeyStoreType());
        Resource resource = resourceLoader.getResource(responderMetadata.getKeyStore());
        keystore.load(resource.getInputStream(), responderMetadata.getKeyStorePassword().toCharArray());
        return keystore;
    }

    @Bean
    public KeyStore responderMetadataTrustStore(ResponderMetadata responderMetadata, ResourceLoader resourceLoader) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(responderMetadata.getTrustStoreType());
        Resource resource = resourceLoader.getResource(responderMetadata.getTrustStore());
        keystore.load(resource.getInputStream(), responderMetadata.getTrustStorePassword().toCharArray());
        return keystore;
    }

    @Bean
    @ConditionalOnProperty(prefix = "eidas.connector.hsm", name = "enabled", havingValue = "true")
    public KeyStore responderMetadataHardwareKeyStore(HsmProperties hsmProperties) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        log.info("Hardware security module enabled. Slot/slot index: {}/{}, Library: {}",
                hsmProperties.getSlot(), hsmProperties.getSlotListIndex(),
                hsmProperties.getLibrary());
        SunPKCS11 provider = new SunPKCS11(new ByteArrayInputStream(hsmProperties.toString().getBytes(UTF_8)));
        Security.addProvider(provider);
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, hsmProperties.getPin().toCharArray());
        return keyStore;
    }

    @Bean
    @ConditionalOnProperty(name = "eidas.connector.hsm.enabled", havingValue = "false", matchIfMissing = true)
    public BasicX509Credential signingCredential(ResponderMetadata responderMetadata, KeyStore responderMetadataKeyStore) throws Exception {
        String alias = responderMetadata.getKeyAlias();
        PrivateKey privateKey = (PrivateKey) responderMetadataKeyStore.getKey(alias, responderMetadata.getKeyStorePassword().toCharArray());
        X509Certificate x509Cert = (X509Certificate) responderMetadataKeyStore.getCertificate(alias);
        BasicX509Credential basicX509Credential = new BasicX509Credential(x509Cert, privateKey);
        basicX509Credential.setEntityId(alias);
        return basicX509Credential;
    }

    @Bean("signingCredential")
    @ConditionalOnProperty(prefix = "eidas.connector.hsm", name = "enabled", havingValue = "true")
    public BasicX509Credential signingCredentialHsm(ResponderMetadata responderMetadata, HsmProperties hsmProperties, KeyStore responderMetadataKeyStore,
                                                    KeyStore responderMetadataHardwareKeyStore) throws Exception {
        String alias = responderMetadata.getKeyAlias();
        char[] password = hsmProperties.getPin().toCharArray();
        PrivateKey privateKey = (PrivateKey) responderMetadataHardwareKeyStore.getKey(alias, password);
        X509Certificate x509Cert = hsmProperties.isCertificatesFromHsm() ?
                (X509Certificate) responderMetadataHardwareKeyStore.getCertificate(alias) : (X509Certificate) responderMetadataKeyStore.getCertificate(alias);
        BasicX509Credential basicX509Credential = new BasicX509Credential(x509Cert, privateKey);
        basicX509Credential.setEntityId(alias);
        return basicX509Credential;
    }

    @Getter
    public static class FailedSigningEvent extends ApplicationEvent {

        public FailedSigningEvent() {
            super("");
        }
    }
}
