package ee.ria.eidas.connector.specific.config;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class ResponderMetadataConfiguration {

    @Autowired
    private SpecificConnectorProperties connectorProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    public Credential metadataSigningCredential() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        return getCredential(getKeystore(),
                connectorProperties.getMetadata().getKeyAlias(),
                connectorProperties.getMetadata().getKeyPassword());
    }

    private KeyStore getKeystore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        Resource resource = resourceLoader.getResource(connectorProperties.getMetadata().getKeyStore());
        keystore.load(resource.getInputStream(), connectorProperties.getMetadata().getKeyStorePassword().toCharArray());
        return keystore;
    }

    private Credential getCredential(KeyStore keystore, String keyPairId, String privateKeyPass) {
        try {
            Map<String, String> passwordMap = new HashMap<>();
            passwordMap.put(keyPairId, privateKeyPass);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
            Criterion criterion = new EntityIdCriterion(keyPairId);
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(criterion);
            return resolver.resolveSingle(criteriaSet);
        } catch (ResolverException e) {
            throw new IllegalStateException("Something went wrong reading credentials", e);
        }
    }
}
