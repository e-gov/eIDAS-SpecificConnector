package ee.ria.eidas.connector.specific.config;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class ResponderMetadataConfiguration {

    @Bean
    public Credential metadataSigningCredential(SpecificConnectorProperties connectorProperties, KeyStore metadataKeyStore) throws ResolverException {
        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(connectorProperties.getMetadata().getKeyAlias(), connectorProperties.getMetadata().getKeyPassword());
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(metadataKeyStore, passwordMap);
        CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(connectorProperties.getMetadata().getKeyAlias()));
        return resolver.resolveSingle(criteria);
    }
}
