package ee.ria.eidas.connector.specific.metadata.sp;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ServiceProvider;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.http.impl.client.HttpClients;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilterChain;
import org.opensaml.saml.metadata.resolver.filter.impl.RequiredValidUntilFilter;
import org.opensaml.saml.metadata.resolver.filter.impl.SchemaValidationFilter;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import java.util.ArrayList;
import java.util.List;

import static org.opensaml.saml.common.xml.SAMLConstants.SAML20P_NS;
import static org.opensaml.security.credential.UsageType.ENCRYPTION;
import static org.opensaml.security.credential.UsageType.SIGNING;

@Slf4j
public class ServiceProviderMetadata {
    @Getter
    private final ServiceProvider serviceProvider;
    private final HTTPMetadataResolver httpMetadataResolver;
    private final ExplicitKeySignatureTrustEngine metadataIssuerTrustEngine;
    private final ExplicitKeySignatureTrustEngine serviceProviderTrustEngine;

    @Builder
    public ServiceProviderMetadata(ServiceProvider serviceProvider, ExplicitKeySignatureTrustEngine metadataIssuerTrustEngine)
            throws ResolverException, ComponentInitializationException {
        log.info("Initializing metadata resolver for: {}", serviceProvider);
        this.serviceProvider = serviceProvider;
        this.metadataIssuerTrustEngine = metadataIssuerTrustEngine;
        this.httpMetadataResolver = initHTTPMetadataResolver();
        this.serviceProviderTrustEngine = initServiceProviderTrustEngine();
    }

    public void validate(Signature signature) throws SignatureException, ResolverException {
        SignatureValidator.validate(signature, resolveCredential(SIGNING));
    }

    public EncryptedAssertion encrypt(Assertion assertion) throws EncryptionException, ResolverException {
        return createEncrypter().encrypt(assertion);
    }

    public EntityDescriptor getEntityDescriptor() {
        try {
            CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(serviceProvider.getEntityId()));
            EntityDescriptor entityDescriptor = httpMetadataResolver.resolveSingle(criteria);
            if (entityDescriptor == null) {
                throw new TechnicalException("EntityDescriptor not found in Service Provider metadata. SP Entity id: %s",
                        serviceProvider.getEntityId());
            }
            return entityDescriptor;
        } catch (ResolverException ex) {
            throw new TechnicalException(ex, "Unable to resolve EntityDescriptor. SP Entity id: %s", serviceProvider.getEntityId());
        }
    }

    public String getEntityId() {
        return serviceProvider.getEntityId();
    }

    public String getAssertionConsumerServiceUrl() {
        return getEntityDescriptor().getSPSSODescriptor(SAML20P_NS).getDefaultAssertionConsumerService().getLocation();
    }

    public boolean getWantAssertionsSigned() {
        return getEntityDescriptor().getSPSSODescriptor(SAML20P_NS).getWantAssertionsSigned();
    }

    public void refreshMetadata() throws ResolverException {
        httpMetadataResolver.refresh();
    }

    public boolean isUpdatedAndValid() {
        Boolean isRootValid = httpMetadataResolver.isRootValid();
        Boolean wasLastRefreshSuccess = httpMetadataResolver.wasLastRefreshSuccess();
        return httpMetadataResolver.isInitialized()
                && isRootValid != null && isRootValid
                && wasLastRefreshSuccess != null && wasLastRefreshSuccess;
    }

    private ExplicitKeySignatureTrustEngine initServiceProviderTrustEngine() throws ComponentInitializationException {
        MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
        PredicateRoleDescriptorResolver roleResolver = new PredicateRoleDescriptorResolver(httpMetadataResolver);
        KeyInfoCredentialResolver keyResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();
        metadataCredentialResolver.setRoleDescriptorResolver(roleResolver);
        metadataCredentialResolver.setKeyInfoCredentialResolver(keyResolver);
        metadataCredentialResolver.initialize();
        roleResolver.initialize();
        return new ExplicitKeySignatureTrustEngine(metadataCredentialResolver, keyResolver);
    }

    private HTTPMetadataResolver initHTTPMetadataResolver() throws ResolverException, ComponentInitializationException {
        HTTPMetadataResolver metadataResolver = new HTTPMetadataResolver(HttpClients.createDefault(), serviceProvider.getEntityId());
        metadataResolver.setId(serviceProvider.getId());
        metadataResolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
        metadataResolver.setRequireValidMetadata(true);
        metadataResolver.setFailFastInitialization(true);

        List<MetadataFilter> metadataFilters = new ArrayList<>();
        metadataFilters.add(new ServiceProviderValidationFilter(serviceProvider.getEntityId(), serviceProvider.getType()));
        metadataFilters.add(new SignatureValidationFilter(metadataIssuerTrustEngine));
        metadataFilters.add(new RequiredValidUntilFilter()); // TODO: consider using maxValidity
        metadataFilters.add(new SchemaValidationFilter(new SAMLSchemaBuilder(SAMLSchemaBuilder.SAML1Version.SAML_11)));

        MetadataFilterChain metadataFilterChain = new MetadataFilterChain();
        metadataFilterChain.setFilters(metadataFilters);

        metadataResolver.setMetadataFilter(metadataFilterChain);
        metadataResolver.initialize();
        return metadataResolver;
    }

    private Encrypter createEncrypter() throws ResolverException {
        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(resolveCredential(ENCRYPTION));
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP); // TODO:

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
        kekParams.setKeyInfoGenerator(keyInfoGenerator);

        DataEncryptionParameters encryptParams = new DataEncryptionParameters();
        encryptParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128); // TODO:

        Encrypter encrypter = new Encrypter(encryptParams, kekParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        return encrypter;
    }

    private Credential resolveCredential(UsageType credentialUsageType) throws ResolverException {
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new UsageCriterion(credentialUsageType));
        criteriaSet.add(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
        criteriaSet.add(new ProtocolCriterion(SAML20P_NS));
        criteriaSet.add(new EntityIdCriterion(serviceProvider.getEntityId()));
        return serviceProviderTrustEngine.getCredentialResolver().resolveSingle(criteriaSet);
    }
}
