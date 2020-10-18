package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.*;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

@Component
public class ResponderMetadataSigner {
    private final SignatureSigningParameters signingParameters;
    private final XMLObjectBuilder<?> builderFactory;
    private final MarshallerFactory marshallerFactory;
    private final Credential signingCredential;

    public ResponderMetadataSigner(SpecificConnectorProperties connectorProperties, KeyStore responderMetadataKeyStore) throws ResolverException {
        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(connectorProperties.getResponderMetadata().getSignatureAlgorithm());
        DigestAlgorithm digestAlgorithm = getRelatedDigestAlgorithm(signatureAlgorithm);
        signingCredential = resolveSigningCredential(connectorProperties, responderMetadataKeyStore);
        signingParameters = getSignatureSigningParameters(signingCredential, signatureAlgorithm, digestAlgorithm);
        builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
    }

    public Signature sign(SignableSAMLObject samlObject) throws SecurityException, MarshallingException, SignatureException {
        Signature signature = buildSignature();
        SignatureSupport.prepareSignatureParams(signature, signingParameters);
        samlObject.setSignature(signature);
        setDigestAlgorithm(signature);
        marshallerFactory.getMarshaller(samlObject).marshall(samlObject);
        Signer.signObject(signature);
        return signature;
    }

    public void validate(Signature signature) throws SignatureException {
        SignatureValidator.validate(signature, signingCredential);
    }

    public Credential getSigningCredential() {
        return signingCredential;
    }

    private Credential resolveSigningCredential(SpecificConnectorProperties connectorProperties, KeyStore metadataKeyStore) throws ResolverException {
        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(connectorProperties.getResponderMetadata().getKeyAlias(), connectorProperties.getResponderMetadata().getKeyPassword());
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(metadataKeyStore, passwordMap);
        CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(connectorProperties.getResponderMetadata().getKeyAlias()));
        return resolver.resolveSingle(criteria);
    }

    private void setDigestAlgorithm(Signature signature) {
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(signingParameters.getSignatureReferenceDigestMethod());
    }

    private Signature buildSignature() {
        return (Signature) builderFactory.buildObject(Signature.DEFAULT_ELEMENT_NAME);
    }

    private SignatureAlgorithm getSignatureAlgorithm(String signatureAlgorithmId) {
        AlgorithmDescriptor signatureAlgorithm = AlgorithmSupport.getGlobalAlgorithmRegistry().get(signatureAlgorithmId);
        Assert.notNull(signatureAlgorithm, "No signature algorithm support for: " + signatureAlgorithmId);
        Assert.isInstanceOf(SignatureAlgorithm.class, signatureAlgorithm, "This is not a valid XML signature algorithm! Please check your configuration!");
        return (SignatureAlgorithm) signatureAlgorithm;
    }

    private DigestAlgorithm getRelatedDigestAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        DigestAlgorithm digestAlgorithm = AlgorithmSupport.getGlobalAlgorithmRegistry().getDigestAlgorithm(signatureAlgorithm.getDigest());
        Assert.notNull(digestAlgorithm, "No corresponding message digest algorithm support for signature algorithm: " + signatureAlgorithm.getURI());
        return digestAlgorithm;
    }

    private SignatureSigningParameters getSignatureSigningParameters(Credential credential, SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm) {
        SignatureSigningParameters params = new SignatureSigningParameters();
        params.setSigningCredential(credential);
        params.setSignatureAlgorithm(signatureAlgorithm.getURI());
        params.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        params.setSignatureReferenceDigestMethod(digestAlgorithm.getURI());
        params.setKeyInfoGenerator(getX509KeyInfoGenerator());
        return params;
    }

    private KeyInfoGenerator getX509KeyInfoGenerator() {
        X509KeyInfoGeneratorFactory x509KeyInfoGenerator = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGenerator.setEmitEntityCertificate(true);
        return x509KeyInfoGenerator.newInstance();
    }
}
