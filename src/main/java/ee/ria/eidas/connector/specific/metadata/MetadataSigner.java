package ee.ria.eidas.connector.specific.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class MetadataSigner {
    private final String signatureAlgorithmId;
    private final Credential signingCredential;

    public MetadataSigner(SpecificConnectorProperties specificConnectorProperties, Credential signingCredential) {
        this.signatureAlgorithmId = specificConnectorProperties.getMetadata().getSignatureAlgorithm();
        this.signingCredential = signingCredential;
    }

    public void sign(SignableSAMLObject samlObject) throws SecurityException, MarshallingException, SignatureException {
        Signature signature = buildSignature();
        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(signatureAlgorithmId);
        DigestAlgorithm digestAlgorithm = getRelatedDigestAlgorithm(signatureAlgorithmId);
        SignatureSigningParameters params = getSignatureSigningParameters(signingCredential, signatureAlgorithm, digestAlgorithm);
        SignatureSupport.prepareSignatureParams(signature, params);
        samlObject.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(params.getSignatureReferenceDigestMethod());
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(samlObject).marshall(samlObject);
        Signer.signObject(signature);
    }

    public static SignatureAlgorithm getSignatureAlgorithm(String signatureAlgorithmId) {
        AlgorithmDescriptor signatureAlgorithm = AlgorithmSupport.getGlobalAlgorithmRegistry().get(signatureAlgorithmId);
        Assert.notNull(signatureAlgorithm, "No signature algorithm support for: " + signatureAlgorithmId);
        Assert.isInstanceOf(SignatureAlgorithm.class, signatureAlgorithm, "This is not a valid XML signature algorithm! Please check your configuration!");
        return (SignatureAlgorithm) signatureAlgorithm;
    }

    public static DigestAlgorithm getRelatedDigestAlgorithm(String signatureAlgorithmId) {
        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(signatureAlgorithmId);
        DigestAlgorithm digestAlgorithm = AlgorithmSupport.getGlobalAlgorithmRegistry().getDigestAlgorithm(signatureAlgorithm.getDigest());
        Assert.notNull(digestAlgorithm, "No corresponding message digest algorithm support for signature algorithm: " + signatureAlgorithm.getURI());
        return digestAlgorithm;
    }

    private org.opensaml.xmlsec.signature.Signature buildSignature() {
        return (org.opensaml.xmlsec.signature.Signature) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME).buildObject(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);
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
