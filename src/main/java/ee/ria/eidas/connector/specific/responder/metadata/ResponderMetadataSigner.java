package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.*;
import org.springframework.stereotype.Component;

@Component
public class ResponderMetadataSigner {
    private final SignatureSigningParameters signingParameters;
    private final XMLObjectBuilder<?> builderFactory;
    private final MarshallerFactory marshallerFactory;
    private final Credential metadataSigningCredential;

    public ResponderMetadataSigner(SpecificConnectorProperties connectorProperties, BasicX509Credential signingCredential) {
        SignatureAlgorithm signatureAlgorithm = OpenSAMLUtils.getSignatureAlgorithm(connectorProperties.getResponderMetadata().getSignatureAlgorithm());
        DigestAlgorithm digestAlgorithm = OpenSAMLUtils.getRelatedDigestAlgorithm(signatureAlgorithm);
        metadataSigningCredential = signingCredential;
        signingParameters = getSignatureSigningParameters(metadataSigningCredential, signatureAlgorithm, digestAlgorithm);
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
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);
        SignatureValidator.validate(signature, metadataSigningCredential);
    }

    private void setDigestAlgorithm(Signature signature) {
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(signingParameters.getSignatureReferenceDigestMethod());
    }

    private Signature buildSignature() {
        return (Signature) builderFactory.buildObject(Signature.DEFAULT_ELEMENT_NAME);
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
