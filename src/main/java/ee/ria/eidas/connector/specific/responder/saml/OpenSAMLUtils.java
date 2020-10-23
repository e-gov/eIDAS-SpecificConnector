package ee.ria.eidas.connector.specific.responder.saml;

import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.util.Base64;

@UtilityClass
public class OpenSAMLUtils {
    private static final String DEFAULT_ELEMENT_NAME = "DEFAULT_ELEMENT_NAME";

    @SneakyThrows
    public <T extends SAMLObject> T buildObject(Class<T> type) {
        QName defaultElementName = (QName) type.getDeclaredField(DEFAULT_ELEMENT_NAME).get(null);
        SAMLObjectBuilder<T> builder = (SAMLObjectBuilder<T>) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .<T>getBuilderOrThrow(defaultElementName);
        return builder.buildObject();
    }

    public String getXmlString(XMLObject object) throws MarshallingException {
        Element entityDescriptorElement = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(object)
                .marshall(object);
        return SerializeSupport.nodeToString(entityDescriptorElement);
    }

    public AuthnRequest unmarshallAuthnRequest(String samlRequest) throws UnmarshallingException, XMLParserException {
        byte[] decodedAuthnRequest = Base64.getDecoder().decode(samlRequest);
        return OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
    }

    public <T extends SAMLObject> T unmarshall(byte[] saml, Class<T> type) throws XMLParserException, UnmarshallingException {
        ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        return type.cast(XMLObjectSupport.unmarshallFromInputStream(parserPool, new ByteArrayInputStream(saml)));
    }

    public SignatureAlgorithm getSignatureAlgorithm(String signatureAlgorithmId) {
        AlgorithmDescriptor signatureAlgorithm = AlgorithmSupport.getGlobalAlgorithmRegistry().get(signatureAlgorithmId);
        Assert.notNull(signatureAlgorithm, "No signature algorithm support for: " + signatureAlgorithmId);
        Assert.isInstanceOf(SignatureAlgorithm.class, signatureAlgorithm, "This is not a valid XML signature algorithm! Please check your configuration!");
        return (SignatureAlgorithm) signatureAlgorithm;
    }

    public DigestAlgorithm getRelatedDigestAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        DigestAlgorithm digestAlgorithm = AlgorithmSupport.getGlobalAlgorithmRegistry().getDigestAlgorithm(signatureAlgorithm.getDigest());
        Assert.notNull(digestAlgorithm, "No corresponding message digest algorithm support for signature algorithm: " + signatureAlgorithm.getURI());
        return digestAlgorithm;
    }
}
