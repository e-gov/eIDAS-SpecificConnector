package ee.ria.eidas.connector.specific.saml;

import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;

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

    public String getXmlString(EntityDescriptor entityDescriptor) throws MarshallingException {
        Element entityDescriptorElement = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(entityDescriptor)
                .marshall(entityDescriptor);
        return SerializeSupport.nodeToString(entityDescriptorElement);
    }

    public <T extends SAMLObject> T unmarshall(byte[] saml, Class<T> type) throws XMLParserException, UnmarshallingException {
        ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        return type.cast(XMLObjectSupport.unmarshallFromInputStream(parserPool, new ByteArrayInputStream(saml)));
    }
}
