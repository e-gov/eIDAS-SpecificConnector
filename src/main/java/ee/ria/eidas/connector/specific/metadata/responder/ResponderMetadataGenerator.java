package ee.ria.eidas.connector.specific.metadata.responder;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.saml.OpenSAMLUtils;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ResponderMetadataGenerator {

    @Autowired
    private SpecificConnectorProperties connectorProperties;

    @Autowired
    private ResponderMetadataSigner responderMetadataSigner;

    public String createSignedMetadata() {
        try {
            ResponderMetadata responderMetadata = connectorProperties.getResponderMetadata();
            EntityDescriptor entityDescriptor = EntityDescriptorFactory.create(responderMetadata, responderMetadataSigner.getSigningCredential());
            responderMetadataSigner.sign(entityDescriptor);
            return OpenSAMLUtils.getXmlString(entityDescriptor);
        } catch (Exception e) {
            throw new TechnicalException("Unable to generate responder metadata", e);
        }
    }
}
