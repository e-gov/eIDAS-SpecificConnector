package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.monitoring.health.ResponderMetadataHealthIndicator.FailedSigningEvent;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.x509.BasicX509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

@Component
public class ResponderMetadataGenerator {

    @Autowired
    private SpecificConnectorProperties connectorProperties;

    @Autowired
    private ResponderMetadataSigner responderMetadataSigner;

    @Autowired
    private BasicX509Credential signingCredential;

    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    public EntityDescriptor createSignedMetadata() {
        try {
            ResponderMetadata responderMetadata = connectorProperties.getResponderMetadata();
            EntityDescriptor entityDescriptor = EntityDescriptorFactory.create(responderMetadata, signingCredential);
            responderMetadataSigner.sign(entityDescriptor);
            return entityDescriptor;
        } catch (Exception e) {
            applicationEventPublisher.publishEvent(new FailedSigningEvent());
            throw new TechnicalException("Unable to generate responder metadata", e);
        }
    }
}
