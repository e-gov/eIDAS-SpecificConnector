package ee.ria.eidas.connector.specific.integration;

import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import eu.eidas.auth.commons.light.ILightResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;

import javax.cache.Cache;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Service
public class SpecificConnectorCommunication {

    @Lazy
    @Autowired
    @Qualifier("specificMSSpRequestCorrelationMap")
    private Cache<String, String> specificMSSpRequestCorrelationMap;

    public void putRequestCorrelation(AuthnRequest authnRequest) {
        try {
            String correlationId = authnRequest.getID();
            String encodedAuthnRequest = Base64.getEncoder().encodeToString(OpenSAMLUtils.getXmlString(authnRequest).getBytes(UTF_8));
            boolean isInserted = specificMSSpRequestCorrelationMap.putIfAbsent(correlationId, encodedAuthnRequest);
            log.info(append("communication_cache.name", specificMSSpRequestCorrelationMap.getName())
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "info")),
                    "Put AuthnRequest to cache with id: '{}', Result: {} ",
                    value("authn_request.ID", correlationId), value("communication_cache.result", isInserted));
            if (!isInserted) {
                throw new TechnicalException("AuthnRequest was not saved. A AuthnRequest with id: '%s' already exists", correlationId);
            }
        } catch (MarshallingException ex) {
            throw new TechnicalException("Unable to marshall AuthnRequest", ex);
        }
    }

    @Nullable
    public AuthnRequest getAndRemoveRequestCorrelation(ILightResponse lightResponse) {
        try {
            String correlationId = lightResponse.getInResponseToId();
            String authnRequest = specificMSSpRequestCorrelationMap.getAndRemove(correlationId);
            log.info(append("communication_cache.name", specificMSSpRequestCorrelationMap.getName())
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "info")),
                    "Get and remove AuthnRequest from cache with id: '{}', Result: {}",
                    value("authn_request.ID", correlationId), value("communication_cache.result", authnRequest != null));
            return OpenSAMLUtils.unmarshallAuthnRequest(authnRequest);
        } catch (UnmarshallingException | XMLParserException ex) {
            throw new TechnicalException("Unable to unmarshall AuthnRequest", ex);
        }
    }
}
