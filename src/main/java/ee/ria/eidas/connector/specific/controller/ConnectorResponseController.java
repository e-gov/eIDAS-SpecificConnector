package ee.ria.eidas.connector.specific.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import ee.ria.eidas.connector.specific.exception.AuthenticationException;
import ee.ria.eidas.connector.specific.exception.BadRequestException;
import ee.ria.eidas.connector.specific.integration.EidasNodeCommunication;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import eu.eidas.auth.commons.light.ILightResponse;
import eu.eidas.auth.commons.light.IResponseStatus;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Pattern;
import java.util.Base64;

import static net.logstash.logback.marker.Markers.append;
import static net.logstash.logback.marker.Markers.appendRaw;
import static org.springframework.web.servlet.View.RESPONSE_STATUS_ATTRIBUTE;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ConnectorResponseController {
    private final EidasNodeCommunication eidasNodeCommunication;
    private final SpecificConnectorCommunication specificConnectorCommunication;
    private final ServiceProviderMetadataRegistry metadataRegistry;
    private final ResponseFactory responseFactory;
    private final MappingJackson2XmlHttpMessageConverter xmlMapper;

    @GetMapping(value = "/ConnectorResponse")
    public ModelAndView get(@RequestParam("token") @Pattern(regexp = "^[A-Za-z0-9+/=]{1,1000}$") String token) {
        return execute(token);
    }

    @PostMapping(value = "/ConnectorResponse")
    public ModelAndView post(@RequestParam("token") @Pattern(regexp = "^[A-Za-z0-9+/=]{1,1000}$") String token, HttpServletRequest request) {
        request.setAttribute(RESPONSE_STATUS_ATTRIBUTE, HttpStatus.TEMPORARY_REDIRECT);
        return execute(token);
    }

    @SneakyThrows
    private ModelAndView execute(String token) {
        ILightResponse lightResponse = eidasNodeCommunication.getAndRemoveLightResponse(token);
        if (lightResponse == null) {
            throw new BadRequestException("Token is invalid or has expired");
        }
        AuthnRequest authnRequest = specificConnectorCommunication.getAndRemoveRequestCorrelation(lightResponse);
        if (authnRequest == null) {
            throw new BadRequestException("Authentication request related to token is invalid or has expired");
        }
        ServiceProviderMetadata spMetadata = metadataRegistry.get(authnRequest.getIssuer().getValue());
        if (spMetadata == null) {
            throw new BadRequestException("SAML request is invalid - issuer not allowed");
        }

        IResponseStatus status = lightResponse.getStatus();
        if (status.isFailure()) {
            String samlResponse = responseFactory.createSamlErrorResponse(authnRequest, lightResponse);
            logAuthenticationResult(samlResponse, status, lightResponse.getRelayState(), "info");
            throw new AuthenticationException(samlResponse, authnRequest.getAssertionConsumerServiceURL(), status.getStatusMessage());
        } else {
            String samlResponse = responseFactory.createSamlResponse(lightResponse, spMetadata);
            String assertionConsumerServiceUrl = spMetadata.getAssertionConsumerServiceUrl();
            ModelAndView modelAndView = new ModelAndView("redirect:" + assertionConsumerServiceUrl);
            String samlResponseBase64 = Base64.getEncoder().encodeToString(samlResponse.getBytes());
            modelAndView.addObject("SAMLResponse", samlResponseBase64);
            modelAndView.addObject("RelayState", lightResponse.getRelayState());
            logAuthenticationResult(samlResponse, status, lightResponse.getRelayState(), "end");
            return modelAndView;
        }
    }

    private void logAuthenticationResult(String samlResponse, IResponseStatus status, String relayState, String eventType) {
        try {
            JsonNode samResponseJson = xmlMapper.getObjectMapper().readTree(samlResponse);
            log.info(appendRaw("saml_response", samResponseJson.toString())
                            .and(append("authn_request.relay_state", relayState))
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", eventType))
                            .and(append("event.outcome", status.isFailure() ? "failure" : "success")),
                    "SAML response created");
        } catch (JsonProcessingException e) {
            log.warn("Unable to parse AuthnRequest");
        }
    }
}
