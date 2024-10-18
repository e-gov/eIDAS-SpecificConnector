package ee.ria.eidas.connector.specific.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import ee.ria.eidas.connector.specific.exception.AuthenticationException;
import ee.ria.eidas.connector.specific.exception.BadRequestException;
import ee.ria.eidas.connector.specific.exception.CertificateResolverException;
import ee.ria.eidas.connector.specific.integration.EidasNodeCommunication;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.commons.light.ILightResponse;
import eu.eidas.auth.commons.light.IResponseStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Base64;

import static ee.ria.eidas.connector.specific.exception.ResponseStatus.SP_ENCRYPTION_CERT_MISSING_OR_INVALID;
import static eu.eidas.auth.commons.EidasParameterKeys.RELAY_STATE;
import static eu.eidas.auth.commons.EidasParameterKeys.SAML_RESPONSE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.logstash.logback.marker.Markers.append;
import static net.logstash.logback.marker.Markers.appendRaw;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ConnectorResponseController {
    private final EidasNodeCommunication eidasNodeCommunication;
    private final SpecificConnectorCommunication specificConnectorCommunication;
    private final ServiceProviderMetadataRegistry metadataRegistry;
    private final ResponseFactory responseFactory;
    private final MappingJackson2XmlHttpMessageConverter messageConverter;

    @GetMapping(value = "/ConnectorResponse")
    public ModelAndView get(@RequestParam("token") @Pattern(regexp = "^[A-Za-z0-9+/=]{1,1000}$") String token) throws MalformedURLException {
        Response response = processResponse(token);
        URL redirectUrl = UriComponentsBuilder.fromUri(URI.create(response.getAssertionConsumerServiceUrl()))
                .queryParam(SAML_RESPONSE.getValue(), UriUtils.encode(response.getSamlResponseBase64(), UTF_8))
                .queryParam(RELAY_STATE.getValue(), response.getRelayState())
                .build(true).toUri().toURL();
        return new ModelAndView("redirect:" + redirectUrl);
    }

    @PostMapping(value = "/ConnectorResponse")
    public ModelAndView post(@RequestParam("token") @Pattern(regexp = "^[A-Za-z0-9+/=]{1,1000}$") String token, HttpServletRequest request) {
        Response response = processResponse(token);
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.addObject(SAML_RESPONSE.getValue(), response.getSamlResponseBase64());
        modelAndView.addObject(RELAY_STATE.getValue(), response.getRelayState());
        modelAndView.addObject("action", response.getAssertionConsumerServiceUrl());
        modelAndView.setViewName("postBinding");
        return modelAndView;
    }

    @SneakyThrows
    private Response processResponse(String token) {
        ILightResponse lightResponse = getLightResponse(token);
        AuthnRequest authnRequest = getAuthnRequest(lightResponse);
        ServiceProviderMetadata spMetadata = getServiceProviderMetadata(authnRequest);

        IResponseStatus status = lightResponse.getStatus();
        if (status.isFailure()) {
            throw new AuthenticationException(authnRequest, lightResponse);
        } else {
            try {
                String samlResponse = responseFactory.createSamlResponse(authnRequest, lightResponse, spMetadata);
                String assertionConsumerServiceUrl = spMetadata.getAssertionConsumerServiceUrl();
                String samlResponseBase64 = Base64.getEncoder().encodeToString(samlResponse.getBytes());
                logSuccessfulAuthenticationResult(samlResponse, lightResponse);
                return new Response(samlResponseBase64, lightResponse.getRelayState(), assertionConsumerServiceUrl);
            } catch (CertificateResolverException certificateException) {
                throw new AuthenticationException(authnRequest, lightResponse, SP_ENCRYPTION_CERT_MISSING_OR_INVALID, certificateException);
            }
        }
    }

    @NotNull
    private ILightResponse getLightResponse(String token) {
        try {
            ILightResponse lightResponse = eidasNodeCommunication.getAndRemoveLightResponse(token);
            if (lightResponse == null) {
                throw new BadRequestException("Token is invalid or has expired");
            }
            return lightResponse;
        } catch (SecurityEIDASException ex) {
            throw new BadRequestException("Token is invalid", ex);
        }
    }

    @NotNull
    private AuthnRequest getAuthnRequest(ILightResponse lightResponse) {
        AuthnRequest authnRequest = specificConnectorCommunication.getAndRemoveAuthenticationRequest(lightResponse);
        if (authnRequest == null) {
            throw new BadRequestException("Authentication request related to token is invalid or has expired");
        }
        return authnRequest;
    }

    @NotNull
    private ServiceProviderMetadata getServiceProviderMetadata(AuthnRequest authnRequest) {
        ServiceProviderMetadata spMetadata = metadataRegistry.get(authnRequest.getIssuer().getValue());
        if (spMetadata == null) {
            throw new BadRequestException("SAML request is invalid - issuer not allowed");
        }
        return spMetadata;
    }

    private void logSuccessfulAuthenticationResult(String samlResponse, ILightResponse lightResponse) {
        try {
            JsonNode samResponseJson = messageConverter.getObjectMapper().readTree(samlResponse);
            log.info(appendRaw("saml_response", samResponseJson.toString())
                    .and(append("authn_request.relay_state", lightResponse.getRelayState()))
                    .and(append("light_request.id", lightResponse.getInResponseToId()))
                    .and(append("light_response.id", lightResponse.getId()))
                    .and(append("event.kind", "event"))
                    .and(append("event.category", "authentication"))
                    .and(append("event.type", "end"))
                    .and(append("event.outcome", "success")), "SAML Response created");
        } catch (JsonProcessingException e) {
            log.error("Unable to convert SAMLResponse from xml to json", e);
        }
    }

    @Getter
    @RequiredArgsConstructor
    private static class Response {
        private final String samlResponseBase64;
        private final String relayState;
        private final String assertionConsumerServiceUrl;
    }
}
