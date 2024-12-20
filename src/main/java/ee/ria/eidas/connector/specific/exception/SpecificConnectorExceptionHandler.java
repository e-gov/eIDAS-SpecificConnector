package ee.ria.eidas.connector.specific.exception;

import com.fasterxml.jackson.databind.JsonNode;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import eu.eidas.auth.commons.light.ILightResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.validation.BindException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.util.Base64;
import java.util.UUID;

import static eu.eidas.auth.commons.EidasParameterKeys.RELAY_STATE;
import static eu.eidas.auth.commons.EidasParameterKeys.SAML_RESPONSE;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.logstash.logback.marker.Markers.append;
import static net.logstash.logback.marker.Markers.appendRaw;
import static org.springframework.web.servlet.View.RESPONSE_STATUS_ATTRIBUTE;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class SpecificConnectorExceptionHandler {
    public static final String BAD_REQUEST_ERROR_MESSAGE = "Bad request exception: %s";
    public static final String AUTHENTICATION_FAILED_ERROR_MESSAGE = "SAML Response created. Authentication failed: %s";
    private final MappingJackson2XmlHttpMessageConverter messageConverter;
    private final ResponseFactory responseFactory;

    @ExceptionHandler({HttpRequestMethodNotSupportedException.class})
    public ModelAndView handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex, HttpServletResponse response) throws IOException {
        log.error(format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()));
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return new ModelAndView();
    }

    @ExceptionHandler({MissingServletRequestParameterException.class, ConstraintViolationException.class, BindException.class})
    public ModelAndView handleValidationException(Exception ex, HttpServletResponse response) throws IOException {
        log.error(format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()));
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return new ModelAndView();
    }

    @ExceptionHandler({BadRequestException.class})
    public ModelAndView handleBadRequestException(BadRequestException ex, HttpServletResponse response) throws IOException {
        log.error(append("event.kind", "event")
                        .and(append("event.category", "authentication"))
                        .and(append("event.type", "end"))
                        .and(append("event.outcome", "failure")),
                format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()), ex.getCause());
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return new ModelAndView();
    }

    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public ModelAndView handleNoResourceException(Exception ex, HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_NOT_FOUND);
        return new ModelAndView();
    }

    @ExceptionHandler({AuthenticationException.class})
    public Object handleAuthenticationException(AuthenticationException ex, HttpServletRequest request) throws IOException {
        AuthnRequest authnRequest = ex.getAuthnRequest();
        ILightResponse lightResponse = ex.getLightResponse();
        String samlResponse = responseFactory.createSamlErrorResponse(authnRequest, ex.getStatusCode(), ex.getSubStatusCode(), ex.getStatusMessage());
        JsonNode samlResponseJson = messageConverter.getObjectMapper().readTree(samlResponse);

        LogstashMarker markers = appendRaw("saml_response", samlResponseJson.toString())
                .and(append("event.kind", "event"))
                .and(append("event.category", "authentication"))
                .and(append("event.type", "end"))
                .and(append("event.outcome", "failure"));
        if (lightResponse != null) {
            markers.and(append("authn_request.relay_state", lightResponse.getRelayState()))
                    .and(append("light_request.id", lightResponse.getInResponseToId()))
                    .and(append("light_response.id", lightResponse.getId()));
        }
        log.error(markers, format(AUTHENTICATION_FAILED_ERROR_MESSAGE, ex.getMessage()), ex.getCause());

        String samlResponseBase64 = Base64.getEncoder().encodeToString(samlResponse.getBytes());
        if (HttpMethod.POST.matches(request.getMethod())) {
            ModelAndView modelAndView = new ModelAndView();
            modelAndView.addObject(SAML_RESPONSE.getValue(), samlResponseBase64);
            modelAndView.addObject(RELAY_STATE.getValue(), lightResponse != null ? lightResponse.getRelayState() : UUID.randomUUID());
            modelAndView.addObject("action", authnRequest.getAssertionConsumerServiceURL());
            modelAndView.setViewName("postBinding");
            return modelAndView;
        } else {
            request.setAttribute(RESPONSE_STATUS_ATTRIBUTE, HttpStatus.FOUND);
            String uri = UriComponentsBuilder.fromHttpUrl(authnRequest.getAssertionConsumerServiceURL())
                    .queryParam(SAML_RESPONSE.getValue(), UriUtils.encode(samlResponseBase64, UTF_8))
                    .queryParam(RELAY_STATE.getValue(), lightResponse != null ? lightResponse.getRelayState() : UUID.randomUUID())
                    .build(true)
                    .toUri()
                    .toString();
            return new RedirectView(uri);
        }
    }

    @ExceptionHandler({TechnicalException.class})
    public ModelAndView handleTechnicalException(TechnicalException ex, HttpServletResponse response) throws IOException {
        log.error(ex.getMessage(), ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }

    @ExceptionHandler({Exception.class})
    public ModelAndView handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Unexpected exception", ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }
}
