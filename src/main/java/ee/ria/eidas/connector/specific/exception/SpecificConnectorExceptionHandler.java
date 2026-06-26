package ee.ria.eidas.connector.specific.exception;

import tools.jackson.databind.JsonNode;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.xml.JacksonXmlHttpMessageConverter;
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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.DEFAULT_CONTENT_SECURITY_POLICY;
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
    private final JacksonXmlHttpMessageConverter messageConverter;
    private final ResponseFactory responseFactory;

    @ExceptionHandler({HttpRequestMethodNotSupportedException.class})
    public ResponseEntity<Map<String, Object>> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex,
                                                                                             HttpServletRequest request) {
        log.error(format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()));
        return errorResponse(HttpStatus.METHOD_NOT_ALLOWED, ex.getMessage(), request);
    }

    @ExceptionHandler({MissingServletRequestParameterException.class, ConstraintViolationException.class, BindException.class})
    public ResponseEntity<Map<String, Object>> handleValidationException(Exception ex, HttpServletRequest request) {
        log.error(format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()));
        return errorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    @ExceptionHandler({BadRequestException.class})
    public ResponseEntity<Map<String, Object>> handleBadRequestException(BadRequestException ex, HttpServletRequest request) {
        log.error(append("event.kind", "event")
                        .and(append("event.category", "authentication"))
                        .and(append("event.type", "end"))
                        .and(append("event.outcome", "failure")),
                format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()), ex.getCause());
        return errorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public ResponseEntity<Map<String, Object>> handleNoResourceException(Exception ex, HttpServletRequest request) {
        return errorResponse(HttpStatus.NOT_FOUND, HttpStatus.NOT_FOUND.getReasonPhrase(), request);
    }

    @ExceptionHandler({AuthenticationException.class})
    public Object handleAuthenticationException(AuthenticationException ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthnRequest authnRequest = ex.getAuthnRequest();
        ILightResponse lightResponse = ex.getLightResponse();
        String samlResponse = responseFactory.createSamlErrorResponse(authnRequest, ex.getStatusCode(), ex.getSubStatusCode(), ex.getStatusMessage());
        JsonNode samlResponseJson = messageConverter.getMapper().readTree(samlResponse);

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
            applyResponseHeaders(response);
            ModelAndView modelAndView = new ModelAndView();
            modelAndView.addObject(SAML_RESPONSE.getValue(), samlResponseBase64);
            modelAndView.addObject(RELAY_STATE.getValue(), lightResponse != null ? lightResponse.getRelayState() : UUID.randomUUID());
            modelAndView.addObject("action", authnRequest.getAssertionConsumerServiceURL());
            modelAndView.setViewName("postBinding");
            return modelAndView;
        } else {
            request.setAttribute(RESPONSE_STATUS_ATTRIBUTE, HttpStatus.FOUND);
            String uri = UriComponentsBuilder.fromUriString(authnRequest.getAssertionConsumerServiceURL())
                    .queryParam(SAML_RESPONSE.getValue(), UriUtils.encode(samlResponseBase64, UTF_8))
                    .queryParam(RELAY_STATE.getValue(), lightResponse != null ? lightResponse.getRelayState() : UUID.randomUUID())
                    .build(true)
                    .toUri()
                    .toString();
            return new RedirectView(uri);
        }
    }

    @ExceptionHandler({TechnicalException.class})
    public ResponseEntity<Map<String, Object>> handleTechnicalException(TechnicalException ex, HttpServletRequest request) {
        log.error(ex.getMessage(), ex);
        return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR, SpecificConnectorErrorAttributes.INTERNAL_EXCEPTION_MSG, request);
    }

    @ExceptionHandler({Exception.class})
    public ResponseEntity<Map<String, Object>> handleAll(Exception ex, HttpServletRequest request) {
        log.error("Unexpected exception", ex);
        return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR, SpecificConnectorErrorAttributes.INTERNAL_EXCEPTION_MSG, request);
    }

    private ResponseEntity<Map<String, Object>> errorResponse(HttpStatus status, String message, HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", request.getRequestURI());
        body.put("locale", request.getLocale().toString());
        body.put("incidentNumber", UUID.randomUUID().toString());
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
    }

    private void applyResponseHeaders(HttpServletResponse response) {
        if (response == null) {
            return;
        }
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", DEFAULT_CONTENT_SECURITY_POLICY);
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
    }
}
