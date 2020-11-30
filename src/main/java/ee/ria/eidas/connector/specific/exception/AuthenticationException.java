package ee.ria.eidas.connector.specific.exception;

import eu.eidas.auth.commons.light.ILightResponse;
import lombok.Getter;
import org.opensaml.saml.saml2.core.AuthnRequest;

public class AuthenticationException extends SpecificConnectorException {

    @Getter
    private final AuthnRequest authnRequest;

    @Getter
    private final ILightResponse lightResponse;

    @Getter
    private final String statusCode;

    @Getter
    private final String subStatusCode;

    @Getter
    private final String statusMessage;

    public AuthenticationException(AuthnRequest authnRequest, ILightResponse lightResponse) {
        this(authnRequest, lightResponse, lightResponse.getStatus().getStatusCode(), lightResponse.getStatus().getSubStatusCode(), lightResponse.getStatus().getStatusMessage(), null);
    }

    public AuthenticationException(AuthnRequest authnRequest, ILightResponse lightResponse, ResponseStatus responseStatus, Throwable cause) {
        this(authnRequest, lightResponse, responseStatus.getStatusCode().getValue(), responseStatus.getSubStatusCode().getValue(), responseStatus.getStatusMessage(), cause);
    }

    public AuthenticationException(AuthnRequest authnRequest, ResponseStatus responseStatus, Throwable cause) {
        this(authnRequest, null, responseStatus.getStatusCode().getValue(), responseStatus.getSubStatusCode().getValue(), responseStatus.getStatusMessage(), cause);
    }

    private AuthenticationException(AuthnRequest authnRequest, ILightResponse lightResponse, String statusCode, String subStatusCode, String statusMessage, Throwable cause) {
        super(statusMessage, cause);
        this.authnRequest = authnRequest;
        this.lightResponse = lightResponse;
        this.statusCode = statusCode;
        this.subStatusCode = subStatusCode;
        this.statusMessage = statusMessage;
    }
}
