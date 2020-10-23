package ee.ria.eidas.connector.specific.exception;

import lombok.Getter;

public class AuthenticationException extends SpecificConnectorException {

    @Getter
    private final String samlResponse;

    @Getter
    private final String assertionConsumerServiceURL;

    public AuthenticationException(String samlResponse, String assertionConsumerServiceURL, String message) {
        this(samlResponse, assertionConsumerServiceURL, message, null);
    }

    public AuthenticationException(String samlResponse, String assertionConsumerServiceURL, String message, Throwable cause) {
        super(message, cause);
        this.samlResponse = samlResponse;
        this.assertionConsumerServiceURL = assertionConsumerServiceURL;
    }
}
