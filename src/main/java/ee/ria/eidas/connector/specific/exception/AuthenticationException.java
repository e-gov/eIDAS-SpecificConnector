package ee.ria.eidas.connector.specific.exception;

public class AuthenticationException extends SpecificConnectorException {

    public AuthenticationException(String messageFormat, Object... args) {
        super(messageFormat, args);
    }
}
