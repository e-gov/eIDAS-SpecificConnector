package ee.ria.eidas.connector.specific.exception;

public class TechnicalException extends SpecificConnectorException {

    public TechnicalException(String messageFormat, Object... args) {
        super(messageFormat, args);
    }

    public TechnicalException(String message, Throwable cause) {
        super(message, cause);
    }
}
