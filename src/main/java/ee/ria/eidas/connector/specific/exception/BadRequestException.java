package ee.ria.eidas.connector.specific.exception;

public class BadRequestException extends SpecificConnectorException {

    public BadRequestException(String message) {
        super(message);
    }

    public BadRequestException(String format, Object... args) {
        super(format, args);
    }

    public BadRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
