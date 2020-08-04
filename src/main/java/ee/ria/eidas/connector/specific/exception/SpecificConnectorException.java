package ee.ria.eidas.connector.specific.exception;

import static java.lang.String.format;

public class SpecificConnectorException extends RuntimeException {

    public SpecificConnectorException(String message) {
        super(message);
    }

    public SpecificConnectorException(String messageFormat, Object... args) {
        super(format(messageFormat, args));
    }

    public SpecificConnectorException(Throwable cause, String messageFormat, Object... args) {
        super(format(messageFormat, args), cause);
    }

    public SpecificConnectorException(String message, Throwable cause) {
        super(message, cause);
    }

}
