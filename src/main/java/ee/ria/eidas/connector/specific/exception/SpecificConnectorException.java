package ee.ria.eidas.connector.specific.exception;

import static java.lang.String.format;

public class SpecificConnectorException extends RuntimeException {

    public SpecificConnectorException(String messageFormat, Object... args) {
        super(format(messageFormat, args));
    }

    public SpecificConnectorException(String message, Throwable cause) {
        super(message, cause);
    }

}
