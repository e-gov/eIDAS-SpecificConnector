package ee.ria.eidas.connector.specific.exception;

import lombok.Getter;

@Getter
public class BadRequestException extends SpecificConnectorException {

    public BadRequestException(String message) {
        this(message, null);
    }

    public BadRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
