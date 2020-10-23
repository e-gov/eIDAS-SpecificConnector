package ee.ria.eidas.connector.specific.exception;

import eu.eidas.auth.commons.EIDASStatusCode;
import eu.eidas.auth.commons.EIDASSubStatusCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import static eu.eidas.auth.commons.EIDASStatusCode.REQUESTER_URI;
import static eu.eidas.auth.commons.EIDASSubStatusCode.REQUEST_DENIED_URI;

@Getter
@RequiredArgsConstructor
public enum AuthenticationStatus {
    SP_LOA_MISSING_OR_INVALID("LoA is missing or invalid", REQUESTER_URI, REQUEST_DENIED_URI),
    SP_SIGNING_CERT_MISSING_OR_INVALID("The signing key in the service provider metadata is not valid or accessible", REQUESTER_URI, REQUEST_DENIED_URI),
    SP_ENCRYPTION_KEY_NOT_ACCESSIBLE("The encryption key in the service provider metadata is not valid or accessible", REQUESTER_URI, REQUEST_DENIED_URI);
    private final String statusMessage;
    private final EIDASStatusCode statusCode;
    private final EIDASSubStatusCode subStatusCode;
}