package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SpringExtension.class)
public class SupportedAttributesTest {

    @Test
    void validSupportedAttribute() {
        SupportedAttribute personIdentifier = new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", "PersonIdentifier");
        assertEquals("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", personIdentifier.getName());
        assertEquals("PersonIdentifier", personIdentifier.getFriendlyName());
    }

    @Test
    void throwsErrorWhen_InvalidName() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifierInvalid", "PersonIdentifier");
        });
        assertEquals("Unsupported eIDAS attribute. Name: http://eidas.europa.eu/attributes/naturalperson/PersonIdentifierInvalid, FriendlyName: PersonIdentifier", exception.getMessage());
    }

    @Test
    void throwsErrorWhen_InvalidFriendlyName() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new SupportedAttribute("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", "PersonIdentifierInvalid");
        });
        assertEquals("Unsupported eIDAS attribute. Name: http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier, FriendlyName: PersonIdentifierInvalid", exception.getMessage());
    }
}
