package ee.ria.eidas.connector.specific.validation;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.HsmProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.apache.logging.log4j.util.Strings.isEmpty;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {HsmConfigurationValidator.class})
public @interface ValidHsmConfiguration {
    String message() default "Invalid HSM configuration";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}

class HsmConfigurationValidator implements ConstraintValidator<ValidHsmConfiguration, SpecificConnectorProperties> {

    @Override
    public boolean isValid(SpecificConnectorProperties specificConnectorProperties, ConstraintValidatorContext context) {
        HsmProperties hsmProperties = specificConnectorProperties.getHsm();
        ResponderMetadata responderMetadata = specificConnectorProperties.getResponderMetadata();
        boolean hsmDisabled = hsmProperties == null || !hsmProperties.isEnabled();
        if (hsmDisabled && isEmpty(responderMetadata.getKeyPassword())) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("'eidas.connector.responder-metadata.key-password' property must be set if 'eidas.connector.hsm.enabled=false'")
                    .addConstraintViolation();
            return false;
        } else return hsmDisabled
                || (!isEmpty(hsmProperties.getLibrary()) && !isEmpty(hsmProperties.getPin())
                && (hsmProperties.getSlotListIndex() != null || !isEmpty(hsmProperties.getSlot())));
    }
}
