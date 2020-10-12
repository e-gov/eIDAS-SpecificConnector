package ee.ria.eidas.connector.specific.validation;


import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Documented
@Retention(RUNTIME)
@Target({METHOD, FIELD, TYPE})
@Constraint(validatedBy = SpELAssertValidator.class)
@Repeatable(SpELAssert.List.class)
public @interface SpELAssert {

    String message() default "{ee.ria.eidas.connector.specific.validation.SpELAssert.message}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    String appliesTo() default "";

    String value();

    @Documented
    @Retention(RUNTIME)
    @Target({METHOD, FIELD, TYPE})
    @interface List {
        SpELAssert[] value();
    }
}