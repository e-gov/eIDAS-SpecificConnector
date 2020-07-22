package ee.ria.eidas.connector.specific.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotNull;

@ConfigurationProperties(prefix = "eidas.connector")
public class SpecificConnectorProperties {

    @NotNull
    private String appInstanceId;

}
