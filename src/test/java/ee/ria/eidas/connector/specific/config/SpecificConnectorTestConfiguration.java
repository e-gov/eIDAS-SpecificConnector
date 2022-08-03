package ee.ria.eidas.connector.specific.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

@TestConfiguration
public class SpecificConnectorTestConfiguration {

    @Bean
    public Clock clock() {
        // Many XML files and keystores in test/resources/__files/ directory contain certificates that expired in July 2022.
        // Some files in that directory MUST be expired to test validation - these have expiration date of January 2020.
        // The date specified on the following line needs to be between these 2 dates for the tests to work as expected.
        return Clock.fixed(Instant.parse("2022-01-01T00:00:00Z"), ZoneOffset.UTC);
    }
}
