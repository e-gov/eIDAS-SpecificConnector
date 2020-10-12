package ee.ria.eidas.connector.specific.metadata.sp;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "eidas.connector.service-provider-metadata-min-refresh-delay=1000",
                "eidas.connector.service-provider-metadata-max-refresh-delay=60000",
                "eidas.connector.service-provider-metadata-refresh-delay-factor=0.99",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[0].type=public",
                "eidas.connector.service-providers[1].id=service-provider-1",
                "eidas.connector.service-providers[1].entity-id=https://localhost:9999/metadata",
                "eidas.connector.service-providers[1].key-alias=service-provider-1-metadata-signing",
                "eidas.connector.service-providers[1].type=public"
        })
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class ServiceProviderMetadataExpiredMetadataSigningCertificateTest extends ServiceProviderTest {

    @BeforeAll
    static void beforeAll() {
        startServiceProviderMetadataServer();
        startServiceProvider1MetadataServer("sp1-expired-metadata-signing-cert.xml");
    }

    @Test
    @Order(1)
    @SneakyThrows
    void requestSignatureValidationFailsWhen_InvalidMetadataState() {
        assertUnsuccessfulRequestSignatureValidation();
    }

    @Test
    @Order(2)
    void serviceProviderMetadataIsUpdatedAndValidWhen_MetadataIsUpdated() {
        assertValidMetadataAfterServiceProviderMetadataUpdate();
    }

    @Test
    @Order(3)
    @SneakyThrows
    void requestSignatureValidationSucceedsWhen_ValidMetadataState() {
        assertSuccessfulRequestSignatureValidation();
    }
}
