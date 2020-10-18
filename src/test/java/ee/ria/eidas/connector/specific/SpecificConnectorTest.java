package ee.ria.eidas.connector.specific;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.*;
import org.slf4j.LoggerFactory;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static io.restassured.config.RestAssuredConfig.config;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.apache.ignite.events.EventType.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;

@Slf4j
@ActiveProfiles("test")
@ContextConfiguration(initializers = SpecificConnectorTest.TestContextInitializer.class)
public abstract class SpecificConnectorTest {
    private static final Logger rootLogger = (Logger) LoggerFactory.getLogger(ROOT_LOGGER_NAME);
    private static final Map<String, Object> EXPECTED_RESPONSE_HEADERS = new HashMap<String, Object>() {{
        put("X-XSS-Protection", "1; mode=block");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Pragma", "no-cache");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
    }};
    protected static final WireMockServer mockEidasNodeMetadataServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/specific-connector-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(8443)
    );
    protected static final String SP_ENTITY_ID = "https://localhost:8888/metadata";
    protected static final WireMockServer mockSPMetadataServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/service-provider-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(8888)
    );

    protected static Ignite eidasNodeIgnite;
    private static ListAppender<ILoggingEvent> testLogAppender;

    static {
        System.setProperty("javax.net.ssl.trustStore", "src/test/resources/__files/mock_keys/specific-connector-tls-truststore.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    @MockBean
    protected BuildProperties buildProperties;

    @MockBean
    protected GitProperties gitProperties;

    @LocalServerPort
    protected int port;

    @BeforeAll
    static void beforeAllTests() {
        startMockEidasNodeMetadataServer();
        startMockEidasNodeIgniteServer();
        setupRestAssured();
    }

    @AfterAll
    static void afterAllTests() {
        mockEidasNodeMetadataServer.stop();
        mockSPMetadataServer.stop();
    }

    @BeforeEach
    void beforeEachTest() {
        RestAssured.responseSpecification = new ResponseSpecBuilder().expectHeaders(EXPECTED_RESPONSE_HEADERS).build();
        RestAssured.port = port;
        setupTestLogAppender();
    }

    @AfterEach
    void afterEachTest() {
        rootLogger.detachAppender(testLogAppender);
    }

    @Test
    void contextLoads() {
    }

    protected static void startMockEidasNodeMetadataServer() {
        mockEidasNodeMetadataServer.start();
        mockEidasNodeMetadataServer.stubFor(get(urlEqualTo("/EidasNode/ConnectorMetadata")).willReturn(aResponse().withStatus(200)));
    }

    protected static void startMockEidasNodeIgniteServer() {
        if (eidasNodeIgnite == null) {
            System.setProperty("IGNITE_QUIET", "false");
            System.setProperty("IGNITE_HOME", System.getProperty("java.io.tmpdir"));
            System.setProperty("java.net.preferIPv4Stack", "true");
            InputStream cfgXml = SpecificConnectorTest.class.getClassLoader()
                    .getResourceAsStream("mock_eidasnode/igniteSpecificCommunication.xml");
            IgniteConfiguration cfg = Ignition.loadSpringBean(cfgXml, "igniteSpecificCommunication.cfg");
            cfg.setIncludeEventTypes(EVT_CACHE_OBJECT_PUT, EVT_CACHE_OBJECT_READ, EVT_CACHE_OBJECT_REMOVED);
            eidasNodeIgnite = Ignition.getOrStart(cfg);
        }
    }

    protected static void startServiceProviderMetadataServer() {
        mockSPMetadataServer.start();
        updateServiceProviderMetadata("sp-valid-metadata.xml");
    }

    protected static void updateServiceProviderMetadata(String metadataFile) {
        mockSPMetadataServer.resetAll();
        mockSPMetadataServer.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse()
                .withHeader("Content-Type", "application/xml;charset=UTF-8")
                .withStatus(200)
                .withBodyFile("sp_metadata/" + metadataFile)));
    }

    private static void setupRestAssured() {
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        RestAssured.config = config().redirect(redirectConfig().followRedirects(false));
    }

    private void setupTestLogAppender() {
        testLogAppender = new ListAppender<>();
        testLogAppender.start();
        rootLogger.addAppender(testLogAppender);
    }

    protected void assertLogs(Level loggingLevel, String... messagesInRelativeOrder) {
        assertLogs(null, loggingLevel, messagesInRelativeOrder);
    }

    protected void assertLogs(Class<?> loggerClass, Level loggingLevel, String... messagesInRelativeOrder) {
        assertLogs((ListAppender<ILoggingEvent>) rootLogger.getAppender("applicationLogAppender"), loggerClass, loggingLevel, messagesInRelativeOrder);
    }

    protected void assertTestLogs(Level loggingLevel, String... messagesInRelativeOrder) {
        assertLogs(testLogAppender, null, loggingLevel, messagesInRelativeOrder);
    }

    protected void assertTestLogs(Class<?> loggerClass, Level loggingLevel, String... messagesInRelativeOrder) {
        assertLogs(testLogAppender, loggerClass, loggingLevel, messagesInRelativeOrder);
    }

    @SuppressWarnings("unchecked")
    private void assertLogs(ListAppender<ILoggingEvent> logAppender, Class<?> loggerClass, Level loggingLevel, String... messagesInRelativeOrder) {
        List<String> events = logAppender.list.stream()
                .filter(e -> e.getLevel() == loggingLevel && (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())))
                .map(ILoggingEvent::getFormattedMessage)
                .collect(toList());
        assertThat(events, containsInRelativeOrder(stream(messagesInRelativeOrder).map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
    }

    public static class TestContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        public void initialize(@NotNull ConfigurableApplicationContext configurableApplicationContext) {
            String currentDirectory = System.getProperty("user.dir");
            System.setProperty("SPECIFIC_CONNECTOR_CONFIG_REPOSITORY", currentDirectory + "/src/test/resources/mock_eidasnode");
            System.setProperty("EIDAS_CONFIG_REPOSITORY", currentDirectory + "/src/test/resources/mock_eidasnode");
        }
    }
}
