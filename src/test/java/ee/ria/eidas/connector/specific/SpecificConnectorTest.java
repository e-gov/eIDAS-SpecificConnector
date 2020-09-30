package ee.ria.eidas.connector.specific;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import io.restassured.RestAssured;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import javax.cache.Cache;
import java.io.InputStream;
import java.util.List;

import static ch.qos.logback.classic.Level.*;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static io.restassured.config.RestAssuredConfig.config;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.apache.ignite.events.EventType.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;

@Slf4j
@ActiveProfiles("test")
public abstract class SpecificConnectorTest {

    protected static final WireMockServer mockEidasNodeServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/sc-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(8443)
    );

    protected static final String SP_ENTITY_ID = "https://localhost:8888/metadata";
    protected static final WireMockServer mockSPMetadataServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .keystorePath("src/test/resources/__files/mock_keys/sp-tls-keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
            .httpsPort(8888)
    );

    protected static Ignite eidasNodeIgnite;
    protected static ListAppender<ILoggingEvent> mockAppender;

    static {
        String currentDirectory = System.getProperty("user.dir");
        System.setProperty("javax.net.ssl.trustStore", "src/test/resources/__files/mock_keys/sc-tls-truststore.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        System.setProperty("SPECIFIC_CONNECTOR_CONFIG_REPOSITORY", currentDirectory + "/src/test/resources/mock_eidasnode");
        System.setProperty("EIDAS_CONFIG_REPOSITORY", currentDirectory + "/src/test/resources/mock_eidasnode");
    }

    @LocalServerPort
    protected int port;

    @MockBean
    protected BuildProperties buildProperties;

    @MockBean
    protected GitProperties gitProperties;

    @SpyBean
    protected MeterRegistry meterRegistry;

    @SpyBean
    @Qualifier("specificNodeConnectorRequestCache")
    protected Cache<String, String> specificNodeConnectorRequestCache;

    @SpyBean
    @Qualifier("nodeSpecificConnectorResponseCache")
    protected Cache<String, String> nodeSpecificConnectorResponseCache;

    @SpyBean
    @Qualifier("specificMSSpRequestCorrelationMap")
    protected Cache<String, String> specificMSSpRequestCorrelationMap;

    @BeforeAll
    static void beforeAllTests() {
        startMockEidasNodeServer();
        startMockEidasNodeIgniteServer();
        configureRestAssured();
    }

    @AfterAll
    static void afterAllTests() {
        mockEidasNodeServer.stop();
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.port = port;
        setupMockLogAppender();
    }

    private static void startMockEidasNodeServer() {
        mockEidasNodeServer.start();
        mockEidasNodeServer.stubFor(get(urlEqualTo("/EidasNode/ConnectorMetadata")).willReturn(aResponse().withStatus(200)));
    }

    private static void startMockEidasNodeIgniteServer() {
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
        updateServiceProviderMetadata("valid-metadata.xml");
    }

    protected static void updateServiceProviderMetadata(String metadataFile) {
        mockSPMetadataServer.resetAll();
        mockSPMetadataServer.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse()
                .withHeader("Content-Type", "application/xml;charset=UTF-8")
                .withStatus(200)
                .withBodyFile("sp_metadata/" + metadataFile)));
    }

    private static void configureRestAssured() {
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        RestAssured.config = config().redirect(redirectConfig().followRedirects(false));
    }

    private void setupMockLogAppender() {
        mockAppender = new ListAppender<>();
        mockAppender.start();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).addAppender(mockAppender);
    }

    protected void assertInfoIsLogged(String... messagesInRelativeOrder) {
        assertMessageIsLogged(null, INFO, messagesInRelativeOrder);
    }

    protected void assertWarningIsLogged(String... messagesInRelativeOrder) {
        assertMessageIsLogged(null, WARN, messagesInRelativeOrder);
    }

    protected void assertErrorIsLogged(String... messagesInRelativeOrder) {
        assertMessageIsLogged(null, ERROR, messagesInRelativeOrder);
    }

    protected void assertInfoIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        assertMessageIsLogged(loggerClass, INFO, messagesInRelativeOrder);
    }

    protected void assertWarningIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        assertMessageIsLogged(loggerClass, WARN, messagesInRelativeOrder);
    }

    protected void assertErrorIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        assertMessageIsLogged(loggerClass, ERROR, messagesInRelativeOrder);
    }

    @SuppressWarnings("unchecked")
    private void assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, String... messagesInRelativeOrder) {
        List<String> events = mockAppender.list.stream()
                .filter(e -> e.getLevel() == loggingLevel && (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())))
                .map(ILoggingEvent::getFormattedMessage)
                .collect(toList());
        assertThat(events, containsInRelativeOrder(stream(messagesInRelativeOrder).map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
    }

    @Test
    @Order(1)
    void contextLoads() {
    }
}
