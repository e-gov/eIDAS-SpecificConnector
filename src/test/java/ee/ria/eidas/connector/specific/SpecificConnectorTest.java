package ee.ria.eidas.connector.specific;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.io.InputStream;
import java.util.List;

import static ch.qos.logback.classic.Level.*;
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
    @Getter
    private static Ignite eidasNodeIgnite;
    private static ListAppender<ILoggingEvent> mockAppender;

    static {
        String currentDirectory = System.getProperty("user.dir");
        System.setProperty("javax.net.ssl.trustStore", "src/test/resources/__files/mock_keys/tls-truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStoreType", "jks");
        System.setProperty("SPECIFIC_CONNECTOR_CONFIG_REPOSITORY", currentDirectory + "/src/test/resources/mock_eidasnode");
        System.setProperty("EIDAS_CONFIG_REPOSITORY", currentDirectory + "/src/test/resources/mock_eidasnode");
    }

    @MockBean
    protected BuildProperties buildProperties;

    @MockBean
    protected GitProperties gitProperties;

    @BeforeAll
    static void beforeAllTests() {
        startMockEidasNodeIgniteServer();
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

    @BeforeEach
    public void beforeEachTest() {
        setupMockLogAppender();
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
