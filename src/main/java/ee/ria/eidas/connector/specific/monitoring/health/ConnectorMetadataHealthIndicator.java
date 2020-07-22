package ee.ria.eidas.connector.specific.monitoring.health;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.net.URL;
import java.time.Duration;

import static java.lang.Math.toIntExact;

@Slf4j
@Component
public class ConnectorMetadataHealthIndicator extends AbstractHealthIndicator {

    @Value("${connector.metadata.url}")
    private String connectorMetadataUrl;

    @Value("${eidas.connector.health.dependencies.connect-timeout:3}")
    private Duration connectTimeout;

    public ConnectorMetadataHealthIndicator() {
        super("Connector metadata health check failed");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        URL url = new URL(connectorMetadataUrl);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setConnectTimeout(toIntExact(connectTimeout.toMillis()));
        con.setSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());
        try {
            if (con.getResponseCode() == HttpsURLConnection.HTTP_OK) {
                builder.up();
            } else {
                builder.down();
            }
        } finally {
            con.disconnect();
        }
    }
}
