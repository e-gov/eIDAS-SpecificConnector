package ee.ria.eidas.connector.specific.integration;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.events.CacheEvent;
import org.apache.ignite.lang.IgnitePredicate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import javax.cache.Cache;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.apache.ignite.events.EventType.EVT_CACHE_OBJECT_EXPIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false)
public class CacheExpirationTests extends SpecificConnectorTest {
    private static final long EVENT_TIMEOUT = 10_000;

    @MockitoSpyBean
    @Qualifier("specificNodeConnectorRequestCache")
    Cache<String, String> specificNodeConnectorRequestCache;

    @MockitoSpyBean
    @Qualifier("nodeSpecificConnectorResponseCache")
    Cache<String, String> nodeSpecificConnectorResponseCache;

    @MockitoSpyBean
    @Qualifier("specificMSSpRequestCorrelationMap")
    Cache<String, String> specificMSSpRequestCorrelationMap;

    @Test
    void specificNodeConnectorRequestCacheEventExpires() {
        cacheEventExpires(specificNodeConnectorRequestCache);
    }

    @Test
    void nodeSpecificConnectorResponseCacheEventExpires() {
        cacheEventExpires(nodeSpecificConnectorResponseCache);
    }

    @Test
    void specificMSSpRequestCorrelationMapEventExpires() {
        cacheEventExpires(specificMSSpRequestCorrelationMap);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    void cacheEventExpires(Cache cache) {
        String cacheEntryKey = "testKey-" + UUID.randomUUID();
        CountDownLatch objectExpiredLatch = new CountDownLatch(1);
        AtomicReference<CacheEvent> expiredEvent = new AtomicReference<>();
        IgnitePredicate<CacheEvent> localListener = evt -> {
            log.debug("Ignite client event: {}/{}/{}  Cache: {}", evt.type(), evt.key(), evt.oldValue(), evt.cacheName());
            if (!evt.cacheName().equals(cache.getName())) {
                return true;
            }
            if (evt.type() != EVT_CACHE_OBJECT_EXPIRED) {
                return true;
            }
            if (!evt.key().equals(cacheEntryKey)) {
                return true;
            }
            expiredEvent.set(evt);
            objectExpiredLatch.countDown();
            return true;
        };

        eidasNodeIgnite.events().localListen(localListener, EVT_CACHE_OBJECT_EXPIRED);
        cache.put(cacheEntryKey, "testValue");
        assertExpirationEvent(objectExpiredLatch);
        assertEquals("testValue", expiredEvent.get().oldValue());
        eidasNodeIgnite.events().stopLocalListen(localListener);
    }

    @SneakyThrows
    private void assertExpirationEvent(CountDownLatch latch) {
        if (!latch.await(EVENT_TIMEOUT, MILLISECONDS)) {
            fail("Failed to wait for object expired event.");
        }
    }
}
