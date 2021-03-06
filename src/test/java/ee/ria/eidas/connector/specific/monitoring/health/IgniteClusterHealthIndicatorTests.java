package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.ignite.events.CacheEvent;
import org.apache.ignite.lang.IgnitePredicate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;

import javax.cache.Cache;
import javax.cache.CacheException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.ignite.events.EventType.EVT_CACHE_OBJECT_PUT;
import static org.apache.ignite.events.EventType.EVT_CACHE_OBJECT_REMOVED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
public class IgniteClusterHealthIndicatorTests extends ApplicationHealthTest {
    private static final AtomicInteger cachePuts = new AtomicInteger();
    private static final AtomicInteger cacheRemoves = new AtomicInteger();
    private static IgnitePredicate<CacheEvent> eidasNodeCacheEventListener;

    @SpyBean
    @Qualifier("specificNodeConnectorRequestCache")
    Cache<String, String> specificNodeConnectorRequestCache;

    @SpyBean
    @Qualifier("nodeSpecificConnectorResponseCache")
    Cache<String, String> nodeSpecificConnectorResponseCache;

    @SpyBean
    @Qualifier("specificMSSpRequestCorrelationMap")
    Cache<String, String> specificMSSpRequestCorrelationMap;

    @BeforeAll
    static void setEidasNodeCacheEventListener() {
        eidasNodeCacheEventListener = evt -> {
            if ("CACHE_OBJECT_PUT".equals(evt.name())) {
                cachePuts.incrementAndGet();
            } else if ("CACHE_OBJECT_REMOVED".equals(evt.name())) {
                cacheRemoves.incrementAndGet();
            }
            return true;
        };
        eidasNodeIgnite.events()
                .localListen(eidasNodeCacheEventListener, EVT_CACHE_OBJECT_PUT, EVT_CACHE_OBJECT_REMOVED);
    }

    @AfterAll
    static void tearDownCacheEventListener() {
        if (eidasNodeCacheEventListener != null)
            eidasNodeIgnite.events().stopLocalListen(eidasNodeCacheEventListener);
    }

    @Test
    void healthStatusUpWhen_HealthyCache() {
        cachePuts.set(0);
        cacheRemoves.set(0);
        Response healthResponse = getHealthResponse();
        assertDependenciesUp(healthResponse, Dependencies.IGNITE_CLUSTER);

        assertEquals(3, cachePuts.get());
        assertEquals(3, cacheRemoves.get());
    }

    @Test
    void healthStatusDownWhen_ClusterStateInactive() {
        setClusterStateInactive();
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.IGNITE_CLUSTER);

        setClusterStateActive();
        healthResponse = getHealthResponse();
        assertDependenciesUp(healthResponse, Dependencies.IGNITE_CLUSTER);
    }

    @Test
    void healthStatusDownWhen_UnhealthyEidasSpecificNodeConnectorRequestCache() {
        assertHealthDownOnCachePutException(specificNodeConnectorRequestCache);
        assertEquals(0, cachePuts.get());
        assertEquals(0, cacheRemoves.get());
        assertHealthDownOnCacheGetAndRemoveException(specificNodeConnectorRequestCache);
        assertEquals(1, cachePuts.get());
        assertEquals(0, cacheRemoves.get());
    }

    @Test
    void healthStatusDownWhen_UnhealthyEidasNodeSpecificConnectorResponseCache() {
        assertHealthDownOnCachePutException(nodeSpecificConnectorResponseCache);
        assertEquals(1, cachePuts.get());
        assertEquals(1, cacheRemoves.get());
        assertHealthDownOnCacheGetAndRemoveException(nodeSpecificConnectorResponseCache);
        assertEquals(2, cachePuts.get());
        assertEquals(1, cacheRemoves.get());
    }

    @SneakyThrows
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void assertHealthDownOnCachePutException(Cache cache) {
        cachePuts.set(0);
        cacheRemoves.set(0);
        cleanMocks();
        Mockito.doThrow(new CacheException()).when(cache).put(any(), any());
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.IGNITE_CLUSTER);
    }

    @SneakyThrows
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void assertHealthDownOnCacheGetAndRemoveException(Cache cache) {
        cachePuts.set(0);
        cacheRemoves.set(0);
        cleanMocks();
        Mockito.doThrow(new CacheException()).when(cache).getAndRemove(any());
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.IGNITE_CLUSTER);
    }

    @SuppressWarnings({"unchecked"})
    private void cleanMocks() {
        Mockito.reset(specificNodeConnectorRequestCache,
                nodeSpecificConnectorResponseCache,
                specificMSSpRequestCorrelationMap);
    }
}
