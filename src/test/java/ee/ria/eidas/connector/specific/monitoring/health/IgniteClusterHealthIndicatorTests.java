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
import org.springframework.boot.test.context.SpringBootTest;

import javax.cache.Cache;
import javax.cache.CacheException;
import java.util.concurrent.atomic.AtomicInteger;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.apache.ignite.events.EventType.EVT_CACHE_OBJECT_PUT;
import static org.apache.ignite.events.EventType.EVT_CACHE_OBJECT_REMOVED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.jmx.exposure.exclude=*",
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat",
                "management.endpoints.web.base-path=/",
                "management.info.git.mode=full",
                "management.health.defaults.enabled=false",
                "eidas.connector.health.trust-store-expiration-warning=30d"
        })
public class IgniteClusterHealthIndicatorTests extends ApplicationHealthTest {
    private static final AtomicInteger cachePuts = new AtomicInteger();
    private static final AtomicInteger cacheRemoves = new AtomicInteger();
    private static IgnitePredicate<CacheEvent> eidasNodeCacheEventListener;

    @BeforeAll
    public static void setEidasNodeCacheEventListener() {
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
    public static void tearDownCacheEventListener() {
        if (eidasNodeCacheEventListener != null)
            eidasNodeIgnite.events().stopLocalListen(eidasNodeCacheEventListener);
    }

    @Test
    public void healthStatusUpWhenHealthyCache() {
        cachePuts.set(0);
        cacheRemoves.set(0);
        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertDependenciesUp(healthResponse);

        assertEquals(2, cachePuts.get());
        assertEquals(2, cacheRemoves.get());
    }

    @Test
    public void healthStatusDownWhenClusterStateInactive() {
        setClusterStateInactive();
        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertDependenciesDown(healthResponse, Dependencies.CONNECTOR_METADATA);

        setClusterStateActive();
        healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertDependenciesUp(healthResponse);
    }

    @Test
    public void healthStatusDownWhen_UnhealthyEidasSpecificNodeConnectorRequestCache() {
        assertHealthDownOnCachePutException(specificNodeConnectorRequestCache);
        assertEquals(0, cachePuts.get());
        assertEquals(0, cacheRemoves.get());
        assertHealthDownOnCacheGetAndRemoveException(specificNodeConnectorRequestCache);
        assertEquals(1, cachePuts.get());
        assertEquals(0, cacheRemoves.get());
    }

    @Test
    public void healthStatusDownWhenUnhealthyEidasNodeSpecificConnectorResponseCache() {
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
        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertDependenciesDown(healthResponse, Dependencies.CONNECTOR_METADATA);
    }

    @SneakyThrows
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void assertHealthDownOnCacheGetAndRemoveException(Cache cache) {
        cachePuts.set(0);
        cacheRemoves.set(0);
        cleanMocks();
        Mockito.doThrow(new CacheException()).when(cache).getAndRemove(any());
        Response healthResponse = given()
                .when()
                .get(APPLICATION_HEALTH_ENDPOINT_REQUEST)
                .then()
                .assertThat()
                .statusCode(200)
                .contentType(JSON).extract().response();
        assertDependenciesDown(healthResponse, Dependencies.CONNECTOR_METADATA);
    }

    @SuppressWarnings({"unchecked"})
    public void cleanMocks() {
        Mockito.reset(specificNodeConnectorRequestCache,
                nodeSpecificConnectorResponseCache);
    }
}
