package ee.ria.eidas.connector.specific.integration;

import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.ILightResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import javax.cache.Cache;

@Slf4j
@Service
public class SpecificConnectorCommunication {

    @Lazy
    @Autowired
    @Qualifier("specificMSSpRequestCorrelationMap")
    private Cache<String, String> specificMSSpRequestCorrelationMap;

    public void putRequestCorrelation(ILightRequest lightRequest) {
        specificMSSpRequestCorrelationMap.put(lightRequest.getId(), lightRequest.getIssuer());
    }

    public String getAndRemoveRequestCorrelation(ILightResponse lightResponse) {
        return specificMSSpRequestCorrelationMap.getAndRemove(lightResponse.getInResponseToId());
    }
}
