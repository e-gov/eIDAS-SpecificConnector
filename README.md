# EE specific eIDAS connector service

- [1. Building the SpecificConnector webapp](#build)
- [2. Integration with EidasNode webapp](#integrate_with_eidasnode)
  * [2.1. Configuring communication with EidasNode](#integrate_eidasnode)
  * [2.2. Ignite configuration](#ignite_conf)
- [6. Monitoring](#heartbeat)
- [x. Appendix 1 - service configuration parameters](#configuration_parameters)  

<a name="build"></a>

## 1. Building the SpecificConnector webapp

````
./mvnw clean package
````

<a name="integrate_with_eidasnode"></a>
## 2. Integration with EidasNode webapp

In order to enable communication between `EidasNode` and `SpecificConnector` webapp's, both must be able to access the same `Ignite` cluster and have the same communication configuration (shared secret, etc).

**NB!** It is assumed, that the `SpecificConnector` webapp is installed in the same web server instance as `EidasNode` and that both have access to the same configuration files.

<a name="integrate_eidasnode"></a>
### 2.1 Configuring communication with EidasNode

To set the same communication definitions, it is required that the `SpecificConnector` has access to communication definitions provided in the following `EidasNode` configuration file:
`$SPECIFIC_CONNECTOR_CONFIG_REPOSITORY/specificCommunicationDefinitionConnector.xml`

<a name="ignite_conf"></a>
### 2.2 Ignite configuration

By default, it is assumed that `EidasNode` and `SpecificConnector` will share the same xml configuration file `$EIDAS_CONFIG_REPOSITORY/igniteSpecificCommunication.xml`. The configuration location can be overridden (see to [configuration parameters](#configuration_parameters_eidas) for further details).

The `SpecificConnector` webapp starts Ignite node in client mode using EidasNode webapp's Ignite configuration. The ignite client is started lazily (initialized on the first query).

Note that `SpecificConnector` requires access to four predefined maps in the cluster - see Table 1 for details.

| Map name        |  Description |
| :---------------- | :---------- |
| `specificNodeConnectorRequestCache` | Holds pending LightRequests from EidasNode webapp. |
| `nodeSpecificConnectorResponseCache` | Holds LightResponses for EidasNode webapp. |

Table 1 - Required shared map's in `SpecificConnector` webapp.

## 6. Monitoring

`SpecificConnector` webapp uses `Spring Boot Actuator` for monitoring. To customize Monitoring, Metrics, Auditing, and more see [Spring Boot Actuator documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready).    

### 6.1 Disable all monitoring endpoints configuration

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `management.endpoints.jmx.exposure.exclude` | No | Endpoint IDs that should be excluded to be exposed over JMX or `*` for all. Recommended value `*` |
| `management.endpoints.web.exposure.exclude` | No | Endpoint IDs that should be excluded to be exposed over HTTP or `*` for all. Recommended value `*` |

### 6.2 Custom application health endpoint configuration

`SpecificConnector` webapp implements [custom health endpoint](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-endpoints-custom) with id `heartbeat` and [custom health indicators](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#writing-custom-healthindicators) with id's `igniteCluster`, `connectorMetadata`, `truststore`. This endpoint is disabled by default.

Request:

````
curl -X GET https://ee-eidas-connector:8084/SpecificConnector/heartbeat
````

Response:
````
{
    "currentTime": "2020-07-23T09:42:46.307Z",
    "upTime": "PT1M25S",
    "buildTime": "2020-07-23T08:35:57.257Z",
    "name": "ee-specific-connector",
    "startTime": "2020-07-01T09:41:33.411Z",
    "commitId": "7fb1482da3c091c361a7a9f4dbaf1e19817bc76f",
    "version": "1.0.0-SNAPSHOT",
    "commitBranch": "develop",
    "status": "UP",
    "dependencies": [        
        {
            "name": "igniteCluster",
            "status": "UP"
        },
        {
            "name": "connectorMetadata",
            "status": "UP"
        },
        {
            "name": "truststore",
            "status": "UP"
        }
    ]
}
````

#### 6.2.1 Minimal recommended configuration to enable only `heartbeat` endpoint:

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `management.endpoints.jmx.exposure.exclude` | No | Endpoint IDs that should be excluded to be exposed over JMX or `*` for all. Recommended value `*` |
| `management.endpoints.web.exposure.include` | No | Endpoint IDs that should be included to be exposed over HTTP or `*` for all. Recommended value `heartbeat` |
| `management.endpoints.web.base-path` | No |  Base path for Web endpoints. Relative to server.servlet.context-path or management.server.servlet.context-path if management.server.port is configured. Recommended value `/` |
| `management.health.defaults.enabled` | No | Whether to enable default Spring Boot Actuator health indicators. Recommended value `false` |
| `management.info.git.mode` | No | Mode to use to expose git information. Recommended value `full` |
| `eidas.connector.health.dependencies.connect-timeout` | No | Timeout for `connectorMetadata` health indicators. Defaults to `3s` |
| `eidas.connector.health.trust-store-expiration-warning` | No | Certificate expiration warning period for `truststore` health indicator. Default value `30d` |


- [x. Appendix 1 - service configuration parameters](#configuration_parameters) 
  * [x.2 Integration with the EidasNode webapp](#configuration_parameters_eidas)