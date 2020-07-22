# EE specific eIDAS connector service

- [1. Building the SpecificConnector webapp](#build)
- [2. Integration with EidasNode webapp](#integrate_with_eidasnode)
  * [2.1. Configuring communication with EidasNode](#integrate_eidasnode)
  * [2.2. Ignite configuration](#ignite_conf)

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

- [x. Appendix 1 - service configuration parameters](#configuration_parameters) 
  * [x.2 Integration with the EidasNode webapp](#configuration_parameters_eidas)