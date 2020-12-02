# EE specific eIDAS connector service

- [1. Building the SpecificConnector webapp](#build)
- [2. Integration with EidasNode webapp](#integrate_with_eidasnode)
  * [2.1. Configuring communication with EidasNode](#integrate_eidasnode)
  * [2.2. Ignite configuration](#ignite_conf)
- [3. Metadata generation](#metdata_generation)
- [4. Service provider integration](#service_providers)  
- [5. Logging](#logging)
  * [5.1. Log configuration](#log_conf)
  * [5.2. Log file and format](#log_file)
- [6. Monitoring](#heartbeat)
- [7. Security](#security)

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

It is required that the `SpecificConnector` has access to communication definitions provided in the following `EidasNode` configuration files:
`$EIDAS_CONFIG_REPOSITORY/eidas.xml`,
`$SPECIFIC_CONNECTOR_CONFIG_REPOSITORY/specificCommunicationDefinitionConnector.xml`

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `eidas.connector.specific-connector-request-url` | Yes | The URL in the `EidasNode` webapp, that accepts the lighttoken that references the member state specific authentication request. Example value: https://eidas-specificconnector:8443/EidasNode/SpecificConnectorRequest|

<a name="ignite_conf"></a>
### 2.2 Ignite configuration

It is required that `EidasNode` and `SpecificConnector` will share the same xml configuration file: `$EIDAS_CONFIG_REPOSITORY/igniteSpecificCommunication.xml`

The `SpecificConnector` webapp starts Ignite node in client mode using EidasNode webapp's Ignite configuration. The ignite client is started lazily (initialized on the first query).

Note that `SpecificConnector` requires access to four predefined maps in the cluster - see Table 1 for details.

| Map name        |  Description |
| :---------------- | :---------- |
| `specificNodeConnectorRequestCache` | Holds pending LightRequests from EidasNode webapp. |
| `nodeSpecificConnectorResponseCache` | Holds LightResponses for EidasNode webapp. |
| `specificMSSpRequestCorrelationMap` | Service provider request correlation map |

Table 1 - Shared map's used in `SpecificConnector` webapp.

An example of a configuration file is provided [here](src/test/resources/mock_eidasnode/igniteSpecificCommunication.xml).

<a name="metdata_generation"></a>
## 3. Metadata generation

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `eidas.connector.responder-metadata.key-store` | Yes | Path to key store. Example: file:/etc/eidasconf/keystore/responder-metadata-keystore.p12 |
| `eidas.connector.responder-metadata.key-store-password` | Yes | Key store password |
| `eidas.connector.responder-metadata.key-store-type` | No | Key store type. Default value: PKCS12 |
| `eidas.connector.responder-metadata.key-alias` | Yes | Key alias in key store |
| `eidas.connector.responder-metadata.key-password` | Yes | Key password in key store |
| `eidas.connector.responder-metadata.trust-store` | Yes | Path to key store. Example: file:/etc/eidasconf/keystore/responder-metadata-truststore.p12 |
| `eidas.connector.responder-metadata.trust-store-password` | Yes | Trust store password |
| `eidas.connector.responder-metadata.trust-store-type` | No | Trust store type. Default value: PKCS12 |
| `eidas.connector.responder-metadata.signature-algorithm` | No | Signature algorithm used to sign published metadata, SAML response objects and assertions (defined by RFC 4051). Default value: http://www.w3.org/2001/04/xmldsig-more#rsa-sha512 |
| `eidas.connector.responder-metadata.key-transport-algorithm` | No | Key transport algorithm used in SAML response assertions encryption. Default value: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p |
| `eidas.connector.responder-metadata.encryption-algorithm` | No | Algorithm used in SAML response assertions encryption. Default value: http://www.w3.org/2009/xmlenc11#aes256-gcm |
| `eidas.connector.responder-metadata.path` | No | Metadata endpoint path. https://eidas-specificconnector:8443/SpecificConnector/{eidas.connector.responder-metadata.path}. Default value: `ConnectorResponderMetadata` |
| `eidas.connector.responder-metadata.entity-id` | Yes | Exact HTTPS URL where metadata is published. Examlpe: https://eidas-specificconnector:8443/SpecificConnector/ConnectorResponderMetadata |
| `eidas.connector.responder-metadata.sso-service-url` | Yes | Exact HTTPS URL where authentication endpoint for service providers is located. Example: https://eidas-specificconnector:8443/SpecificConnector/ServiceProvider |
| `eidas.connector.responder-metadata.name-id-format` | No | Possible values: `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`,`urn:oasis:names:tc:SAML:2.0:nameid-format:transient`,`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| `eidas.connector.responder-metadata.sp-type` | No | Public or private sector service provider. Possible values: `public`, `private` |
| `eidas.connector.responder-metadata.validity-interval` | No | Metadata validity duration. [Defined as standard ISO-8601 format used by java.time.Duration](https://docs.spring.io/spring-boot/docs/current/reference/html/spring-boot-features.html#boot-features-external-config-conversion-duration) Default value: 1d |
| `eidas.connector.responder-metadata.assertion-validity-interval` | No | Authentication response assertion validity duration. [Defined as standard ISO-8601 format used by java.time.Duration](https://docs.spring.io/spring-boot/docs/current/reference/html/spring-boot-features.html#boot-features-external-config-conversion-duration) Default value: 5m |
| `eidas.connector.responder-metadata.supported-member-states` | Yes | Supported member states for authentication (defined by ISO 3166-1 alpha-2) |
| `eidas.connector.responder-metadata.supported-bindings` | No | Possible values: `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`, `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`. Default value:`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST,urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect` |
| `eidas.connector.responder-metadata.digest-methods` | No | Supported digest methods. Default value: `http://www.w3.org/2001/04/xmlenc#sha256,http://www.w3.org/2001/04/xmlenc#sha512` |
| `eidas.connector.responder-metadata.signing-methods[X].name` | Yes | Supported signing algorithm name (defined by RFC 4051) |
| `eidas.connector.responder-metadata.signing-methods[X].minKeySize` | Yes | Minimum key size |
| `eidas.connector.responder-metadata.signing-methods[X].maxKeySize` | Yes | Maximum key size |
| `eidas.connector.responder-metadata.supported-attributes[X].name` | Yes | Supported eIDAS attribute name (defined by [eIDAS SAML Attribute Profile v1.2, paragraphs 2.2 and 2.3](https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eIDAS+eID+Profile?preview=/82773108/148898847/eIDAS%20SAML%20Attribute%20Profile%20v1.2%20Final.pdf) |
| `eidas.connector.responder-metadata.supported-attributes[X].friendly-name` | Yes | Supported eIDAS attribute friendly name (defined by [eIDAS SAML Attribute Profile v1.2, paragraphs 2.2 and 2.3](https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eIDAS+eID+Profile?preview=/82773108/148898847/eIDAS%20SAML%20Attribute%20Profile%20v1.2%20Final.pdf) |
| `eidas.connector.responder-metadata.organization.name` | Yes | Organization name published in metadata |
| `eidas.connector.responder-metadata.organization.display-name` | Yes | Organization display name published in metadata |
| `eidas.connector.responder-metadata.organization.url` | Yes | Organization homepage published in metadata |
| `eidas.connector.responder-metadata.contacts[X].surname` | Yes | Contact surname published in metadata |
| `eidas.connector.responder-metadata.contacts[X].given-name` | Yes | Contact given name published in metadata |
| `eidas.connector.responder-metadata.contacts[X].company` | Yes | Contact company published in metadata |
| `eidas.connector.responder-metadata.contacts[X].phone` | Yes | Contact phone published in metadata |
| `eidas.connector.responder-metadata.contacts[X].email` | Yes | Contact email published in metadata |
| `eidas.connector.responder-metadata.contacts[X].type` | Yes | Contact type. Possible values: `technical`,`support`,`administrative`,`billing`,`other`

* Where X is index starting from zero and incremented for each new signing method, contact, supported attribute.

| Default values        |
| :---------------- |
| `eidas.connector.responder-metadata.path=ConnectorResponderMetadata` |
| `eidas.connector.responder-metadata.sp-type=public` |
| `eidas.connector.responder-metadata.validity-in-days=1` |
| `eidas.connector.responder-metadata.key-store-type=PKCS12` |
| `eidas.connector.responder-metadata.trust-store-type=PKCS12` |
| `eidas.connector.responder-metadata.digest-methods=http://www.w3.org/2001/04/xmlenc#sha256,http://www.w3.org/2001/04/xmlenc#sha512` |
| `eidas.connector.responder-metadata.signing-methods[0].name=http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512` |
| `eidas.connector.responder-metadata.signing-methods[0].minKeySize=384` |
| `eidas.connector.responder-metadata.signing-methods[0].maxKeySize=384` |
| `eidas.connector.responder-metadata.signing-methods[1].name=http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` |
| `eidas.connector.responder-metadata.signing-methods[1].minKeySize=384` |
| `eidas.connector.responder-metadata.signing-methods[1].maxKeySize=384` |
| `eidas.connector.responder-metadata.signing-methods[2].name=http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1` |
| `eidas.connector.responder-metadata.signing-methods[2].minKeySize=4096` |
| `eidas.connector.responder-metadata.signing-methods[2].maxKeySize=4096` |
| `eidas.connector.responder-metadata.supported-bindings=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST,urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect` |
| `eidas.connector.responder-metadata.supported-attributes[0]name=http://eidas.europa.eu/attributes/naturalperson/BirthName` |
| `eidas.connector.responder-metadata.supported-attributes[0]friendlyName=BirthName` |
| `eidas.connector.responder-metadata.supported-attributes[1]name=http://eidas.europa.eu/attributes/naturalperson/CurrentAddress` |
| `eidas.connector.responder-metadata.supported-attributes[1]friendlyName=CurrentAddress` |
| `eidas.connector.responder-metadata.supported-attributes[2]name=http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName` |
| `eidas.connector.responder-metadata.supported-attributes[2]friendlyName=FamilyName` |
| `eidas.connector.responder-metadata.supported-attributes[3]name=http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName` |
| `eidas.connector.responder-metadata.supported-attributes[3]friendlyName=FirstName` |
| `eidas.connector.responder-metadata.supported-attributes[4]name=http://eidas.europa.eu/attributes/naturalperson/DateOfBirth` |
| `eidas.connector.responder-metadata.supported-attributes[4]friendlyName=DateOfBirth` |
| `eidas.connector.responder-metadata.supported-attributes[5]name=http://eidas.europa.eu/attributes/naturalperson/Gender` |
| `eidas.connector.responder-metadata.supported-attributes[5]friendlyName=Gender` |
| `eidas.connector.responder-metadata.supported-attributes[6]name=http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[6]friendlyName=PersonIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[7]name=http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth` |
| `eidas.connector.responder-metadata.supported-attributes[7]friendlyName=PlaceOfBirth` |
| `eidas.connector.responder-metadata.supported-attributes[8]name=http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[8]friendlyName=D-2012-17-EUIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[9]name=http://eidas.europa.eu/attributes/legalperson/EORI` |
| `eidas.connector.responder-metadata.supported-attributes[9]friendlyName=EORI` |
| `eidas.connector.responder-metadata.supported-attributes[10]name=http://eidas.europa.eu/attributes/legalperson/LEI` |
| `eidas.connector.responder-metadata.supported-attributes[10]friendlyName=LEI` |
| `eidas.connector.responder-metadata.supported-attributes[11]name=http://eidas.europa.eu/attributes/legalperson/LegalName` |
| `eidas.connector.responder-metadata.supported-attributes[11]friendlyName=LegalName` |
| `eidas.connector.responder-metadata.supported-attributes[12]name=http://eidas.europa.eu/attributes/legalperson/LegalPersonAddress` |
| `eidas.connector.responder-metadata.supported-attributes[12]friendlyName=LegalAddress` |
| `eidas.connector.responder-metadata.supported-attributes[13]name=http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[13]friendlyName=LegalPersonIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[14]name=http://eidas.europa.eu/attributes/legalperson/SEED` |
| `eidas.connector.responder-metadata.supported-attributes[14]friendlyName=SEED` |
| `eidas.connector.responder-metadata.supported-attributes[15]name=http://eidas.europa.eu/attributes/legalperson/SIC` |
| `eidas.connector.responder-metadata.supported-attributes[15]friendlyName=SIC` |
| `eidas.connector.responder-metadata.supported-attributes[16]name=http://eidas.europa.eu/attributes/legalperson/TaxReference` |
| `eidas.connector.responder-metadata.supported-attributes[16]friendlyName=TaxReference` |
| `eidas.connector.responder-metadata.supported-attributes[17]name=http://eidas.europa.eu/attributes/legalperson/VATRegistrationNumber` |
| `eidas.connector.responder-metadata.supported-attributes[17]friendlyName=VATRegistration` |

Example metadata published by endpoint https://eidas-specificconnector:8443/SpecificConnector/ConnectorResponderMetadata

```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_nbkbamxofhndwguwkbskhwr0untehl1kyvypnpq" entityID="https://eidas-specificconnector:8443/SpecificConnector/ConnectorResponderMetadata" validUntil="2020-10-13T18:10:11.090Z">
   <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
         <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
         <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" />
         <ds:Reference URI="#_nbkbamxofhndwguwkbskhwr0untehl1kyvypnpq">
            <ds:Transforms>
               <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
               <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />
            <ds:DigestValue>2Z7PUIrB5sXVPt6TkHfX8J7WwDvM7OER0lBKo3vZpNQK3YaWR4ukjw7OFKzDqS6fB8QWTVt0tJcESP12GRXEPw==</ds:DigestValue>
         </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>Q8kTcdIugmGkosaq/7Z3HG9jiv9+mfNkOlErK0igXZXQfqABDXFg1BpMAM4ooxwe422982AB+tVO
jLYi+BikTzPFUKN3KBPN+Lr9rRAt107fuv9jGIAZzTrPr+f0UAPO61qhBs2n/YbjwMxgqgxxnisO
htwgueo5HpD3ciAiFRx+4dRLh++6caIKZdfO9Ko9cH8P1hcG4tvsj5VR4bfZwBH2gqU4XeDoKsQG
CIET5QIqdgRklDoyg4OJ0MinbYwHy6BFC3KEC34xDxE2qyXqAnRog8f5/BPRnlEonwvPM9A6xnTR
kYrzQf02gFfoEesHnZ9eZOkw2sTH/2rA/LfFH/QuPvvRVl3XITaYSRv8GH0JDxOy3eYUu+Aopcrr
l8SSLQUJS9xOyBLobaGHCPAAZX6miHKe0MRWM/UHHL5eXVAh+GkLRk9u/WolZUdz0sa0F8PIeaea
Z0GHBBRCfiCG5ImXa1sTCwSVv2a1oNY7SjzSM1XxNPtmIBDA8eE9wrTcZXYlAD/0LL4N0BOgjZ5B
g+jnoSrITvq3nBF522nn6dgQxYy4HOT3tb5c+slSAdDCnKWjNaKwJIPIfaCy+LR6P7oJuSHLaWkk
4Nu9BBoXUhnQWzO49QPotVJ7FMrr4n+4q9AbtFiH1PPsLkCokhUPm/uy/VPRMCGgiVcyx8ief40=</ds:SignatureValue>
      <ds:KeyInfo>
         <ds:X509Data>
            <ds:X509Certificate>MIIFmzCCA4OgAwIBAgIEX2eUsTANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJFRTENMAsGA1UE
CAwEdGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDEzMDEG
A1UEAwwqZWlkYXMtc3BlY2lmaWNjb25uZWN0b3ItcmVzcG9uZGVyLW1ldGFkYXRhMB4XDTIwMDky
MDE3NDMxM1oXDTMwMDkyMDE3NDMxM1owfjELMAkGA1UEBhMCRUUxDTALBgNVBAgMBHRlc3QxDTAL
BgNVBAcMBHRlc3QxDTALBgNVBAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxMzAxBgNVBAMMKmVpZGFz
LXNwZWNpZmljY29ubmVjdG9yLXJlc3BvbmRlci1tZXRhZGF0YTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBANP/gTFt+ToahE842QQQyDr1PPXAECy5GeZ7OcViVSoU239EG+edTGgdfvJn
p+Ek/kjL/vgG5X5uMIlvMcjssu7xuJZndyJUPrWQM6FGnEtJ1Qv+tKRvmD8ZDz4e/kFjPXr+9/W6
z4jt/TOGcVKwiB4luYD54GWGCoqoX55WCsJzYUVrMS4paHoftp/iUVRyQf4DSijtbvZl/Ypbmy6i
LNVOKhFbDaFw5j1DFmO6pOf41IFMxCANBUhq2PHignZjSx0eGP0675o/i9QbLyc59dVwnUhnPQvs
EQWyAiiS+61ZzDkAyIVTbQdx/RyQwLyFJh4QO00aocLpBud9FsYuSN1wLKuZSjbbM/ClbiIgs9F9
3tzijCLkEU9Tx62NhwExq4P5PY1O8cEl9BX4ema+aoyvYDd5eifvI7iTvHv621jxqT2LDvCQjlNA
OWelNOGsbZuCiQJjln3I1fscN6SB2cdxYebyVCQrfhsZZv7iawp8WCnw/wd/XVyise0lt0asTZWy
haOmTFv+nVIbHLcbiFzcEHoPfA31uQa4AOb6mTC9LIZDcelEKJIRiWuTv7hrBw5EAIUVhSdoGv9M
ReYq+vhMtT8lHg8m+IK0iEOfTRUs8x3YJYt2GH9+DC6onyhCm1WdEKuxYU5lPJVJgyg0ejxk0pmt
sjrHdAeEdbZF4wrPAgMBAAGjITAfMB0GA1UdDgQWBBSz7x9rg/0/MDKXc1gISohsoUXXHDANBgkq
hkiG9w0BAQsFAAOCAgEAVy6kdgxstQCsWvtq1PuNMnYanzveW1l/jrH8u80r/tBQ29yLjlvSj4e6
MQdA6EIKwFsKjmH2ZrdpqXyUdFjlfF2LYgpQamf7b8U6s+oFsX3IYRj73fDGJbvlE6gahv4Euadu
HrivtfHpgtNXdVF2ZrsrY6LbgiMPFZto938M0xmdxDxpGXp2Q2PXu0LGXXptidudikcvD09sciAP
7RBFPmxSQG2o+RgoJKAsvEQnEPCfSvhlK/SZR/iBmYyxXPhLCBpszFq91xXrD0h2w1KCXKIWTDb8
w2JuHs7P1PkcmrqSXXYHIf7dBNFKU6AuA/uKteqOO5i0hh7wL7gA56YDghbFGi+UHCft7TrWssso
GaQkM/YLaFApayHuqQ7J7F5hQvfkwBErPR6uIvFyHMjL5NtoFF2kzVTDx4j/uNzxHXk4XqDX3ZDw
6hiQmV7Tk7cJRUqU+q5TkYu4TgkBeE1quscVK7gsfFaWv7MBTIT4IBelEFtCU97cNzTqy6TTHnbo
aTqRc1cqN5cA6tebLp+cP0+pIsu6RM69eive+RJJBOMh7Dfd/EVp/EYPmc2AFiNVNMRnq4SVa1Ac
2nr1ewvm5yJAkefV8w7TNbQ/QKKpPZRfgCH5/5bWp6Q9T3T+6s0ydiIUJQ7fLMR8zEj50+UT/iuf
OF6TawGAOCgZSsptJbU=</ds:X509Certificate>
         </ds:X509Data>
      </ds:KeyInfo>
   </ds:Signature>
   <md:Extensions xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport">
      <eidas:SPType xmlns:eidas="http://eidas.europa.eu/saml-extensions">public</eidas:SPType>
      <ria:SupportedMemberStates xmlns:ria="http://eidas.europa.eu/saml-extensions">
         <ria:MemberState>CA</ria:MemberState>
         <ria:MemberState>DE</ria:MemberState>
      </ria:SupportedMemberStates>
      <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
      <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />
      <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" MaxKeySize="384" MinKeySize="384" />
      <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" MaxKeySize="384" MinKeySize="384" />
      <alg:SigningMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" MaxKeySize="4096" MinKeySize="4096" />
   </md:Extensions>
   <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
         <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
               <ds:X509Certificate>MIIFmzCCA4OgAwIBAgIEX2eUsTANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJFRTENMAsGA1UE
CAwEdGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDEzMDEG
A1UEAwwqZWlkYXMtc3BlY2lmaWNjb25uZWN0b3ItcmVzcG9uZGVyLW1ldGFkYXRhMB4XDTIwMDky
MDE3NDMxM1oXDTMwMDkyMDE3NDMxM1owfjELMAkGA1UEBhMCRUUxDTALBgNVBAgMBHRlc3QxDTAL
BgNVBAcMBHRlc3QxDTALBgNVBAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxMzAxBgNVBAMMKmVpZGFz
LXNwZWNpZmljY29ubmVjdG9yLXJlc3BvbmRlci1tZXRhZGF0YTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBANP/gTFt+ToahE842QQQyDr1PPXAECy5GeZ7OcViVSoU239EG+edTGgdfvJn
p+Ek/kjL/vgG5X5uMIlvMcjssu7xuJZndyJUPrWQM6FGnEtJ1Qv+tKRvmD8ZDz4e/kFjPXr+9/W6
z4jt/TOGcVKwiB4luYD54GWGCoqoX55WCsJzYUVrMS4paHoftp/iUVRyQf4DSijtbvZl/Ypbmy6i
LNVOKhFbDaFw5j1DFmO6pOf41IFMxCANBUhq2PHignZjSx0eGP0675o/i9QbLyc59dVwnUhnPQvs
EQWyAiiS+61ZzDkAyIVTbQdx/RyQwLyFJh4QO00aocLpBud9FsYuSN1wLKuZSjbbM/ClbiIgs9F9
3tzijCLkEU9Tx62NhwExq4P5PY1O8cEl9BX4ema+aoyvYDd5eifvI7iTvHv621jxqT2LDvCQjlNA
OWelNOGsbZuCiQJjln3I1fscN6SB2cdxYebyVCQrfhsZZv7iawp8WCnw/wd/XVyise0lt0asTZWy
haOmTFv+nVIbHLcbiFzcEHoPfA31uQa4AOb6mTC9LIZDcelEKJIRiWuTv7hrBw5EAIUVhSdoGv9M
ReYq+vhMtT8lHg8m+IK0iEOfTRUs8x3YJYt2GH9+DC6onyhCm1WdEKuxYU5lPJVJgyg0ejxk0pmt
sjrHdAeEdbZF4wrPAgMBAAGjITAfMB0GA1UdDgQWBBSz7x9rg/0/MDKXc1gISohsoUXXHDANBgkq
hkiG9w0BAQsFAAOCAgEAVy6kdgxstQCsWvtq1PuNMnYanzveW1l/jrH8u80r/tBQ29yLjlvSj4e6
MQdA6EIKwFsKjmH2ZrdpqXyUdFjlfF2LYgpQamf7b8U6s+oFsX3IYRj73fDGJbvlE6gahv4Euadu
HrivtfHpgtNXdVF2ZrsrY6LbgiMPFZto938M0xmdxDxpGXp2Q2PXu0LGXXptidudikcvD09sciAP
7RBFPmxSQG2o+RgoJKAsvEQnEPCfSvhlK/SZR/iBmYyxXPhLCBpszFq91xXrD0h2w1KCXKIWTDb8
w2JuHs7P1PkcmrqSXXYHIf7dBNFKU6AuA/uKteqOO5i0hh7wL7gA56YDghbFGi+UHCft7TrWssso
GaQkM/YLaFApayHuqQ7J7F5hQvfkwBErPR6uIvFyHMjL5NtoFF2kzVTDx4j/uNzxHXk4XqDX3ZDw
6hiQmV7Tk7cJRUqU+q5TkYu4TgkBeE1quscVK7gsfFaWv7MBTIT4IBelEFtCU97cNzTqy6TTHnbo
aTqRc1cqN5cA6tebLp+cP0+pIsu6RM69eive+RJJBOMh7Dfd/EVp/EYPmc2AFiNVNMRnq4SVa1Ac
2nr1ewvm5yJAkefV8w7TNbQ/QKKpPZRfgCH5/5bWp6Q9T3T+6s0ydiIUJQ7fLMR8zEj50+UT/iuf
OF6TawGAOCgZSsptJbU=</ds:X509Certificate>
            </ds:X509Data>
         </ds:KeyInfo>
      </md:KeyDescriptor>
      <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://eidas-specificconnector:8443/SpecificConnector/ServiceProvider" />
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://eidas-specificconnector:8443/SpecificConnector/ServiceProvider" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="BirthName" Name="http://eidas.europa.eu/attributes/naturalperson/BirthName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="CurrentAddress" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentAddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="FamilyName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="FirstName" Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="DateOfBirth" Name="http://eidas.europa.eu/attributes/naturalperson/DateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Gender" Name="http://eidas.europa.eu/attributes/naturalperson/Gender" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="PersonIdentifier" Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="PlaceOfBirth" Name="http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="D-2012-17-EUIdentifier" Name="http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="EORI" Name="http://eidas.europa.eu/attributes/legalperson/EORI" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="LEI" Name="http://eidas.europa.eu/attributes/legalperson/LEI" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="LegalName" Name="http://eidas.europa.eu/attributes/legalperson/LegalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="LegalAddress" Name="http://eidas.europa.eu/attributes/legalperson/LegalPersonAddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="LegalPersonIdentifier" Name="http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="SEED" Name="http://eidas.europa.eu/attributes/legalperson/SEED" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="SIC" Name="http://eidas.europa.eu/attributes/legalperson/SIC" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="TaxReference" Name="http://eidas.europa.eu/attributes/legalperson/TaxReference" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
      <saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="VATRegistration" Name="http://eidas.europa.eu/attributes/legalperson/VATRegistrationNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />
   </md:IDPSSODescriptor>
   <md:Organization>
      <md:OrganizationName xml:lang="en">Estonian Information System Authority</md:OrganizationName>
      <md:OrganizationDisplayName xml:lang="en">RIA</md:OrganizationDisplayName>
      <md:OrganizationURL xml:lang="en">https://www.ria.ee</md:OrganizationURL>
   </md:Organization>
   <md:ContactPerson contactType="support">
      <md:Company>RIA</md:Company>
      <md:GivenName>Desk</md:GivenName>
      <md:SurName>Help</md:SurName>
      <md:EmailAddress>help@ria.ee</md:EmailAddress>
      <md:TelephoneNumber>+372 663 0230</md:TelephoneNumber>
   </md:ContactPerson>
   <md:ContactPerson contactType="technical">
      <md:Company>RIA</md:Company>
      <md:GivenName>Desk</md:GivenName>
      <md:SurName>Help</md:SurName>
      <md:EmailAddress>help@ria.ee</md:EmailAddress>
      <md:TelephoneNumber>+372 663 0230</md:TelephoneNumber>
   </md:ContactPerson>
</md:EntityDescriptor>
```

<a name="service_providers"></a>
## 4. Service provider integration

To add new service provider, following properties must be set for each service provider:

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `eidas.connector.service-providers[X].id` | Yes | Id of service provider. Must be unique. |
| `eidas.connector.service-providers[X].entity-id` | Yes | `entityId` published in service provider metadata. It is a HTTPS URL pointing to the location of metadata. Must be unique. |
| `eidas.connector.service-providers[X].key-alias` | Yes | Certificate key alias in [responder truststore](). Must be unique. |
| `eidas.connector.service-providers[X].type` | Yes | Type of service provider. Possible values: `public`, `private` |

* Where X is index starting from zero and incremented for each new service provider.

Application periodically checks to see if the service provider metadata has changed. Each service provider can publish `validUntil` and `cacheDuration`
in its metadata to indicate how metadata should be updated.

The delay between each refresh interval is calculated as follows: 

If there is a problem connecting to service provider metadata, then `eidas.connector.service-provider-metadata-min-refresh-delay` is used as reconnection delay. If no `validUntil` and `cacheDuration` is present in the metadata, then the `eidas.connector.service-provider-metadata-max-refresh-delay` value is used. If that refresh interval is larger than the max refresh delay then `eidas.connector.service-provider-metadata-max-refresh-delay` is used. If its smaller than the min refresh delay then `eidas.connector.service-provider-metadata-min-refresh-delay` is used. Otherwise, the calculated refresh delay multiplied by `eidas.connector.service-provider-metadata-refresh-delay-factor` is used. By using this factor, the application will attempt to refresh before the cache actually expires, allowing a some room for error and recovery. Assuming the factor is not exceedingly close to 1.0 and a min refresh delay that is not overly large, this refresh will likely occur a few times before the cache expires.

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `eidas.connector.service-provider-metadata-min-refresh-delay` | No | Sets the minimum amount of time, in milliseconds, between refreshes. Default value: 60000 (60 seconds) |
| `eidas.connector.service-provider-metadata-max-refresh-delay` | No |  Refresh interval used when metadata does not contain any validUntil or cacheDuration information. Default value: 14400000 (4 hours) |
| `eidas.connector.service-provider-metadata-refresh-delay-factor` | No | Sets the delay factor used to compute the next refresh time. The delay must be between 0.0 and 1.0 exclusive. |
| `eidas.connector.add-saml-error-assertion` | No | Backwards compatibility option for eIDAS-Client to add encrypted assertion, when authentication fails. Default value: false |

<a name="logging"></a>
## 5. Logging

Logging in SpecificConnectorService is handled by [Logback framework](http://logback.qos.ch/documentation.html) through the [SLF4J facade](http://www.slf4j.org/).

<a name="log_conf"></a>
### 5.1 Log configuration

Logging can be configured by using an xml configuration file (logback-spring.xml). By default the SpecificConnectorService webapp uses an [example configuration](src/main/resources/logback-spring.xml) embedded in the service application, that logs into a file - `/var/log/SpecificConnector-yyyy-mm-dd.log` and rotates active file daily. Console logging is disabled by default.

Logging behavior can be customized in the following ways:

1. By overriding the specific parameter values in the default logback-spring.xml configuration file with environment variables (see table 5.1.1)

    Table 5.1.1 - properties in the default log confguration file

    | Parameter        | Mandatory | Description, example |
    | :---------------- | :---------- | :----------------|
    | `LOG_HOME` | No | Directory for log files. Defaults to `/var/log`, if not specified. |
    | `LOG_CONSOLE_LEVEL` | No | Level of detail for console logger. Valid values are: `OFF`, `FATAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`. Defaults to `OFF`, if not specified. |
    | `LOG_CONSOLE_PATTERN` | No | Log row pattern for console logs.  |
    | `LOG_FILE_LEVEL` | No | Level of detail for file logger. Valid values are: `OFF`, `FATAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`. Defaults to `INFO`, if not specified. |
    | `LOG_FILES_MAX_COUNT` | No | The number days rotated log files are kept locally. Defaults to `31`, if not specified. |    

2. Custom logging configuration file can be provided for more detailed logging control. Log file location can be specified by using the environment variable `LOGGING_CONFIG`, Java system property `logging.config` or property providing the property `logging.config` in the application.properties file.

   Example 1: overriding the default log conf with environment variable:
    
   ````
   LOGGING_CONFIG=/etc/eidas/config/logback.xml
   ````
   
   Example 2: overriding the default log conf with Java system property:
       
   ````
   -Dlogging.config=/etc/eidas/config/logback.xml
   ````      

   Example 3: overriding the default log conf in the application.properties:
    
   ````
   logging.config=file:/etc/eidas/config/logback.xml
   ````   

<a name="log_file"></a>
### 5.2 Log file and format
By default the SpecificConnectorService webapp uses an [example configuration](src/main/resources/logback-spring.xml) embedded in the service application, that logs into a file - `/var/log/SpecificConnector-yyyy-mm-dd.log`. 

JSON format is used for a log row. The JSON field set for a single log record follows the [ECS Field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html).  

The following log record fields are supported:

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `@timestamp` | Yes | Date/time when the event originated. |
| `log.level` | Yes | Original log level of the log event. Possible values: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE` |
| `log.logger` | Yes | The name of the logger inside an application. |
| `process.pid` | Yes | Process ID. |
| `process.thread.name` | Yes | Thread name. |
| `service.name` | Yes | Name of the service data is collected from. Constant value: `ee-eidas-connector`. |
| `service.type` | Yes | The type of the service data is collected from. Constant value: `specific`. |
| `service.node.name` | Yes | Unique name of a service node. This allows for two nodes of the same service running on the same host to be differentiated. |
| `service.version` | No | Version of the service. |
| `session.id` | No | Unique identifier of the session. Cookie based identifier that enables log correlation between `EidasNode` and `SpecificConnectorService` webapps. |
| `trace.id` | No | Unique identifier of the session. Groups multiple events like transactions that belong together. For example, a user request handled by multiple inter-connected services. |
| `transaction.id` | No | Unique identifier of the transaction. A transaction is the highest level of work measured within a service, such as a request to a server. |
| `message` | Yes | The log message. |
| `error.type` | No | The type of the error - the class name of the exception. |
| `error.stack_trace` | No | The stack trace of this error in plain text. |
| `event.kind` | No | [ECS Event Categorization Field](https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html) |
| `event.category` | No | [ECS Event Categorization Field](https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html) |
| `event.type` | No | The [ECS Event Categorization Field](https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-type.html) |
| `event.outcome` | No | [ECS Event Categorization Field](https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-outcome.html) |

Custom fields related to authentication

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `authn_request` | No | Fields related to SAML 2.0 AuthnRequest |
| `saml_response` | No | Fields related to SAML 2.0 SAML Response |

Example log message containing Autentication initialization event (authn_request):

```json
{
  "@timestamp": "2020-10-23T14:22:50.750Z",
  "log.level": "INFO",
  "log.logger": "e.r.e.c.s.c.ServiceProviderController",
  "process.pid": 1,
  "process.thread.name": "https-openssl-nio-8443-exec-7",
  "service.name": "ee-eidas-connector",
  "service.type": "specific",
  "service.node.name": "25848971-d261-4686-ac78-cbda659a6c9b",
  "service.version": "1.0.0-SNAPSHOT",
  "session.id": "35537975F280B3B9CDA37AFEC90177E2",
  "trace.id": "d28dac609b3fff64",
  "transaction.id": "d28dac609b3fff64",
  "message": "AuthnRequest received",
  "authn_request": {
    "AssertionConsumerServiceURL": "https://eidas-eeserviceprovider:8889/returnUrl",
    "Destination": "https://eidas-specificconnector:8443/SpecificConnector/ServiceProvider",
    "ForceAuthn": "true",
    "ID": "_19e7fe372ac0f1c2c2600c36aa26411d",
    "IsPassive": "false",
    "IssueInstant": "2020-10-23T14:22:50.325Z",
    "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "ProviderName": "eidas-eeserviceprovider",
    "Version": "2.0",
    "Issuer": "https://eidas-eeserviceprovider:8889/metadata",
    "Signature": {
      "SignedInfo": {
        "CanonicalizationMethod": {
          "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
        },
        "SignatureMethod": {
          "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
        },
        "Reference": {
          "URI": "#_19e7fe372ac0f1c2c2600c36aa26411d",
          "Transforms": {
            "Transform": {
              "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
            }
          },
          "DigestMethod": {
            "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha512"
          },
          "DigestValue": "07/aMjC0XXGXd0au+50fvBhu1jOF53Aw6Wv9AaY0zYpV1w7lrGPL2169YYun1ns7BEHL99ecmJzW\r\naA82zhyTIA=="
        }
      },
      "SignatureValue": "\nOPxK3sDj2tnbYDn6cPxO0JvDen/MTd9s1wzVgx+lxfvIBlRE6Nb3iY6xNZ0M5KnW2XVr3brxT8Jj\r\n/4JCjSr8ZQ==\n",
      "KeyInfo": {
        "X509Data": {
          "X509Certificate": "MIIB8zCCAZmgAwIBAgIEX2d0kTAKBggqhkjOPQQDAjBwMQswCQYDVQQGEwJFRTENMAsGA1UECAwE\ndGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDElMCMGA1UE\nAwwcZWlkYXMtZWVzZXJ2aWNlcHJvdmlkZXItc2lnbjAeFw0yMDA5MjAxNTI2MDlaFw0zMDA5MjAx\nNTI2MDlaMHAxCzAJBgNVBAYTAkVFMQ0wCwYDVQQIDAR0ZXN0MQ0wCwYDVQQHDAR0ZXN0MQ0wCwYD\nVQQKDAR0ZXN0MQ0wCwYDVQQLDAR0ZXN0MSUwIwYDVQQDDBxlaWRhcy1lZXNlcnZpY2Vwcm92aWRl\nci1zaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESgy4lzSY6vB2Ib1EhydCW+jcfnyVeUmc\nWgFVcAOGyMmhUmk6TnBELevewzntc8X1QHQuLdwIh1a4ZXH3s0aY/6MhMB8wHQYDVR0OBBYEFIXa\nAerTmJkYtRDGTUFcjUVyZKBPMAoGCCqGSM49BAMCA0gAMEUCIQCdcQ6jbf20NXI+o+MdPio4xQeH\nONDcFT9alMGzNpqWyQIgGsm8We8T5QGE+e4g8KDE85ucxpDR2iLGiqnr8k5k5Vs="
        }
      }
    },
    "Extensions": {
      "SPType": "public",
      "RequestedAttributes": {
        "RequestedAttribute": {
          "FriendlyName": "PersonIdentifier",
          "Name": "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
          "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
          "isRequired": "true"
        }
      }
    },
    "NameIDPolicy": {
      "AllowCreate": "true",
      "Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    },
    "RequestedAuthnContext": {
      "Comparison": "minimum",
      "AuthnContextClassRef": "http://eidas.europa.eu/LoA/high"
    }
  },
  "authn_request.country": "CA",
  "authn_request.relay_state": "12345",
  "event.kind": "event",
  "event.category": "authentication",
  "event.type": "start"
}
```

Example log message containing successful Autentication end event (saml_response):

```json
{
  "@timestamp": "2020-10-23T14:23:03.221Z",
  "log.level": "INFO",
  "log.logger": "e.r.e.c.s.c.ConnectorResponseController",
  "process.pid": 1,
  "process.thread.name": "https-openssl-nio-8443-exec-5",
  "service.name": "ee-eidas-connector",
  "service.type": "specific",
  "service.node.name": "25848971-d261-4686-ac78-cbda659a6c9b",
  "service.version": "1.0.0-SNAPSHOT",
  "session.id": "35537975F280B3B9CDA37AFEC90177E2",
  "trace.id": "4cf9d54b8ed39d83",
  "transaction.id": "4cf9d54b8ed39d83",
  "message": "SAML response created",
  "saml_response": {
    "Destination": "https://eidas-eeserviceprovider:8889/returnUrl",
    "ID": "_KlrvIqsRSR_lmeSP5ULVlGLTesFFb-OC0kUTs9-20E3WQPIkDsqQMAiuTEJM0-O",
    "InResponseTo": "_19e7fe372ac0f1c2c2600c36aa26411d",
    "IssueInstant": "2020-10-23T14:23:03.142Z",
    "Version": "2.0",
    "Issuer": {
      "Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
      "": "https://eidas-specificconnector:8443/SpecificConnector/ConnectorResponderMetadata"
    },
    "Signature": {
      "SignedInfo": {
        "CanonicalizationMethod": {
          "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
        },
        "SignatureMethod": {
          "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
        },
        "Reference": {
          "URI": "#_KlrvIqsRSR_lmeSP5ULVlGLTesFFb-OC0kUTs9-20E3WQPIkDsqQMAiuTEJM0-O",
          "Transforms": {
            "Transform": {
              "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
            }
          },
          "DigestMethod": {
            "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha512"
          },
          "DigestValue": "E6YDbMaZddP64Vw2y8bmMM21nwAH+aT4ke6X8A/FNJPeAmP3wecbLWZS74xxwqJ3zOwD7CWN09Ny\r\nrr+DVU2OUg=="
        }
      },
      "SignatureValue": "\nsVlOTiy+0QDCuK9eIXK8ZGQGFZg2m4br8cbfRs81HFiWyIrF5BALKC5ZmfaI5D3roMRl+bVxQKks\r\nKFTJwDs7a1pwVf8RvhupswzWtTJyo2Tc0FkBEJ+ZaLTfjOUiQQuTK/E10rzeTo0ewilrs4OdTfyr\r\n/kjchILHhfqwAMpE8wqxxFdboknlhFpWH61aOeeGk1pj/hnArtirATihmzbtxxyn6ZBBH4UDqpQP\r\nGe3Wy14RkY+KGXvv31kaPZ8E0Ogn0YYLqcb2hv8gjCDFx9q0P+pj33F8Dw90pEQAQlrXad//jrI/\r\neBoGCgxvYfzm+DjQmvpuZmsR2Q35ZWUBqH72gkyTG3+4NDmF9ibECq85L7TMkT2hdKWX/NbVGO+m\r\n5QRpB+sxu5oSNvMH2KNzDq0ASWtGWYVw+edaAV2O/Xa0/3DsCHI/nkg/A0UnLZZPahf+Pu0wZ337\r\n5DiCuLg9mmuk8Wy3WYn3FczSAPjyzbU/Wpdsj8X1u/xcsiGt7KUpR37hwRJS6VVcNEt025xzl3+E\r\n8MoF1e5bHQJQVif9YWMIcPVZZ9YVocIxaSiUtKmGQt5e2iLsIY7vJ7g1FFPTUHtoGcT30bM3e4ff\r\nvYXOyXCVjOn7LF7hfQCybN+esyk26eRp0WjL3Nxh6+OGWwIh5IhPz6A4JAmOXhsHfIthjK+o9mI=\n",
      "KeyInfo": {
        "X509Data": {
          "X509Certificate": "MIIFmzCCA4OgAwIBAgIEX2eUsTANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJFRTENMAsGA1UE\nCAwEdGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDEzMDEG\nA1UEAwwqZWlkYXMtc3BlY2lmaWNjb25uZWN0b3ItcmVzcG9uZGVyLW1ldGFkYXRhMB4XDTIwMDky\nMDE3NDMxM1oXDTMwMDkyMDE3NDMxM1owfjELMAkGA1UEBhMCRUUxDTALBgNVBAgMBHRlc3QxDTAL\nBgNVBAcMBHRlc3QxDTALBgNVBAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxMzAxBgNVBAMMKmVpZGFz\nLXNwZWNpZmljY29ubmVjdG9yLXJlc3BvbmRlci1tZXRhZGF0YTCCAiIwDQYJKoZIhvcNAQEBBQAD\nggIPADCCAgoCggIBANP/gTFt+ToahE842QQQyDr1PPXAECy5GeZ7OcViVSoU239EG+edTGgdfvJn\np+Ek/kjL/vgG5X5uMIlvMcjssu7xuJZndyJUPrWQM6FGnEtJ1Qv+tKRvmD8ZDz4e/kFjPXr+9/W6\nz4jt/TOGcVKwiB4luYD54GWGCoqoX55WCsJzYUVrMS4paHoftp/iUVRyQf4DSijtbvZl/Ypbmy6i\nLNVOKhFbDaFw5j1DFmO6pOf41IFMxCANBUhq2PHignZjSx0eGP0675o/i9QbLyc59dVwnUhnPQvs\nEQWyAiiS+61ZzDkAyIVTbQdx/RyQwLyFJh4QO00aocLpBud9FsYuSN1wLKuZSjbbM/ClbiIgs9F9\n3tzijCLkEU9Tx62NhwExq4P5PY1O8cEl9BX4ema+aoyvYDd5eifvI7iTvHv621jxqT2LDvCQjlNA\nOWelNOGsbZuCiQJjln3I1fscN6SB2cdxYebyVCQrfhsZZv7iawp8WCnw/wd/XVyise0lt0asTZWy\nhaOmTFv+nVIbHLcbiFzcEHoPfA31uQa4AOb6mTC9LIZDcelEKJIRiWuTv7hrBw5EAIUVhSdoGv9M\nReYq+vhMtT8lHg8m+IK0iEOfTRUs8x3YJYt2GH9+DC6onyhCm1WdEKuxYU5lPJVJgyg0ejxk0pmt\nsjrHdAeEdbZF4wrPAgMBAAGjITAfMB0GA1UdDgQWBBSz7x9rg/0/MDKXc1gISohsoUXXHDANBgkq\nhkiG9w0BAQsFAAOCAgEAVy6kdgxstQCsWvtq1PuNMnYanzveW1l/jrH8u80r/tBQ29yLjlvSj4e6\nMQdA6EIKwFsKjmH2ZrdpqXyUdFjlfF2LYgpQamf7b8U6s+oFsX3IYRj73fDGJbvlE6gahv4Euadu\nHrivtfHpgtNXdVF2ZrsrY6LbgiMPFZto938M0xmdxDxpGXp2Q2PXu0LGXXptidudikcvD09sciAP\n7RBFPmxSQG2o+RgoJKAsvEQnEPCfSvhlK/SZR/iBmYyxXPhLCBpszFq91xXrD0h2w1KCXKIWTDb8\nw2JuHs7P1PkcmrqSXXYHIf7dBNFKU6AuA/uKteqOO5i0hh7wL7gA56YDghbFGi+UHCft7TrWssso\nGaQkM/YLaFApayHuqQ7J7F5hQvfkwBErPR6uIvFyHMjL5NtoFF2kzVTDx4j/uNzxHXk4XqDX3ZDw\n6hiQmV7Tk7cJRUqU+q5TkYu4TgkBeE1quscVK7gsfFaWv7MBTIT4IBelEFtCU97cNzTqy6TTHnbo\naTqRc1cqN5cA6tebLp+cP0+pIsu6RM69eive+RJJBOMh7Dfd/EVp/EYPmc2AFiNVNMRnq4SVa1Ac\n2nr1ewvm5yJAkefV8w7TNbQ/QKKpPZRfgCH5/5bWp6Q9T3T+6s0ydiIUJQ7fLMR8zEj50+UT/iuf\nOF6TawGAOCgZSsptJbU="
        }
      }
    },
    "Status": {
      "StatusCode": {
        "Value": "urn:oasis:names:tc:SAML:2.0:status:Success"
      },
      "StatusMessage": "urn:oasis:names:tc:SAML:2.0:status:Success"
    },
    "EncryptedAssertion": {
      "EncryptedData": {
        "Id": "_3f4f5a72328705e98056f3c72c99ad53",
        "Type": "http://www.w3.org/2001/04/xmlenc#Element",
        "EncryptionMethod": {
          "Algorithm": "http://www.w3.org/2009/xmlenc11#aes256-gcm"
        },
        "KeyInfo": {
          "EncryptedKey": {
            "Id": "_fde6312a14823bf5cb2f95d7a2a72773",
            "EncryptionMethod": {
              "Algorithm": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
              "DigestMethod": {
                "Algorithm": "http://www.w3.org/2000/09/xmldsig#sha1"
              }
            },
            "KeyInfo": {
              "X509Data": {
                "X509Certificate": "MIIFhTCCA22gAwIBAgIEX2dz8zANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJFRTENMAsGA1UE\nCAwEdGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDEoMCYG\nA1UEAwwfZWlkYXMtZWVzZXJ2aWNlcHJvdmlkZXItZW5jcnlwdDAeFw0yMDA5MjAxNTIzMzFaFw0z\nMDA5MjAxNTIzMzFaMHMxCzAJBgNVBAYTAkVFMQ0wCwYDVQQIDAR0ZXN0MQ0wCwYDVQQHDAR0ZXN0\nMQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQLDAR0ZXN0MSgwJgYDVQQDDB9laWRhcy1lZXNlcnZpY2Vw\ncm92aWRlci1lbmNyeXB0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy7CmpMU9eoP8\neOsxtc3IAK/c9GFat4nCNJyv9e1QXJc8GCla3QdrNcnRDPx2Yvf0cMm1OMlnSfmCfzSh5joglJY1\nBJTKDa8m5JYVZQE8w0aeNNs7ksAZBZ+dXDVN3Tak3qt1lvOYWjcV55BEpLeU6TDBCXpUXKpBDgym\nIeG7oAi+sco8yFd2XbZqHE6hQ3B7LGPvMhYtzitNm0RvYOPbc2ush6MoFTIsxFSf4V7mos5q0iyK\nRBrKWs6ldE0Hj/EZavC+h18gMIRGfccTbTlWvihRUG+dp5asQrMfkMcH1wwfZZBWVnv6Fc9JShUf\nYTPETXvyUpU/NgRFcdN6B7FFQkIqk476Ugvi6nZo6smWoY3XzetKe2ahnqZ1D5FoGa2vFj4a6EGH\nsie9v4BstB9nWZC5mrF/cSopQLSOeLc9V/1l5FwM6u4NhKkd3/0Gk9MYjlwTT/nlz/j/d6NctBMl\nx5EnGhDPxwJUf+Ca+XbI93z8/mFnhig9eroj10fNo4EY/x6agcat2PHxpTVUAbuX13q2olVE1l80\nPujTw6chItPQbzvUnxR4ynS0HYg6FgQym9g3IoweSOGMffOh0qbgmatFWerL2WShaQYn91cHlcT3\n1WPyLjXWynReRnaNPPmEHMMMcWqHJrB5NTthb5xIBLi7hOl+QlSGqmoTnqBFyz8CAwEAAaMhMB8w\nHQYDVR0OBBYEFF21oZNP2zq46biZrKJVF0fE1U7mMA0GCSqGSIb3DQEBCwUAA4ICAQA4ezcCHign\n/yQo16ldwsi40O7oeQekNsiUvEnI97LQ6wXWN/hor4jZguqu1xfBqMue9htbIVl/1ck2/e+rM7vF\neQNL9SevuZsHsCAPLw7wTgJFuShq9MQbnPt/o9+MKYLC8fJkljZcl4PdNRJFY5/nNIlGDWGho89C\nORohxbdppURQGv3QYQGjxXuqsCunVASlstpLpgVl8GPkRnvCQIdWr18dV0G0O8Tesv25WLrud5Np\nM9QclPvPMaSJ3vzkKYYlyVxrHC6JhFLobrSdCv7xZUeOytFU5zwJl+ZWv2SEFr+/g3ZCAYt8JhD4\nrBWeo3iqrSXTWIu2RPJXIgBPYfSayRT3zdSP9xcDmYct6vXbZMyf1ICyTWPUT/rc/9UbejGY0nNc\nRx6nDhLONzA8q0CukLc4jFMjamjTlzWqnWuLcKwfD76+X+Nq3CYjqBtcrJ64O3+v4HN6miDvE6fL\nsTvT7JtYvlnUFvNpMREB1NN3c+O9lS5z1eKYHJabMxXyQKJd13Md6tq9xnDxjKD1lz0DluGomZDL\nxzlEiE1vJeUD9Edgi091D3qsC3kLwuwPiULJor88R1D2hmE6BLC0YfQfB4IvQRcKsoKsl4WUVqZB\nYQMBRK/tmts8yreDLOKGlIThu9SkwLkC43r5xGgfKK/5shXzE1SKI2NiOCgtgqrOQQ=="
              }
            },
            "CipherData": {
              "CipherValue": "i65FqK7vkmN2kkMJNtKSg8C2c6fQIPUmIJYCMG/ZNfS6JWWgBI6f46jxbgZD9lLnoCdB5Cln0HsB\r\n3XF9rOTbLQfeR7wZt9rXN/oGdmVlmBBuxEIdXT/CrhKhfxL+QmKeF+EtYDvYvy7qZCBMIoWxjAEa\r\nFUQ/JHSRmd05JAUp5y4nYUpLGj2o7hJ+3bjuKKBHSqWHhn7W2rJkgSqnk056jy72wZYGbmR3lGd9\r\nbk7YpAiUkHUrwF+2cebXwf51H36MDTm1MW37aEnnLEoAp1RCKdCFhiJnfNIwwbPrhq1+/cCkGlPE\r\n0mmsJC6EJZIXKNyKbI7XOM/USC6EYc9P/RBQeASrd0RpJ6OZq5p2Y05z/77Vy3OkCLDSOEmDvkKV\r\nh5TpZgS0pitqhz5XWXTpsDRKs+9bVRYXGI/HasM3ul3REKaRWFfZcR+AbSzTn7BVgbX1JhCo0Dgn\r\nGvRtXDN48vjQpOCN31HcXtbWeylNB7gMXME17GPg687vCj3R+K+IftR5a0d1eKx61DY89PqyBsQE\r\nEv60XQKPibCxA4rVsGxPbDsiJyICc6p/mKyYxl27RmViz6Fm8akEeq3wT7tV8hBmx5QCtmBK37G0\r\nlJEiyUW36i0WVtS0kCM5w1/Cwn5xWqqPq+GYQLXxmgjaPDmmi/BbFJs75p6CE/F7D8dGoIAa3Fg="
            }
          }
        },
        "CipherData": {
          "CipherValue": "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"
        }
      }
    }
  },
  "authn_request.relay_state": "12345",
  "event.kind": "event",
  "event.category": "authentication",
  "event.type": "end",
  "event.outcome": "success"
}
```

Example log message containing failed Autentication end event (saml_response): 
```json
{
  "@timestamp": "2020-10-23T14:36:09.447Z",
  "log.level": "ERROR",
  "log.logger": "e.r.e.c.s.e.SpecificConnectorExceptionHandler",
  "process.pid": 1,
  "process.thread.name": "https-openssl-nio-8443-exec-6",
  "service.name": "ee-eidas-connector",
  "service.type": "specific",
  "service.node.name": "25848971-d261-4686-ac78-cbda659a6c9b",
  "service.version": "1.0.0-SNAPSHOT",
  "session.id": "597CF877D3E37F5E9840601D1A5E8D11",
  "trace.id": "c7f421136e5dfb9b",
  "transaction.id": "c7f421136e5dfb9b",
  "message": "Authentication failed: LoA is missing or invalid",
  "saml_response": {
    "Destination": "https://eidas-eeserviceprovider:8889/returnUrl",
    "ID": "_3f5c43c067a79b2512ae2d41a545befb",
    "InResponseTo": "_8c0384b4fbf8b3e58cd4637d7807aeb7",
    "IssueInstant": "2020-10-23T14:36:09.425Z",
    "Version": "2.0",
    "Issuer": {
      "Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
      "": "https://eidas-specificconnector:8443/SpecificConnector/ConnectorResponderMetadata"
    },
    "Signature": {
      "SignedInfo": {
        "CanonicalizationMethod": {
          "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
        },
        "SignatureMethod": {
          "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
        },
        "Reference": {
          "URI": "#_3f5c43c067a79b2512ae2d41a545befb",
          "Transforms": {
            "Transform": {
              "Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
            }
          },
          "DigestMethod": {
            "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha512"
          },
          "DigestValue": "xjP1cavpaoVsjTBt6bvlGI1u6l2juXQn7Yr7kSRm45Xe2xnjKNciFGvMxjDJlMExo3N0Geu6aVI9\r\nNiGyPzhSVw=="
        }
      },
      "SignatureValue": "\nezeIya/f3erx9a5SmyI1Nd4hnjf2hEkWH7NAgL8FJdsPcdArM9UaNTW9jcsRcMO8tkHU6UEyXwtK\r\nM6OwELnGtRnbCEECCJLPcj5OETAXsgqkBGoWJ92d5yqEvL5HbdJxYcRc1sUkiYiTT3CYCqZ60ubU\r\nG0DQva8agJnc7YzSbtnZJsh/GEuPuAEe81RRZhVNDfkBjKcBQcrLwVMDpU5lRyo+GckCT56DiGzt\r\n8Y9/b0VYOZIt+uZLLTXmmQ6bQtLkE+jGcNR3Jeh1gZ8bxHlAVYxWwX2fu239gQmRJXzGxrYrd2CP\r\nJhzCEqaofFUE8/W1DRmrpbaLZdjSkCG28DffIZTHFuSmENRmIS5K8eo6Q0eIz24N690gzHJqgMuS\r\niUAO7zQTzSPJJrPX8NCorageRcPftjYASgco7fal3X2w34tUd2vySnluGN+/PvtyyQUMdVkko6p5\r\nVSZRy/1RnIbAUeAmg+RRZzK5sCu0Jz2rAPWRaWcTdh1iXbCFkLVAFPcIXhNU8Z5BqZXki71j3VqS\r\n1C0KSAWn+yll2lT0uZ1ZnEcvm3hu9q900iQBvmCtlt7OE/3Ylx3HEfvlsB7ZfLOZ3JQMzpfq1Cyn\r\npFep+mzbgGLQwFMo2SXgbHQdAHd+RiP/20oLSUt2e9a0UoDVIyAcizyFJCP5Co7ZxejDtZZAiv0=\n",
      "KeyInfo": {
        "X509Data": {
          "X509Certificate": "MIIFmzCCA4OgAwIBAgIEX2eUsTANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJFRTENMAsGA1UE\nCAwEdGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDEzMDEG\nA1UEAwwqZWlkYXMtc3BlY2lmaWNjb25uZWN0b3ItcmVzcG9uZGVyLW1ldGFkYXRhMB4XDTIwMDky\nMDE3NDMxM1oXDTMwMDkyMDE3NDMxM1owfjELMAkGA1UEBhMCRUUxDTALBgNVBAgMBHRlc3QxDTAL\nBgNVBAcMBHRlc3QxDTALBgNVBAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxMzAxBgNVBAMMKmVpZGFz\nLXNwZWNpZmljY29ubmVjdG9yLXJlc3BvbmRlci1tZXRhZGF0YTCCAiIwDQYJKoZIhvcNAQEBBQAD\nggIPADCCAgoCggIBANP/gTFt+ToahE842QQQyDr1PPXAECy5GeZ7OcViVSoU239EG+edTGgdfvJn\np+Ek/kjL/vgG5X5uMIlvMcjssu7xuJZndyJUPrWQM6FGnEtJ1Qv+tKRvmD8ZDz4e/kFjPXr+9/W6\nz4jt/TOGcVKwiB4luYD54GWGCoqoX55WCsJzYUVrMS4paHoftp/iUVRyQf4DSijtbvZl/Ypbmy6i\nLNVOKhFbDaFw5j1DFmO6pOf41IFMxCANBUhq2PHignZjSx0eGP0675o/i9QbLyc59dVwnUhnPQvs\nEQWyAiiS+61ZzDkAyIVTbQdx/RyQwLyFJh4QO00aocLpBud9FsYuSN1wLKuZSjbbM/ClbiIgs9F9\n3tzijCLkEU9Tx62NhwExq4P5PY1O8cEl9BX4ema+aoyvYDd5eifvI7iTvHv621jxqT2LDvCQjlNA\nOWelNOGsbZuCiQJjln3I1fscN6SB2cdxYebyVCQrfhsZZv7iawp8WCnw/wd/XVyise0lt0asTZWy\nhaOmTFv+nVIbHLcbiFzcEHoPfA31uQa4AOb6mTC9LIZDcelEKJIRiWuTv7hrBw5EAIUVhSdoGv9M\nReYq+vhMtT8lHg8m+IK0iEOfTRUs8x3YJYt2GH9+DC6onyhCm1WdEKuxYU5lPJVJgyg0ejxk0pmt\nsjrHdAeEdbZF4wrPAgMBAAGjITAfMB0GA1UdDgQWBBSz7x9rg/0/MDKXc1gISohsoUXXHDANBgkq\nhkiG9w0BAQsFAAOCAgEAVy6kdgxstQCsWvtq1PuNMnYanzveW1l/jrH8u80r/tBQ29yLjlvSj4e6\nMQdA6EIKwFsKjmH2ZrdpqXyUdFjlfF2LYgpQamf7b8U6s+oFsX3IYRj73fDGJbvlE6gahv4Euadu\nHrivtfHpgtNXdVF2ZrsrY6LbgiMPFZto938M0xmdxDxpGXp2Q2PXu0LGXXptidudikcvD09sciAP\n7RBFPmxSQG2o+RgoJKAsvEQnEPCfSvhlK/SZR/iBmYyxXPhLCBpszFq91xXrD0h2w1KCXKIWTDb8\nw2JuHs7P1PkcmrqSXXYHIf7dBNFKU6AuA/uKteqOO5i0hh7wL7gA56YDghbFGi+UHCft7TrWssso\nGaQkM/YLaFApayHuqQ7J7F5hQvfkwBErPR6uIvFyHMjL5NtoFF2kzVTDx4j/uNzxHXk4XqDX3ZDw\n6hiQmV7Tk7cJRUqU+q5TkYu4TgkBeE1quscVK7gsfFaWv7MBTIT4IBelEFtCU97cNzTqy6TTHnbo\naTqRc1cqN5cA6tebLp+cP0+pIsu6RM69eive+RJJBOMh7Dfd/EVp/EYPmc2AFiNVNMRnq4SVa1Ac\n2nr1ewvm5yJAkefV8w7TNbQ/QKKpPZRfgCH5/5bWp6Q9T3T+6s0ydiIUJQ7fLMR8zEj50+UT/iuf\nOF6TawGAOCgZSsptJbU="
        }
      }
    },
    "Status": {
      "StatusCode": {
        "Value": "urn:oasis:names:tc:SAML:2.0:status:Requester",
        "StatusCode": {
          "Value": "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
        }
      },
      "StatusMessage": "LoA is missing or invalid"
    }
  },
  "event.kind": "event",
  "event.category": "authentication",
  "event.type": "end",
  "event.outcome": "failure"
}
```
<a name="heartbeat"></a>
## 6. Monitoring

`SpecificConnector` webapp uses `Spring Boot Actuator` for monitoring. To customize Monitoring, Metrics, Auditing, and more see [Spring Boot Actuator documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready).

### 6.1 Disable all monitoring endpoints configuration

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `management.endpoints.jmx.exposure.exclude` | No | Endpoint IDs that should be excluded to be exposed over JMX or `*` for all. Recommended value `*` |
| `management.endpoints.web.exposure.exclude` | No | Endpoint IDs that should be excluded to be exposed over HTTP or `*` for all. Recommended value `*` |

### 6.2 Custom application health endpoint configuration

`SpecificConnector` webapp implements [custom health endpoint](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-endpoints-custom) with id `heartbeat` and [custom health indicators](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#writing-custom-healthindicators) with id's `igniteCluster`, `connectorMetadata`, `truststore`, `sp-%{service-provider-id}-metadata`. This endpoint is disabled by default.

Request:

````
curl -X GET https://ee-eidas-connector:8084/SpecificConnector/heartbeat
````

Response:
```json
{
  "currentTime": "2020-09-28T15:45:34.091Z",
  "upTime": "PT28M13S",
  "buildTime": "2020-09-28T14:53:39.502Z",
  "name": "ee-specific-connector",
  "startTime": "2020-09-28T15:17:37.850Z",
  "commitId": "dbdb7bfa1e48237b3f69fb1de9357f55a1e2df9d",
  "version": "1.0.0-SNAPSHOT",
  "commitBranch": "develop",
  "status": "UP",
  "dependencies": [
    {
      "name": "igniteCluster",
      "status": "UP"
    },
    {
      "name": "truststore",
      "status": "UP"
    },
    {
      "name": "sp-ca-metadata",
      "status": "UP"
    },
    {
      "name": "connectorMetadata",
      "status": "UP"
    }
  ]
}
```

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

<a name="security"></a>
## 7. Security

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `eidas.connector.content-security-policy` | No | HTTP Content security policy. Default value `block-all-mixed-content; default-src 'self'; object-src: 'none'; frame-ancestors 'none'; script-src 'self' 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='` |