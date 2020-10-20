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
| `eidas.connector.responder-metadata.validity-in-days` | No | Metadata validity in days. Default value: 1 |
| `eidas.connector.responder-metadata.supported-member-states` | Yes | Supported member states for authentication (defined by ISO 3166-1 alpha-2) |
| `eidas.connector.responder-metadata.supported-bindigs` | No | Possible values: `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`, `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`. Default value:`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST,urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect` |
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
| `eidas.connector.responder-metadata.supported-attributes[3]name=http://eidas.europa.eu/attributes/naturalperson/CurrentGivenNam ` |
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
| `eidas.connector.responder-metadata.supported-attributes[10]name=http://eidas.europa.eu/attributes/legalperson/LEI ` |
| `eidas.connector.responder-metadata.supported-attributes[10]friendlyName=LEI` |
| `eidas.connector.responder-metadata.supported-attributes[11]name=http://eidas.europa.eu/attributes/legalperson/LegalName` |
| `eidas.connector.responder-metadata.supported-attributes[11]friendlyName=LegalName` |
| `eidas.connector.responder-metadata.supported-attributes[12]name=http://eidas.europa.eu/attributes/legalperson/LegalPersonAddress` |
| `eidas.connector.responder-metadata.supported-attributes[12]friendlyName=LegalAddress` |
| `eidas.connector.responder-metadata.supported-attributes[13]name=http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[13]friendlyName=LegalPersonIdentifier` |
| `eidas.connector.responder-metadata.supported-attributes[14]name=http://eidas.europa.eu/attributes/legalperson/SEED` |
| `eidas.connector.responder-metadata.supported-attributes[14]friendlyName=SEED` |
| `eidas.connector.responder-metadata.supported-attributes[15]name=http://eidas.europa.eu/attributes/legalperson/SIC ` |
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
| `eidas.connector.service-provider-metadata-min-refresh-delay` | No | Sets the minimum amount of time, in milliseconds, between refreshes. |
| `eidas.connector.service-provider-metadata-max-refresh-delay` | No |  Refresh interval used when metadata does not contain any validUntil or cacheDuration information. Default value: 14400000 (4 hours) |
| `eidas.connector.service-provider-metadata-refresh-delay-factor` | No | Sets the delay factor used to compute the next refresh time. The delay must be between 0.0 and 1.0 exclusive. |

<a name="logging"></a>
## 5. Logging

Logging in SpecificConnectorService is handled by [Logback framework](http://logback.qos.ch/documentation.html) through the [SLF4J facade](http://www.slf4j.org/).

<a name="log_conf"></a>
### 5.1 Log configuration

Logging can be configured by using an xml configuration file (logback-spring.xml). By default the SpecificConnectorService webapp uses an [example configuration](src/main/resources/logback-spring.xml) embedded in the service application, that logs into a file - `/var/log/SpecificConnectorService-yyyy-mm-dd.log` and rotates active file daily. Console logging is disabled by default.

Logging behavior can be customized in the following ways:

1. By overriding the specific parameter values in the default logback-spring.xml configuration file with environment variables (see table 4.1.1)

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
By default the SpecificConnectorService webapp uses an [example configuration](src/main/resources/logback-spring.xml) embedded in the service application, that logs into a file - `/var/log/SpecificConnectorService-yyyy-mm-dd.log`. 

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

Example log message:

```json
{
	"@timestamp": "2020-06-26T17:38:09,388Z",
	"log.level": "INFO",
	"log.logger": "e.r.e.p.s.s.SpecificConnectorCommunication",
	"process.pid": 2447,
	"process.thread.name": "https-openssl-nio-8083-exec-4",
    "service.name": "ee-eidas-connector",
    "service.type": "specific",
	"service.node.name": "specificconnector-8ie7665",
    "session.id": "43CB9681C492423DFA5DBF892ABA693C",
	"trace.id": "49eb6edf9621cea5",
	"transaction.id": "49eb6edf9621cea5",
	"message": "Request with ID: 'e1b4f4a9-f59e-44b0-aa17-6acc76ad0412' received"
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
