## Signing service provider metadata mock responses

This directory contains mock service provider metadata responses. These responses are signed using XML-DSig, which means
any changes to the responses will invalidate the existing signature. You can use utility script 
`src/test/java/ee/ria/eidas/connector/specific/SignServiceProviderMetadata.java` to resign the responses. 
The script has a list of mock response files that it will update. You might have to modify it to include the specific
response files you want to resign. 
