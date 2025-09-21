# smtp-xoauth2-test-tool

This is a test tool for the SMTP XOAUTH2 email workflow.  
It uses OpenID Connect to obtain the name and email of the  
authenticated user via OAuth2 and then sends a test SMTP email  
to a specified recipient.

The motivation for this project is to verify whether any  
breakages occur at the endpoints. Sometimes, providers make  
changes that introduce issues without notice. It’s better to  
detect these problems in advance rather than waiting for  
clients to call and complain.

<br>

## How to use this tool

#### $ cargo run \<provider\> \<access token grant type\> \<client id\> \<client secret\> \<recipient email\> \<recipient name\> \<debug log level\> \<HTTP client used\>

Notes:

### The \<provider\> can be of the following:
- Microsoft
- Google

### The \<client secret\> can be of the following:
- None (If there is no client secret)
- Client Secret string (If there is a client secret)

### The \<access token grant type\> can be of the following:
- AuthorizationCodeGrant
- DeviceCodeFlow

### The \<debug log level\> can be of the following
- error
- warn
- info
- debug
- trace

    If <debug log level> is not specified, the default level is info.

### The \<HTTP client used\> can be of the following
- Curl
- Reqwest

    If <HTTP client used> is not specified, the default HTTP client is reqwest.

Just look in the logs for the login link.
