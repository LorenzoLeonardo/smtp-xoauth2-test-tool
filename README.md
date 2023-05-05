# smtp-xoauth2-test-tool
This is a test tool for SMTP XOAUTH2 email workflow

How to use this tool

cargo run \<provider\> \<access token grant type\> \<client id\> \<client secret\> \<sender email address\> \<sender name\> \<recipient email\> \<recipient name\> \<debug log level\>

Notes:

The \<provider\> can be of the following:
- Microsoft
- Google

The \<client secret\> can be of the following:
- None (If there is no client secret)
- Client Secret string (If there is a client secret)

The \<access token grant type\> can be of the following:
- AuthorizationCodeGrant
- DeviceCodeFlow

The \<debug log level\> can be of the following:
- error
- warn
- info
- debug
- trace

Just look in the logs for the login link.
