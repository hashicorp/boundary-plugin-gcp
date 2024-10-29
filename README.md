# GCP Plugin for HashiCorp Boundary

This repo contains the GCP plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/).

## Credentials

### Service Account Credentials

The plugin will authenticate using service account credential when the `secrets` 
object is set. By default, the plugin will attempt to rotate the credentials. 
The given credentials will be used to create a new credential, and then the given 
credential will be revoked. In this way, after rotation, only Boundary knows the 
client secret in use by this plugin.

Credential rotation can be turned off by setting the `disable_credential_rotation` 
attribute to true.

### Service Account Impersonation

The plugin will attempt to impersonate a service account when the `target_service_account_id`
field is supplied through the `attributes` object. The base service account will be
used to assume the identity and permissions of the target service account. A temporary 
credential will be generated for authentication. The base service account requires the 
[service account token creator](https://cloud.google.com/iam/docs/service-account-permissions#token-creator-role) 
role to assume the role of the target service account.

By default, the credentials of the base service account will be rotated if  
credential rotation is not disabled by setting the `disable_credential_rotation` 
attribute.

### Application Default Credentials

The plugin uses [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/provide-credentials-adc) 
for authentication when no `secrets` object is set. The plugin will attempt to 
retrieve the credentials based on the environment.

## Dynamic Hosts

This plugin supports dynamically sourcing instances from GCP Google Compute Engine.

Host sets created with this plugin define filters
which select and group like instances within GCP; these host sets can in turn be
added to targets within Boundary as host sources.

At creation, update or deletion of a host catalog of this type, configuration of the
plugin is performed via the attribute/secret values passed to the create, update, or
delete calls actions. The values passed in to the plugin here are the attributes set
on a host catalog in Boundary.

The plugin fetches hosts through the [Instances.List](https://cloud.google.com/compute/docs/reference/rest/v1/instances/list#filter) 
call.

[Getting Started](plugin/service/host/README.md)