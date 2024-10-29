## Getting Started

Refer to [Attributes and Secrets](#attributes-and-secrets) for more detail on
configuration options for host catalogs and sets.

To create a host catalog (using default scope created by `boundary dev`):

```sh
boundary host-catalogs create plugin \
 -scope-id p_1234567890 \
 -name "Example Plugin-Based Host Catalog" \
 -description "Description for plugin-based host catalog" \
 -plugin-name gcp \
 -attr client_email=CLIENT_EMAIL \
 -attr project_id=PROJECT_ID \
 -attr zone=ZONE \
 -secret private_key_id='PRIVATE_KEY_ID' \
 -secret private_key='PRIVATE_KEY'
```

To create a host set, filtering the host set based on status value
of `RUNNING` and a label.

```sh
boundary host-sets create plugin \
 -host-catalog-id HOST_CATALOG_ID \
 -name "Example Plugin-Based Host Set" \
 -description "Description for plugin-based host set" \
 -attr filters=status=RUNNING
 -attr filters=labels.env:prod
```

## Required IAM Permissions

The following IAM permissions, at the very least, are required to be attached to
a configured service account for this provider:

### List Instances

To list instances, the credential requires these permissions:
```
[
    "compute.instances.list"
]
```

### Rotate Service Account Keys

When GCP service account keys are provided with credential rotation enabled, GCP 
service account keys will be rotated when requests are made to the plugin. These 
permissions are required to rotate the service account key:

```
[
    "iam.serviceAccountKeys.create",
    "iam.serviceAccountKeys.delete",
    "iam.serviceAccountKeys.disable",
    "iam.serviceAccountKeys.enable",
]
```

### Service Account Impersonation

For the base service account to authenticate by service account impersonation. 
The base service account needs to have these roles:

```
[
    "iam.serviceAccountTokenCreator"
]
```

## Attributes and Secrets

### Host Catalog

The following `attributes` are valid on a GCP host catalog resource:


- `zone` (string, required): The zone to configure the host catalog for. All host sets
  in this catalog will be configured for this zone.
- `project_id` (string, required): The project ID associated with the service account. All host sets
  in this catalog will be configured for this project.
- `disable_credential_rotation` (bool): If `true`, credential rotation will not
  be performed. See the [Credentials](../../../README.md#credentials) readme for more information.  
- `client_email` (string): The email address associated with the service account. The email address 
  used to uniquely identify the service account. It is required for authentication and authorization.
- `target_service_account_id` (string): The unique identifier for the service account that will be 
  impersonate. This is only required when authenticating with service account impersonation.

The following `secrets` are required on an GCP host catalog resource:

- `private_key_id` (string): The private key ID for the service account to use with this
  host catalog.
- `private_key` (string): The private key for the service account to use
  with this host catalog.

See the [Credentials](../../../README.md#credentials) readme for more information.

### Host Set

The following attributes are valid on a GCP host Set resource:

- `filters` (array of strings): Host Set filters are used to narrow down the list of hosts 
  returned by the plugin. The filter string is expected to be in the format "key operator value".
  The operator is expected to be one of =, !=, >, <, <=, >=, :, eq, ne.
  as per GCP API documentation:
  [instances.list reference](https://cloud.google.com/compute/docs/reference/rest/v1/instances/list#filter).