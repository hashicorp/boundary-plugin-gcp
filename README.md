# Google Plugin for HashiCorp Boundary

This repo contains the google plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/).

> [!IMPORTANT]
> This is a prototype. Not officially supported by HashiCorp.

## Credentials

This plugin uses [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/provide-credentials-adc)
to authenticate to Google and retrieve a list of instances and instance groups.

As a result, it does not support rotation of the credentials since they are inferred
from the environment.

## Dynamic Hosts

This plugin supports dynamically sourcing instances from Google Compute Engine.

Host sets created with this plugin define filters or instance groups
which select and group like instances within Google; these host sets can in turn be
added to targets within Boundary as host sources.

At creation, update or deletion of a host catalog of this type, configuration of the
plugin is performed via the attribute/secret values passed to the create, update, or
delete calls actions. The values passed in to the plugin here are the attributes set
on on a host catalog in Boundary.

### Google IAM permissions

The plugin requires the following permissions:

- `compute.instances.get`
- `compute.instances.list`
- `compute.instanceGroups.get`
- `compute.instanceGroups.list`

### Attributes

### Host Catalog

The following attributes are valid on a Google host catalog resource:

- `project` (string): required. Project ID of the instances you want to add to host catalog.
- `zone` (string): required. Zone of the instances you want to add to host catalog.

Example:

```shell
$ boundary host-catalogs create plugin -scope-id p_1234567890 -plugin-name google -attr zone=us-central1-a -attr project=$GOOGLE_PROJECT
```

### Host Set

The following attributes are valid on a Google host set resource:

- `filter` (string): Google Cloud [filter expression](https://cloud.google.com/sdk/gcloud/reference/topic/filters)
  to filter instances.

- `instance_group` (string): Name of instance group to get a list of instances.

You can only set a `filter` or `instance_group` attribute, you cannot set both.

Example:

```shell
$ boundary host-sets create plugin -host-catalog-id $HOST_CATALOG_ID -name "filter-example" -description "example using filters" -attr filter="status=RUNNING"

$ boundary host-sets create plugin -host-catalog-id $HOST_CATALOG_ID -name "group-example" -description "example using instance groups" -attr instance_group="instance-group-name"
```

After generating the host set, create a target.

```shell
$ boundary targets create tcp -name google -description "Google Cloud" -scope-id p_1234567890 -default-port 22
$ boundary targets add-host-sources -id $TARGET_ID -host-source $HOST_SET_ID
```

## Setup

You will need to build your own Boundary binary, as Boundary imports the plugins as a dependency.

As a reference, you can review [this fork](https://github.com/joatmon08/boundary/tree/google-plugin) for changes.

To build the fork, go into the repository.

1. Run `make build`.
1. Authenticate to Google Cloud using `gcloud auth application-default login`.
1. Run Boundary with `./bin/boundary dev`.