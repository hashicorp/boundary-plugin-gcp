// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package credential

const (
	// ConstProjectId defines the attribute name for a GCP project
	ConstProjectId = "project_id"

	// ConstZone defines the attribute name for a GCP zone
	ConstZone = "zone"

	// ConstDisableCredentialRotation is the key for the disable credential rotation in the GCP credentials.
	ConstDisableCredentialRotation = "disable_credential_rotation"

	// ConstCredsLastRotatedTime is the key for the last rotated time in the GCP credentials.
	ConstCredsLastRotatedTime = "creds_last_rotated_time"

	// ConstClientEmail is the email address associated with the service account
	ConstClientEmail = "client_email"

	// ConstTargetServiceAccountID is the unique identifier for the service account that will be impersonated.
	ConstTargetServiceAccountID = "target_service_account_id"

	// ConstPrivateKeyId is the private key id associated with the service account
	ConstPrivateKeyId = "private_key_id"

	// ConstPrivateKey is the private key associated with the service account
	ConstPrivateKey = "private_key"
)
