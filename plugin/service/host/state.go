// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"github.com/googleapis/gax-go/v2"
	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"
)

type InstancesAPI interface {
	List(ctx context.Context, req *computepb.ListInstancesRequest, opts ...gax.CallOption) *compute.InstanceIterator
}

type gcpCatalogPersistedState struct {
	// CredentialsConfig is the configuration for the GCP credentials
	*credential.PersistedState
}

type gcpCatalogPersistedStateOption func(s *gcpCatalogPersistedState) error

func withCredentials(x *credential.PersistedState) gcpCatalogPersistedStateOption {
	return func(s *gcpCatalogPersistedState) error {
		if s.PersistedState != nil {
			return errors.New("gcp credentials already set")
		}

		s.PersistedState = x
		return nil
	}
}

func newGCPCatalogPersistedState(opts ...gcpCatalogPersistedStateOption) (*gcpCatalogPersistedState, error) {
	s := new(gcpCatalogPersistedState)
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ToProto converts the state to HostCatalogPersisted proto message.
func (s *gcpCatalogPersistedState) toProto() (*pb.HostCatalogPersisted, error) {
	data, err := structpb.NewStruct(s.ToMap())
	if err != nil {
		return nil, fmt.Errorf("error converting state to structpb.Struct: %w", err)
	}
	return &pb.HostCatalogPersisted{Secrets: data}, nil
}

// InstancesClient returns a configured Instances client based on the session
// information stored in the state.
func (s *gcpCatalogPersistedState) InstancesClient(
	ctx context.Context,
	opts ...option.ClientOption,
) (InstancesAPI, error) {
	creds, err := s.CredentialsConfig.GenerateCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("error generation GCP credentials: %w", err)
	}
	if creds == nil {
		return nil, fmt.Errorf("nil gcp credentials")
	}
	clientOptions := []option.ClientOption{option.WithTokenSource(creds.TokenSource)}
	clientOptions = append(clientOptions, opts...)

	client, err := compute.NewInstancesRESTClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("error creating instances client: %w", err)
	}

	return client, nil
}
