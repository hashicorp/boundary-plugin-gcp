// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/googleapis/gax-go/v2"
	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"google.golang.org/api/option"
)

type testHTTPServer struct {
	server                *httptest.Server
	listInstancesResponse *computepb.InstanceList
	listInstancesError    error
}

func (s *testHTTPServer) start() *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp any
		if strings.Contains(r.URL.Path, "/compute/v1/projects") {
			if s.listInstancesError != nil {
				http.Error(w, "error listing instances: "+s.listInstancesError.Error(), http.StatusBadRequest)
				return
			}
			resp = s.listInstancesResponse
		}
		if resp == nil {
			http.Error(w, "unknown path: "+r.URL.Path, http.StatusNotFound)
			return
		}

		b, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, err = w.Write(b)
		if err != nil {
			http.Error(w, "unable to write response: "+err.Error(), http.StatusBadRequest)
			return
		}
	}))
	s.server = ts
	return ts
}

func pointer[T any](input T) *T {
	ret := input
	return &ret
}

type testMockInstancesState struct {
	ListInstancesCalled      bool
	ListInstancesInputParams *computepb.ListInstancesRequest
}

func (s *testMockInstancesState) Reset() {
	s.ListInstancesCalled = false
	s.ListInstancesInputParams = nil
}

type testMockInstances struct {
	InstancesAPI
	httpServer          *testHTTPServer
	State               *testMockInstancesState
	client              *compute.InstancesClient
	ListInstancesOutput *computepb.InstanceList
	ListInstancesError  error
}

type testMockInstancesOption func(m *testMockInstances) error

func testMockInstancesWithListInstancesOutput(o *computepb.InstanceList) testMockInstancesOption {
	return func(m *testMockInstances) error {
		m.ListInstancesOutput = o
		return nil
	}
}

func testMockInstancesWithListInstancesError(e error) testMockInstancesOption {
	return func(m *testMockInstances) error {
		m.ListInstancesError = e
		return nil
	}
}

func newTestMockInstances(ctx context.Context, state *testMockInstancesState, opts ...testMockInstancesOption) instancesAPIFunc {
	return func(cfgs ...*credential.Config) (InstancesAPI, error) {
		m := &testMockInstances{
			State: state,
		}

		for _, opt := range opts {
			if err := opt(m); err != nil {
				return nil, err
			}
		}

		m.httpServer = &testHTTPServer{
			listInstancesResponse: m.ListInstancesOutput,
			listInstancesError:    m.ListInstancesError,
		}
		m.httpServer.start()
		endpoint := m.httpServer.server.URL

		if m.client == nil {
			client, err := compute.NewInstancesRESTClient(ctx,
				option.WithoutAuthentication(),
				option.WithEndpoint(endpoint),
				option.WithTokenSource(nil),
			)
			if err != nil {
				return nil, err
			}
			m.client = client
		}

		return m, nil
	}
}

func (m *testMockInstances) List(ctx context.Context, input *computepb.ListInstancesRequest, opts ...gax.CallOption) *compute.InstanceIterator {
	if m.State != nil {
		m.State.ListInstancesCalled = true
		m.State.ListInstancesInputParams = input
	}

	return m.client.List(ctx, input)
}
