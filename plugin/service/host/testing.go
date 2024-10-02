// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"cloud.google.com/go/compute/apiv1/computepb"
)

type testServer struct {
	server                *httptest.Server
	listInstancesResponse *computepb.InstanceList
	listInstancesError    error
}

func (s *testServer) start() *httptest.Server {
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

func (s *testServer) stop() {
	s.server.Close()
}

func pointer[T any](input T) *T {
	ret := input
	return &ret
}
