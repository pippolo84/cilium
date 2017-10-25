// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
)

const (
	mapName = "tunnel_endpoint_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536
)

var (
	mapInstance = bpf.NewMap(mapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(tunnelEndpoint{})),
		int(unsafe.Sizeof(tunnelEndpoint{})),
		MaxEntries, 0)
)

func init() {
	mapInstance.NonPersistent = true
	bpf.OpenAfterMount(mapInstance)
}

type tunnelEndpoint struct {
	bpf.EndpointKey
}

func newTunnelEndpoint(ip net.IP) tunnelEndpoint {
	return tunnelEndpoint{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func (v tunnelEndpoint) NewValue() bpf.MapValue { return &tunnelEndpoint{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func SetTunnelEndpoint(prefix net.IP, endpoint net.IP) error {
	key, val := newTunnelEndpoint(prefix), newTunnelEndpoint(endpoint)
	return mapInstance.Update(key, val)
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func DeleteTunnelEndpoint(prefix net.IP) error {
	return mapInstance.Delete(newTunnelEndpoint(prefix))
}

func dumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := tunnelEndpoint{}, tunnelEndpoint{}

	if err := binary.Read(bytes.NewBuffer(key), byteorder.Native, &k); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s", err)
	}

	if err := binary.Read(bytes.NewBuffer(value), byteorder.Native, &v); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert value: %s", err)
	}

	return k, v, nil
}

func dumpCallback(key bpf.MapKey, value bpf.MapValue) {
	k, v := key.(tunnelEndpoint), value.(tunnelEndpoint)
	fmt.Printf("%-20s %s\n", k, v)
}

// DumpMap prints the content of the tunnel endpoint map to stdout
func DumpMap(callback bpf.DumpCallback) error {
	if callback == nil {
		return mapInstance.Dump(dumpParser, dumpCallback)
	}
	return mapInstance.Dump(dumpParser, callback)
}
