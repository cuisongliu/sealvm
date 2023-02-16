// Copyright © 2022 cuisongliu@qq.com Ltd.
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

package v1

import (
	"github.com/labring/sealvm/pkg/utils/iputils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"strings"
)

const MultipassType = "Multipass"
const AliyunProvider = "AliyunProvider"

// VirtualMachineSpec defines the desired state of VirtualMachine
type VirtualMachineSpec struct {
	Hosts   []Host `json:"hosts,omitempty"`
	SSH     SSH    `json:"ssh"`
	Type    string `json:"provider,omitempty"`
	Proxy   string
	NoProxy string
}

type SSH struct {
	PublicFile string `json:"publicFile,omitempty"`
	PkFile     string `json:"pkFile,omitempty"`
	PkPasswd   string `json:"pkPasswd,omitempty"`
}

type Arch string

const (
	AMD64 Arch = "amd64"
	ARM64 Arch = "arm64"
)

type Host struct {
	Role   string            `json:"roles,omitempty"`
	Count  int               `json:"count,omitempty"`
	Arch   Arch              `json:"arch,omitempty"`
	Mounts map[string]string `json:"mounts,omitempty"`
	// key values resources.
	// cpu: 2
	// memory: 4
	// other resources like GPU
	Resources map[string]int `json:"resources,omitempty"`
	// ecs.t5-lc1m2.large
	Image        string `json:"image,omitempty"`
	InstanceType string `json:"instanceType,omitempty"`
}

func (h Host) GetRoleList() []string {
	return strings.Split(h.GetRoles(), ",")
}

func (c *Host) GetRoles() string {
	return c.Role
}

func (c *Host) GetClusterRole() string {
	roles := c.GetRoleList()
	if len(roles) >= 1 {
		return roles[0]
	}
	return NODE
}

func (h Host) String() string {
	data, _ := json.Marshal(&h)
	return string(data)
}

type Phase string

const (
	PhaseFailed    Phase = "Failed"
	PhaseSuccess   Phase = "Success"
	PhaseInProcess Phase = "InProcess"
)

// VirtualMachineStatus defines the observed state of VirtualMachine
type VirtualMachineStatus struct {
	Phase      Phase                      `json:"phase,omitempty"`
	Hosts      []VirtualMachineHostStatus `json:"hosts"`
	Conditions []Condition                `json:"conditions,omitempty" `
	Data       map[string]string          `json:"data,omitempty"`
}

type Condition struct {
	Type              string             `json:"type"`
	Status            v1.ConditionStatus `json:"status"`
	LastHeartbeatTime metav1.Time        `json:"lastHeartbeatTime,omitempty"`
	// +optional
	Reason string `json:"reason,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

const (
	Running = "Running"
)

type VirtualMachineHostStatus struct {
	State string `json:"state"`
	Role  string `json:"roles"`
	ID    string `json:"ID,omitempty"`
	Arch  Arch   `json:"arch,omitempty"`
	//当前主机的所有IP，可能包括公开或者私有的IP
	IPs          []string          `json:"IPs,omitempty"`
	ImageID      string            `json:"imageID,omitempty"`
	ImageName    string            `json:"imageName,omitempty"`
	InstanceType string            `json:"instanceType,omitempty"`
	Capacity     map[string]int    `json:"capacity"`
	Used         map[string]string `json:"used"`
	Mounts       map[string]string `json:"mounts,omitempty"`
	Index        int               `json:"index,omitempty"`
}

func (s *VirtualMachineHostStatus) Roles() []string {
	return strings.Split(s.Role, ",")
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualMachine is the Schema for the infra API
type VirtualMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualMachineSpec   `json:"spec,omitempty"`
	Status VirtualMachineStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualMachineList contains a list of VirtualMachine
type VirtualMachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMachine `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMachine{}, &VirtualMachineList{})
}

// Language: go

var (
	NODE   = "node"
	GOLANG = "golang"
	MASTER = "master"

	CPUKey  = "cpu"
	MEMKey  = "memory"
	DISKKey = "disk"
)

func (c *VirtualMachine) GetIPSByRole(role string) []string {
	var hosts []string
	for _, host := range c.Status.Hosts {
		if role == host.Role {
			hosts = append(hosts, host.IPs...)
		}
	}
	return hosts
}

func (c *VirtualMachine) GetHostByRole(role string) *Host {
	for _, host := range c.Spec.Hosts {
		if role == host.Role {
			return &host
		}
	}
	return nil
}

func (c *VirtualMachine) GetHostStatusByRoleIndex(role string, index int) *VirtualMachineHostStatus {
	for _, host := range c.Status.Hosts {
		if role == host.Role && index == host.Index {
			return &host
		}
	}
	return nil
}

func (c *VirtualMachine) GetSSH() SSH {
	return c.Spec.SSH
}

func (c *VirtualMachine) GetALLIPList() []string {
	return append(iputils.GetHostIPs(c.GetIPSByRole(NODE)), iputils.GetHostIPs(c.GetIPSByRole(GOLANG))...)
}

func In(key string, slice []string) bool {
	for _, s := range slice {
		if key == s {
			return true
		}
	}
	return false
}
