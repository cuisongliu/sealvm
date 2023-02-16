/*
Copyright 2021 cuisongliu@qq.com.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aliyun

import (
	v1 "github.com/labring/sealvm/types/api/v1"
	"time"
)

const (
	Scheme              = "https"
	Product             = "product"
	Role                = "role"
	Arch                = "arch"
	AliDomain           = "sealos.io/"
	TryTimes            = 10
	TrySleepTime        = time.Second
	JustGetInstanceInfo = 0
	AccessSecret        = "SealVMAccessSecret"
	AccessKey           = "SealVMAccessKey"
	privateCidrIP       = "172.16.0.0/24"
)

var defaultCategory = "cloud_essd"

type ResourceName string

const (
	EipID                      ResourceName = AliDomain + "EipID"
	VpcID                      ResourceName = AliDomain + "VpcID"
	VSwitchID                  ResourceName = AliDomain + "VSwitchID"
	SecurityGroupID            ResourceName = AliDomain + "SecurityGroupID"
	ZoneIDs                    ResourceName = AliDomain + "ZoneIDs"
	ZoneID                     ResourceName = AliDomain + "ZoneID"
	RegionID                   ResourceName = AliDomain + "RegionID"
	RegionIDs                  ResourceName = AliDomain + "RegionIDs"
	ShouldBeDeleteInstancesIDs ResourceName = "ShouldBeDeleteInstancesIDs"
	Master0ID                  ResourceName = AliDomain + "Master0ID"
	Master0InternalIP          ResourceName = AliDomain + "Master0InternalIP"
	EIP                        ResourceName = AliDomain + "EIP"
	SpotStrategy               ResourceName = AliDomain + "SpotStrategy"
	Bandwidth                  ResourceName = AliDomain + "Bandwidth"
	DiskCategory               ResourceName = AliDomain + "DiskCategory"
)

func (r ResourceName) SpecValue(infra *v1.VirtualMachine) string {
	return infra.Annotations[string(r)]
}

func (r ResourceName) SpecSetValue(infra *v1.VirtualMachine, val string) {
	infra.Annotations[string(r)] = val
}

func (r ResourceName) StatusValue(status *v1.VirtualMachineStatus) string {
	return status.Data[string(r)]
}

func (r ResourceName) StatusSetValue(status *v1.VirtualMachineStatus, val string) {
	status.Data[string(r)] = val
}

type ImageArch string

func ConvertImageArch(arch v1.Arch) ImageArch {
	switch arch {
	case v1.ARM64:
		return "arm64"
	case v1.AMD64:
		return "x86_64"
	}
	return ""
}

type ExportPort struct {
	Protocol  Protocol `json:"protocol"`
	CidrIP    string   `json:"cidrIP"`
	PortRange string   `json:"portRange"`
}

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)
