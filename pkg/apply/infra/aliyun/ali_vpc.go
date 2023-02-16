// Copyright © 2021 Alibaba Group Holding Ltd.
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

package aliyun

import (
	"errors"
	"fmt"
	"github.com/labring/sealvm/pkg/utils/logger"
	"github.com/labring/sealvm/pkg/utils/rand"
	strings2 "github.com/labring/sealvm/pkg/utils/strings"
	v1 "github.com/labring/sealvm/types/api/v1"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
)

func (a *AliProvider) CreateVPC() error {
	if vpcID := VpcID.SpecValue(a.Infra); vpcID != "" {
		VpcID.StatusSetValue(&a.Infra.Status, vpcID)
		logger.Debug("VpcID using default value")
		return nil
	}
	request := vpc.CreateCreateVpcRequest()
	request.Scheme = Scheme
	request.RegionId = RegionID.StatusValue(&a.Infra.Status)
	//response, err := d.Client.CreateVpc(request)
	response := vpc.CreateCreateVpcResponse()
	err := a.RetryVpcRequest(request, response)
	if err != nil {
		return err
	}
	VpcID.StatusSetValue(&a.Infra.Status, response.VpcId)
	return nil
}

func (a *AliProvider) DeleteVPC() error {
	if VpcID.SpecValue(a.Infra) != "" && VpcID.StatusValue(&a.Infra.Status) != "" {
		return nil
	}
	request := vpc.CreateDeleteVpcRequest()
	request.Scheme = Scheme
	request.VpcId = VpcID.StatusValue(&a.Infra.Status)

	//response, err := d.Client.DeleteVpc(request)
	response := vpc.CreateDeleteVpcResponse()
	return a.RetryVpcRequest(request, response)
}

func (a *AliProvider) CreateVSwitch() error {
	if vSwitchID := VSwitchID.SpecValue(a.Infra); vSwitchID != "" {
		logger.Debug("VSwitchID using default value")
		VSwitchID.StatusSetValue(&a.Infra.Status, vSwitchID)
		return nil
	}
	request := vpc.CreateCreateVSwitchRequest()
	request.Scheme = Scheme
	request.ZoneId = ZoneID.StatusValue(&a.Infra.Status)
	request.CidrBlock = privateCidrIP
	request.VpcId = VpcID.StatusValue(&a.Infra.Status)
	request.RegionId = RegionID.StatusValue(&a.Infra.Status)
	response := vpc.CreateCreateVSwitchResponse()
	err := a.RetryVpcRequest(request, response)
	if err != nil {
		return err
	}
	VSwitchID.StatusSetValue(&a.Infra.Status, response.VSwitchId)

	return nil
}

func (a *AliProvider) DeleteVSwitch() error {
	if VSwitchID.SpecValue(a.Infra) != "" && VSwitchID.StatusValue(&a.Infra.Status) != "" {
		return nil
	}
	request := vpc.CreateDeleteVSwitchRequest()
	request.Scheme = Scheme
	request.VSwitchId = VSwitchID.StatusValue(&a.Infra.Status)

	response := vpc.CreateDeleteVSwitchResponse()
	return a.RetryVpcRequest(request, response)
}

func (a *AliProvider) CreateSecurityGroup() error {
	if securityGroupID := SecurityGroupID.SpecValue(a.Infra); securityGroupID != "" {
		logger.Debug("securityGroupID using default value")
		SecurityGroupID.StatusSetValue(&a.Infra.Status, securityGroupID)
		return nil
	}
	request := ecs.CreateCreateSecurityGroupRequest()
	request.Scheme = Scheme
	request.RegionId = RegionID.StatusValue(&a.Infra.Status)
	request.VpcId = VpcID.StatusValue(&a.Infra.Status)
	response := ecs.CreateCreateSecurityGroupResponse()
	err := a.RetryEcsRequest(request, response)
	if err != nil {
		return err
	}

	ports := []ExportPort{
		{
			Protocol:  ProtocolTCP,
			CidrIP:    "0.0.0.0/0",
			PortRange: "22/22",
		},
		{
			Protocol:  ProtocolTCP,
			CidrIP:    "0.0.0.0/0",
			PortRange: "6443/6443",
		},
	}
	for _, port := range ports {
		if !a.AuthorizeSecurityGroup(response.SecurityGroupId, port) {
			return fmt.Errorf("authorize securitygroup port: %v failed", port)
		}
	}
	SecurityGroupID.StatusSetValue(&a.Infra.Status, response.SecurityGroupId)
	return nil
}

func (a *AliProvider) DeleteSecurityGroup() error {
	if SecurityGroupID.SpecValue(a.Infra) != "" && SecurityGroupID.StatusValue(&a.Infra.Status) != "" {
		return nil
	}
	request := ecs.CreateDeleteSecurityGroupRequest()
	request.Scheme = Scheme
	request.SecurityGroupId = SecurityGroupID.StatusValue(&a.Infra.Status)

	response := ecs.CreateDeleteSecurityGroupResponse()
	return a.RetryEcsRequest(request, response)
}

func (a *AliProvider) GetAvailableZoneID() error {
	if ZoneID.StatusValue(&a.Infra.Status) != "" {
		logger.Debug("zoneID using status value")
		return nil
	}
	defer func() {
		logger.Info("get available resource success %s: %s", "GetAvailableZoneID", ZoneID.StatusValue(&a.Infra.Status))
	}()

	if len(ZoneIDs.SpecValue(a.Infra)) != 0 {
		zoneIDs := strings.Split(ZoneIDs.SpecValue(a.Infra), ",")
		ZoneID.StatusSetValue(&a.Infra.Status, zoneIDs[rand.Rand(len(zoneIDs))])
		return nil
	}
	request := vpc.CreateDescribeZonesRequest()
	request.Scheme = Scheme
	response := vpc.CreateDescribeZonesResponse()
	err := a.RetryVpcRequest(request, response)
	if err != nil {
		return err
	}
	if len(response.Zones.Zone) == 0 {
		return errors.New("not available ZoneID ")
	}
	zoneID := response.Zones.Zone[rand.Rand(len(response.Zones.Zone))].ZoneId
	ZoneID.StatusSetValue(&a.Infra.Status, zoneID)
	return nil
}

func (a *AliProvider) BindEipForMaster0() error {
	var host *v1.VirtualMachineHostStatus
	for _, h := range a.Infra.Status.Hosts {
		if strings2.In(v1.MASTER, h.Roles()) && h.State == v1.Running {
			host = &h
			break
		}
	}
	if host == nil {
		return fmt.Errorf("bind eip for master error: ready master host not fount")
	}
	instances, err := a.GetInstancesInfo(host, JustGetInstanceInfo)
	if err != nil {
		return err
	}
	if len(instances) == 0 {
		return errors.New("can not find master0 ")
	}
	master0 := instances[0]
	eIP, eIPID, err := a.allocateEipAddress()
	if err != nil {
		return err
	}
	err = a.associateEipAddress(master0.InstanceID, eIPID)
	if err != nil {
		return err
	}
	EIP.StatusSetValue(&a.Infra.Status, eIP)
	EipID.StatusSetValue(&a.Infra.Status, eIPID)
	Master0ID.StatusSetValue(&a.Infra.Status, master0.InstanceID)
	Master0InternalIP.StatusSetValue(&a.Infra.Status, master0.PrimaryIPAddress)
	return nil
}

func (a *AliProvider) allocateEipAddress() (eIP, eIPID string, err error) {
	request := vpc.CreateAllocateEipAddressRequest()
	request.Scheme = Scheme
	request.Bandwidth = Bandwidth.SpecValue(a.Infra)
	request.InternetChargeType = "PayByTraffic"
	response := vpc.CreateAllocateEipAddressResponse()
	err = a.RetryVpcRequest(request, response)
	if err != nil {
		return "", "", err
	}
	return response.EipAddress, response.AllocationId, nil
}

func (a *AliProvider) associateEipAddress(instanceID, eipID string) error {
	request := vpc.CreateAssociateEipAddressRequest()
	request.Scheme = Scheme
	request.InstanceId = instanceID
	request.AllocationId = eipID

	response := vpc.CreateAssociateEipAddressResponse()
	return a.RetryVpcRequest(request, response)
}

func (a *AliProvider) unAssociateEipAddress() error {
	request := vpc.CreateUnassociateEipAddressRequest()
	request.Scheme = Scheme
	request.AllocationId = EipID.StatusValue(&a.Infra.Status)
	request.Force = requests.NewBoolean(true)
	response := vpc.CreateUnassociateEipAddressResponse()
	return a.RetryVpcRequest(request, response)
}

func (a *AliProvider) ReleaseEipAddress() error {
	err := a.unAssociateEipAddress()
	if err != nil {
		return err
	}
	request := vpc.CreateReleaseEipAddressRequest()
	request.Scheme = Scheme
	request.AllocationId = EipID.StatusValue(&a.Infra.Status)
	response := vpc.CreateReleaseEipAddressResponse()
	return a.RetryVpcRequest(request, response)
}
