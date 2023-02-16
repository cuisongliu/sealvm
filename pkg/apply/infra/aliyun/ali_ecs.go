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
	strings2 "github.com/labring/sealvm/pkg/utils/strings"
	v1 "github.com/labring/sealvm/types/api/v1"
	"strconv"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
)

type Instance struct {
	CPU              int
	Memory           int
	InstanceID       string
	PrimaryIPAddress string
}

func (a *AliProvider) InputIPlist(host *v1.Host) (ipList []string, err error) {
	if host == nil {
		return nil, err
	}
	instances, err := a.GetInstancesInfo(host, host.Count)
	if err != nil {
		return nil, err
	}
	for _, instance := range instances {
		ipList = append(ipList, instance.PrimaryIPAddress)
	}
	return ipList, nil
}

func (a *AliProvider) GetInstanceStatus(instanceID string) (instanceStatus string, err error) {
	request := ecs.CreateDescribeInstanceStatusRequest()
	request.Scheme = Scheme
	request.InstanceId = &[]string{instanceID}
	response := ecs.CreateDescribeInstanceStatusResponse()
	err = a.RetryEcsRequest(request, response)
	if err != nil {
		return "", fmt.Errorf("get GetAvailableZoneID status failed %v , error :%v", instanceID, err)
	}
	if len(response.InstanceStatuses.InstanceStatus) == 0 {
		return "", fmt.Errorf("GetAvailableZoneID list is empty")
	}
	return response.InstanceStatuses.InstanceStatus[0].Status, nil
}

func (a *AliProvider) PowerOffInstance(instanceID string) error {
	request := ecs.CreateStopInstancesRequest()
	request.Scheme = Scheme
	request.InstanceId = &[]string{instanceID}

	response := ecs.CreateStopInstancesResponse()
	return a.RetryEcsRequest(request, response)
}

func (a *AliProvider) StartInstance(instanceID string) error {
	request := ecs.CreateStartInstanceRequest()
	request.Scheme = Scheme
	request.InstanceId = instanceID
	response := ecs.CreateStartInstanceResponse()
	return a.RetryEcsRequest(request, response)
}

func (a *AliProvider) ChangeInstanceType(instanceID string, host *v1.Host) error {
	instanceStatus, err := a.GetInstanceStatus(instanceID)
	if err != nil {
		return err
	}
	if instanceStatus != "Stopped" {
		err = a.PowerOffInstance(instanceID)
		if err != nil {
			return err
		}
	}
	expectInstanceType, err := a.GetAvailableInstanceType(host)
	if err != nil {
		return err
	}

	request := ecs.CreateModifyInstanceSpecRequest()
	request.Scheme = Scheme
	request.InstanceId = instanceID
	response := ecs.CreateModifyInstanceSpecResponse()
	err = a.RetryEcsInstanceType(request, response, expectInstanceType, host.GetRoleList())
	if err != nil {
		return err
	}
	return a.StartInstance(instanceID)
}

func (a *AliProvider) GetInstancesInfo(host any, expectCount int) (instances []Instance, err error) {
	var count int
	tag := make(map[string]string)
	tag[Product] = a.Infra.Name
	switch t := host.(type) {
	case *v1.VirtualMachineHostStatus:
		tag[Role] = t.Role
		tag[Arch] = string(t.Arch)
	case *v1.Host:
		tag[Role] = t.Role
		tag[Arch] = string(t.Arch)
	}

	if expectCount == 0 {
		count = -1
	} else {
		count = expectCount
	}
	instancesTags := CreateDescribeInstancesTag(tag)
	request := ecs.CreateDescribeInstancesRequest()
	request.Scheme = Scheme
	request.RegionId = RegionID.StatusValue(&a.Infra.Status)
	request.VSwitchId = VSwitchID.StatusValue(&a.Infra.Status)
	request.SecurityGroupId = SecurityGroupID.StatusValue(&a.Infra.Status)
	request.Tag = &instancesTags
	response := ecs.CreateDescribeInstancesResponse()
	err = a.TryGetInstance(request, response, count)
	if err != nil {
		return nil, err
	}

	for _, i := range response.Instances.Instance {
		instances = append(instances,
			Instance{
				CPU:              i.Cpu,
				Memory:           i.Memory / 1024,
				InstanceID:       i.InstanceId,
				PrimaryIPAddress: i.NetworkInterfaces.NetworkInterface[0].PrimaryIpAddress})
	}
	return
}

func (a *AliProvider) ReconcileInstances(host *v1.Host, status *v1.VirtualMachineHostStatus) error {
	var instances []Instance
	switch host.GetClusterRole() {
	case v1.MASTER:
		if host.Count == 0 {
			return errors.New("master count not set")
		}
	case v1.NODE:
		if host == nil {
			return nil
		}
	}
	if host == nil {
		return errors.New("hosts not set")
	}
	var err error
	if status.ID != "" {
		instances, err = a.GetInstancesInfo(host, JustGetInstanceInfo)
	}
	if err != nil {
		return err
	}
	if i := host.Count; len(instances) < i {
		err = a.RunInstances(host, i-len(instances))
		if err != nil {
			return err
		}
		ipList, err := a.InputIPlist(host)
		if err != nil {
			return err
		}
		status.IPs = strings2.AppendIPList(status.IPs, ipList)
		logger.Info("get scale up IP list %v, append iplist %v, host count %d", ipList, status.IPs, host.Count)
	} else if len(instances) > i {
		var deleteInstancesIDs []string
		var count int
		for _, instance := range instances {
			if instance.InstanceID != Master0ID.StatusValue(&a.Infra.Status) {
				deleteInstancesIDs = append(deleteInstancesIDs, instance.InstanceID)
				count++
			}
			if count == (len(instances) - i) {
				break
			}
		}
		if len(deleteInstancesIDs) != 0 {
			ShouldBeDeleteInstancesIDs.StatusSetValue(&a.Infra.Status, strings.Join(deleteInstancesIDs, ","))
			err = a.DeleteInstances()
			if err != nil {
				return err
			}
			ShouldBeDeleteInstancesIDs.StatusSetValue(&a.Infra.Status, "")
		}
		ipList, err := a.InputIPlist(host)
		if err != nil {
			return err
		}
		status.IPs = strings2.ReduceIPList(status.IPs, ipList)
		logger.Info("get scale up IP list %v, reduce iplist %v, host count %d", ipList, status.IPs, host.Count)
	} else {
		logger.Info("get up IP list %v,  host count %d", status.IPs, host.Count)
	}
	for _, instance := range instances {
		if instance.CPU != host.Resources[v1.CPUKey] || instance.Memory != host.Resources[v1.MEMKey] {
			err = a.ChangeInstanceType(instance.InstanceID, host)
			if err != nil {
				return err
			}
		}
	}
	logger.Info("reconcile %s instances success %v ", host.String(), status.IPs)
	return nil
}

func (a *AliProvider) DeleteInstances() error {
	instanceIDs := strings.Split(ShouldBeDeleteInstancesIDs.StatusValue(&a.Infra.Status), ",")
	if len(instanceIDs) == 0 {
		return nil
	}
	request := ecs.CreateDeleteInstancesRequest()
	request.Scheme = Scheme
	request.InstanceId = &instanceIDs
	request.Force = requests.NewBoolean(true)
	response := ecs.CreateDeleteInstancesResponse()
	err := a.RetryEcsRequest(request, response)
	if err != nil {
		return err
	}
	ShouldBeDeleteInstancesIDs.StatusSetValue(&a.Infra.Status, "")
	if strings2.In(Master0ID.StatusValue(&a.Infra.Status), instanceIDs) {
		logger.Debug("delete instance success,need delete about instance info[master0id,master0InternalIP,eip,eipID]")
		Master0ID.StatusSetValue(&a.Infra.Status, "")
		Master0InternalIP.StatusSetValue(&a.Infra.Status, "")
		EIP.StatusSetValue(&a.Infra.Status, "")
		delete(a.Infra.Status.Data, string(EipID))
	}
	return nil
}

func CreateDescribeInstancesTag(tags map[string]string) (instanceTags []ecs.DescribeInstancesTag) {
	for k, v := range tags {
		instanceTags = append(instanceTags, ecs.DescribeInstancesTag{Key: k, Value: v})
	}
	return
}

func (a *AliProvider) RunInstances(host *v1.Host, count int) error {
	if host == nil {
		return errors.New("host not set")
	}

	j := a.Infra.Status.FindHostsByRoles(host.Role)
	if j == -1 {
		return fmt.Errorf("failed to get status, %v", "not find host status,pelase retry")
	}
	systemDiskSize := host.Resources[v1.DISKKey]
	var instanceType []string
	var err error
	var imageID string
	if imageID, err = a.GetAvailableImageID(host); err != nil {
		return err
	}
	a.Infra.Status.Hosts[j].ImageID = imageID
	a.Infra.Status.Hosts[j].Arch = host.Arch
	instanceType, err = a.GetAvailableInstanceType(host)
	if err != nil {
		return err
	}
	tag := make(map[string]string)
	tag[Product] = a.Infra.Name
	tag[Role] = host.Role
	tag[Arch] = string(host.Arch)
	instancesTag := CreateInstanceTag(tag)

	request := ecs.CreateRunInstancesRequest()
	request.Scheme = Scheme
	request.ImageId = imageID

	request.Password = a.Infra.Spec.Metadata.AccessChannels.SSH.Passwd
	request.SecurityGroupId = SecurityGroupID.StatusValue(&a.Infra.Status)
	request.VSwitchId = VSwitchID.StatusValue(&a.Infra.Status)
	request.SystemDiskSize = strconv.Itoa(systemDiskSize)
	request.SystemDiskCategory = ""
	request.SpotStrategy = SpotStrategy.SpecValue(a.Infra)
	request.Amount = requests.NewInteger(count)
	request.Tag = &instancesTag

	response := ecs.CreateRunInstancesResponse()
	err = a.RetryEcsInstanceType(request, response, instanceType, host.GetRoleList())
	if err != nil {
		return err
	}

	instancesIDs := strings.Join(response.InstanceIdSets.InstanceIdSet, ",")
	a.Infra.Status.Hosts[j].IDs += instancesIDs
	return nil
}

func (a *AliProvider) AuthorizeSecurityGroup(securityGroupID string, exportPort ExportPort) bool {
	request := ecs.CreateAuthorizeSecurityGroupRequest()
	request.Scheme = Scheme
	request.SecurityGroupId = securityGroupID
	request.IpProtocol = string(exportPort.Protocol)
	request.PortRange = exportPort.PortRange
	request.SourceCidrIp = exportPort.CidrIP
	request.Policy = "accept"

	response := ecs.CreateAuthorizeSecurityGroupResponse()
	err := a.RetryEcsRequest(request, response)
	if err != nil {
		logger.Error("%v", err)
		return false
	}
	return response.BaseResponse.IsSuccess()
}
func CreateInstanceTag(tags map[string]string) (instanceTags []ecs.RunInstancesTag) {
	for k, v := range tags {
		instanceTags = append(instanceTags, ecs.RunInstancesTag{Key: k, Value: v})
	}
	return
}
