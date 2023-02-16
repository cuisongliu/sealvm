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
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/labring/sealvm/pkg/utils/logger"
	strings2 "github.com/labring/sealvm/pkg/utils/strings"
	v1 "github.com/labring/sealvm/types/api/v1"
	"github.com/manifoldco/promptui"
)

func (a *AliProvider) GetAvailableImageID(host *v1.Host) (string, error) {
	if host.Image != "" {
		logger.Info("host tags is %v,using imageID is %s", host.Role, host.Image)
		return host.Image, nil
	}
	logger.Warn("tips: imageID not set,so imageID is random.that will maybe let instanceType not find.")
	request := ecs.CreateDescribeImagesRequest()
	request.ImageOwnerAlias = "system"
	request.PageSize = "100"
	request.Architecture = string(ConvertImageArch(host.Arch))
	request.OSType = "linux"
	response := ecs.CreateDescribeImagesResponse()
	err := a.RetryEcsRequest(request, response)
	if err != nil {
		return "", fmt.Errorf("get ImageID failed , error :%v", err)
	}
	if response.TotalCount == 0 {
		return "", fmt.Errorf("ImageID list is empty")
	}
	image := ""
	var images []string
	for _, img := range response.Images.Image {
		images = append(images, img.ImageId)
	}

	prompt := promptui.Select{
		Label: "Select Aliyun Image ID for " + host.Role,
		Items: images,
	}

	_, image, err = prompt.Run()
	if err != nil {
		return "", err
	}

	logger.Info("host tags is %v,using first imageID is %s", host.Role, image)
	return image, nil
}

func (a *AliProvider) GetDefaultDiskCategories(host *v1.Host) (system string) {
	if category := DiskCategory.SpecValue(a.Infra); category != "" {
		system = category
	} else {
		logger.Warn("host tags is %v,system category not set", host.Role)
		system = defaultCategory
	}
	return
}

func (a *AliProvider) GetAvailableInstanceType(host *v1.Host) ([]string, error) {
	j := a.Infra.Status.FindHostsByRoles(host.Role)
	if j == -1 {
		return nil, fmt.Errorf("failed to get host, %v", "not find host status,pelase retry")
	}
	if host.InstanceType != "" {
		return []string{host.InstanceType}, nil
	}
	var systemInstanceTypes []string

	var err error
	systemDisk := a.GetDefaultDiskCategories(host)

	logger.Debug("host tags is %v,search systemDiskCategory=%s", host.Role, systemDisk)
	systemInstanceTypes, err = a.GetAvailableResource(host, systemDisk, "")
	if err == nil {
		DiskCategory.StatusSetValue(&a.Infra.Status, systemDisk)
	}

	if len(systemInstanceTypes) < 1 {
		return nil, fmt.Errorf("host tags is %v,systemInstanceType not find", host.Role)
	}

	var instanceTypes []string
	if err != nil {
		return nil, err
	}

	request := ecs.CreateDescribeImageSupportInstanceTypesRequest()
	request.Scheme = Scheme
	request.RegionId = RegionID.StatusValue(&a.Infra.Status)
	request.ImageId = a.Infra.Status.Hosts[j].ImageID

	response := ecs.CreateDescribeImageSupportInstanceTypesResponse()
	err = a.EcsClient.DoAction(request, response)
	if err != nil {
		return nil, err
	}
	for _, i := range response.InstanceTypes.InstanceType {
		if i.CpuCoreCount == host.Resources[v1.CPUKey] && int(i.MemorySize) == host.Resources[v1.MEMKey] {
			if strings2.In(i.InstanceTypeId, systemInstanceTypes) {
				logger.Debug("host tags is %v,append InstanceType is %s", host.Role, i.InstanceTypeId)
				instanceTypes = append(instanceTypes, i.InstanceTypeId)
			}
		}
	}
	if len(instanceTypes) < 1 {
		return nil, fmt.Errorf("host tags is %v,instanceType not find", host.Role)
	}
	return instanceTypes, nil
}

func (a *AliProvider) GetAvailableResource(host *v1.Host, systemCategory, dataCategory string) (instanceType []string, err error) {
	request := ecs.CreateDescribeAvailableResourceRequest()
	request.Scheme = Scheme
	request.RegionId = RegionID.StatusValue(&a.Infra.Status)
	request.ZoneId = ZoneID.StatusValue(&a.Infra.Status)
	request.DestinationResource = "InstanceType"
	request.InstanceChargeType = "PostPaid"
	request.SpotStrategy = SpotStrategy.SpecValue(a.Infra)
	request.SystemDiskCategory = systemCategory
	request.DataDiskCategory = dataCategory
	request.Cores = requests.NewInteger(host.Resources[v1.CPUKey])
	request.Memory = requests.NewFloat(float64(host.Resources[v1.MEMKey]))
	response := ecs.CreateDescribeAvailableResourceResponse()
	err = a.EcsClient.DoAction(request, response)
	if err != nil {
		return nil, err
	}
	if len(response.AvailableZones.AvailableZone) < 1 {
		return nil, fmt.Errorf("available zone  not find")
	}
	for _, i := range response.AvailableZones.AvailableZone {
		for _, f := range i.AvailableResources.AvailableResource {
			for _, r := range f.SupportedResources.SupportedResource {
				if r.StatusCategory == "WithStock" {
					instanceType = append(instanceType, r.Value)
				}
			}
		}
	}
	j := a.Infra.Status.FindHostsByRoles(host.Roles)
	if j == -1 {
		return nil, fmt.Errorf("failed to get ecs instance type, %v", "not find host status,pelase retry")
	}

	if a.Infra.Status.Hosts[j].InstanceType != "" {
		defaultInstanceType := []string{a.Infra.Status.Hosts[j].InstanceType}
		instanceType = append(defaultInstanceType, instanceType...)
	}

	return
}
