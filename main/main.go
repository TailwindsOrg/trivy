package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/trivy"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/docker/docker/client"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/docker/docker/api/types"
)

func main() {
	resultList := make([]map[string]interface{}, 0)
	listPodList, err := getLocalPods()
	if err != nil {
		fmt.Println(err)
	}
	localImageNames := getLocalImages()
	for _, podList := range listPodList {
		for _, pod := range podList.Items {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				containerName := containerStatus.Name
				if contains(localImageNames, containerStatus.Image) {
					t := trivy.NewTrivy(containerStatus.Image)
					err := t.Scan()
					if err != nil {
						fmt.Println(err)
					}
					resultMap := make(map[string]interface{})
					resultMap["container-name"] = containerName
					resultMap["pod-name"] = pod.Name
					resultMap["result"] = getNormalizedResults(t.Results)
					resultMap["total-packages"] = t.GetTotalPackages()
					resultMap["total-libraries"] = t.GetTotalLibraries()
					resultMap["total-errors"] = t.GetTotalErrors()
					resultList = append(resultList, resultMap)
				}
			}
		}
	}
	finalMap := make(map[string]interface{})
	tm := time.Now()
	finalMap["time"] = tm.Format("2006:01:02 15:04:05")
	finalMap["report"] = resultList
	jsonString, _ := json.MarshalIndent(finalMap, "", "    ")
	fmt.Println(string(jsonString))
}

func getNormalizedResults(results report.Results) []map[string]interface{} {
	ret := make([]map[string]interface{}, 0)
	for _, result := range results {
		res := make(map[string]interface{})
		res["Target"] = result.Target
		res["Type"] = result.Type
		vuls := make([]map[string]interface{}, 0)
		for _, vulnerability := range result.Vulnerabilities {
			vul := make(map[string]interface{})
			vul["VulnerabilityID"] = vulnerability.VulnerabilityID
			vul["PkgName"] = vulnerability.PkgName
			vul["InstalledVersion"] = vulnerability.InstalledVersion
			vul["Title"] = vulnerability.Title
			vul["Description"] = vulnerability.Description
			vul["FixedVersion"] = vulnerability.FixedVersion
			vul["Severity"] = vulnerability.Severity
			vuls = append(vuls, vul)
		}
		res["Vulnerabilities"] = vuls
		ret = append(ret, res)
	}
	return ret
}

func getLocalImages() []string {
	names := make([]string, 0)
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Println("NewClientWithOpts")
		fmt.Println(err)
		return names
	}

	imageSummaryList, _ := c.ImageList(context.Background(), types.ImageListOptions{All: false})
	if err != nil {
		return names
	}
	for _, imageSummary := range imageSummaryList {
		names = append(names, imageSummary.RepoTags...)
	}
	return names
}

func getLocalPods() ([]*v1.PodList, error) {
	listPodList := make([]*v1.PodList, 0)
	nodeName := os.Getenv("MY_NODE_NAME")
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	namespaces, err := cs.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	for _, ns := range namespaces.Items {
		if ns.Name == "tailwinds" || ns.Name == "kube-system" {
			continue
		}
		// podList, err := cs.CoreV1().Pods(ns.Name).List(metav1.ListOptions{})
		podList, err := cs.CoreV1().Pods(ns.Name).List(metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			fmt.Println(err)
			continue
		}
		listPodList = append(listPodList, podList)
	}
	return listPodList, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
