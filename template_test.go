package main

import (
	"os"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These are Monitor's application requirements; the control plane only renders
// env and provisions the resources declared by this release.
func TestReleaseTemplateKeepsOwnerBindingAndState(t *testing.T) {
	raw, err := os.ReadFile("tinfoil-config.yml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Volumes []struct {
			Name, Size, Owner string
			KeySecret         string `yaml:"key-secret"`
		}
		CVMNetwork struct {
			Inbound []int `yaml:"inbound-ports"`
		} `yaml:"cvm-network"`
		Containers []struct {
			Name, User                   string
			Command, Env, Ports, Secrets []string
			Mounts                       []string `yaml:"persistent_volumes"`
		}
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Volumes) != 0 || len(config.Containers) != 1 {
		t.Fatal("Monitor needs one container with object storage and no attached disk")
	}
	c := config.Containers[0]
	wantCommand := []string{"-production", "-ssh-host-key", "/run/tinfoil/keys/host-ssh/private_key.pem", "-api", "0.0.0.0:8080", "-listen", "0.0.0.0:2223"}
	if len(c.Mounts) != 0 || c.User != "65532:65532" || !reflect.DeepEqual(c.Command, wantCommand) ||
		!reflect.DeepEqual(c.Env, []string{"MONITOR_OWNER_KEY_SHA256", "TINFOIL_STORAGE_BUCKET", "AWS_CONTAINER_CREDENTIALS_FULL_URI"}) ||
		!reflect.DeepEqual(c.Secrets, []string{"AWS_CONTAINER_AUTHORIZATION_TOKEN"}) {
		t.Fatal("Monitor must bind its owner and storage in measured env and obtain credentials through runtime secrets")
	}
	if !reflect.DeepEqual(c.Ports, []string{"22:2223"}) || !reflect.DeepEqual(config.CVMNetwork.Inbound, []int{443, 22}) {
		t.Fatal("Monitor must expose its native SSH endpoint")
	}
}
