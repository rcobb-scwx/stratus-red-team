package azure

import (
	"context"
	_ "embed"
	"time"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.execution.vm-run-command",
		FriendlyName: "AZT201.1 - Virtual Machine Scripting: RunCommand",
		Description: `
		By utilizing the 'RunCommand' feature on a Virtual Machine, an attacker can pass:

- Windows: PowerShell commands to the VM as SYSTEM.
- Linux: Shell commands to the VM as root.

Reference:

- https://github.com/hausec/Azure-Attack-Matrix/blob/main/Execution/AZT201/AZT201-1.md

Warm-up: 

- Create a virtual machine

Detonation: 

- Invoke a RunCommand on the target virtual machine
`,
		Detection:                  "Identify Azure Activity RunCommand events",
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	vmObjectId := params["vm_instance_object_id"]
	vmName := params["vm_name"]
	resourceGroup := params["resource_group_name"]

	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	subscriptionID := providers.Azure().SubscriptionID
	//clientOptions := providers.Azure().ClientOptions

	virtualMachineRunCommandClient, err := armcompute.NewVirtualMachineRunCommandsClient(subscriptionID, cred, nil)//clientOptions)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	log.Println("Issuing Run Command for VM instance " + vmObjectId)

	poller, err := virtualMachineRunCommandClient.BeginCreateOrUpdate(ctx,
		resourceGroup,
		vmName,
		"RunPowerShellScript",
		armcompute.VirtualMachineRunCommand{
			Location: to.Ptr("West US"),
			Properties: &armcompute.VirtualMachineRunCommandProperties{
				AsyncExecution: to.Ptr(false),
				Parameters: nil,
				RunAsPassword: nil,
				RunAsUser: nil,
				Source: &armcompute.VirtualMachineRunCommandScriptSource{
					Script: to.Ptr("Get-Service"),
				},
				TimeoutInSeconds: to.Ptr[int32](3600),
			},
		},
		&armcompute.VirtualMachineRunCommandsClientBeginCreateOrUpdateOptions{ResumeToken: ""})

	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}

	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}

	_ = res

	return nil
}
