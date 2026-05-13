  .PHONY: help init plan apply kubeconfig destroy clean

  ARTIFACTS := artifacts

  help:
	@echo "Targets:"
	@echo "  init        terraform init"
	@echo "  plan        terraform plan + write artifacts/plan.json"
	@echo "  apply       terraform apply tfplan + write artifacts/terraform-state.json"
	@echo "  kubeconfig  fetch kubectl credentials for the cluster"
	@echo "  destroy     terraform destroy + remove state and artifacts"
	@echo "  clean       remove state and artifacts (no destroy)"
	@echo ""
	@echo "Required env vars for apply:"
	@echo "  TF_VAR_project_id        Lab GCP project ID"
	@echo "  TF_VAR_authorized_cidr   Your /32 public CIDR"

  init:
	terraform init
  
  $(ARTIFACTS):
	mkdir -p $(ARTIFACTS)

  plan: $(ARTIFACTS)
	@if [ -z "$$TF_VAR_project_id" ] || [ -z "$$TF_VAR_authorized_cidr" ]; then \
	        echo "ERROR: TF_VAR_project_id and TF_VAR_authorized_cidr must be set."; \
	        exit 1; \
	fi
	terraform plan -out=tfplan
	terraform show -json tfplan > $(ARTIFACTS)/plan.json
	@echo "Plan JSON written to $(ARTIFACTS)/plan.json"

  apply: $(ARTIFACTS)
	@if [ ! -f tfplan ]; then \
	        echo "ERROR: tfplan does not exist. Run 'make plan' first."; \
	        exit 1; \
	fi
	terraform apply tfplan
	terraform show -json > $(ARTIFACTS)/terraform-state.json
	@echo "State JSON written to $(ARTIFACTS)/terraform-state.json"

  kubeconfig:
	@CLUSTER=$$(terraform output -raw cluster_name); \
	ZONE=$$(terraform output -raw cluster_location); \
	PROJECT=$$(terraform output -raw project_id); \
	gcloud container clusters get-credentials $$CLUSTER --zone $$ZONE --project $$PROJECT

  destroy:
	terraform destroy -auto-approve
	rm -rf .terraform terraform.tfstate terraform.tfstate.* tfplan $(ARTIFACTS)

  clean:
	rm -rf .terraform terraform.tfstate terraform.tfstate.* tfplan $(ARTIFACTS)
