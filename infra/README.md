# infra/: declared access

Terraform here is the **declared** side of the drift comparison. It describes
the access that *should* exist on the dogfooded project.

## Who runs Terraform

Terraform uses Application Default Credentials, which on your Mac impersonate
`auditor-reader`. That gives a useful split:

| Command | Runs as | Works? |
|---|---|---|
| `terraform plan` | auditor-reader | yes: plans only read |
| `terraform apply` with only imports | auditor-reader | yes: importing writes local state, not GCP |
| `terraform apply` that changes GCP | auditor-reader | **refused by IAM** |

So nothing in this folder can change the project by accident. A real change is
a deliberate step you take as yourself, and the auditor's approval flow (P4)
will be the normal way to make one.

## First run (adopting what exists)

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars    # fill in project_id and your lowercase email
terraform init
terraform plan
```

Expect: **`Plan: 6 to import, 0 to add, 0 to change, 0 to destroy.`**
That's the 5 grants the collector recorded (1 Owner, 3 reader roles, 1
token-creator binding) plus the `auditor-reader` service account itself.

Anything under "to add / change / destroy" means the declaration doesn't match
reality. Stop and look; don't apply.

```bash
terraform apply      # imports only; type "yes"
terraform plan       # expect: No changes.
git add .terraform.lock.hcl *.tf README.md terraform.tfvars.example
```

`terraform.tfvars`, `.terraform/` and `*.tfstate` are gitignored: they contain
real identifiers.
