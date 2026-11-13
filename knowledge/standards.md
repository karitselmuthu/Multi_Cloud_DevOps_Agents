# Architecture standards

All S3 buckets must block public access and use server-side encryption. Never use acl public-read.

Security groups must never allow ingress from 0.0.0.0/0 on admin ports; restrict to a known CIDR.

Terraform modules: pin provider versions, tag every resource with owner and environment, keep state in a remote backend.

Kubernetes workloads need resource requests and limits, liveness and readiness probes, and run as non-root.

# Runbooks

If an ECS service is unhealthy, check target group health, task logs in CloudWatch, then recent deploys.

Azure AKS node pool scaling: use the cluster autoscaler; check ACR pull permissions via Entra role assignments.

# Incident history

Past incident: public S3 bucket exposed logs. Fix: account-level public access block and policy denying public ACLs.
