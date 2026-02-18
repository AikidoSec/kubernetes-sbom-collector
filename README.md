# Kubernetes SBOM Collector

A Kubernetes agent that collects Software Bill of Materials (SBOM) data from container images running in a Kubernetes cluster.

## Overview

The Kubernetes SBOM Collector monitors pods in a Kubernetes cluster and collects SBOM information from their container images.

It watches for pod events and processes images to generate comprehensive SBOM data, which can be sent to configured output destinations.

The collector operates as a sidecar component of the [kubernetes agent](https://github.com/AikidoSec/kubernetes-agent), which manages its lifecycle and provides essential runtime services:

- **Configuration management**: Fetches initial configuration from the agent, including namespace filters and watcher settings
- **Authentication**: Retrieves API tokens from the agent for each SBOM submission request
- **Cluster-wide deduplication**: Queries the agent's cache to ensure each image is processed only once across the entire cluster, preventing duplicate SBOM generation
- **Error reporting**: Reports processing errors directly to the agent for centralized monitoring and alerting

## Features

- **Node-specific monitoring**: Can be configured to monitor pods on a specific node or across the entire cluster
- **Namespace filtering**: Exclude or include specific namespaces from SBOM collection
- **Pod lifecycle tracking**: Monitors pod creation, updates, and deletions
- **Image analysis**: Extracts and analyzes container images from running pods
- **Automated SBOM generation**: Collects SBOM data for discovered images
- **Flexible output**: Sends SBOM data to configured destinations

## Image Source Resolution

By default, the collector runs as a DaemonSet, watching for Pods that run in the same node. It uses a multi-source approach to access container images:

1. **Node-local registry**: First attempts to access images from the local container runtime (Docker/containerd)
2. **Remote registry**: Falls back to pulling from the remote registry if local access fails
3. **Rate limiting**: Implements exponential backoff retry logic for registry rate limits

This approach minimizes network traffic and improves performance by preferring local image access.

## Pod Filtering

The collector implements intelligent pod filtering:

- Filters pods in specified namespaces (via `excludedNamespaces` or `includedNamespaces`)
- Filters pods by node assignment
- Only processes pods in Running, Succeeded, or Failed states
- Skips transient pods not in the initial snapshot
- Detects pod specification changes and phase transitions

## Architecture

```
kubernetes-sbom-collector/
├── cmd/
│   └── main.go                         # Application entry point and initialization
├── internal/
│   ├── clients/
│   │   ├── agent/
│   │   │   └── agent.go                # Client for SBOM collection agent communication
│   │   └── output/
│   │       └── output.go               # Client for sending SBOM data to destinations
│   ├── controllers/
│   │   └── watcher.go                  # Kubernetes controller and reconciliation logic
│   ├── predicates/
│   │   ├── pod.go                      # Pod-specific event filtering predicates
│   │   └── predicates.go               # Common predicate utilities
│   └── service/
│       └── service.go                  # Core business logic and orchestration
└── pkg/
├── image/
│   └── image.go                        # Image reference parsing and manipulation
│
├── logger/
│   └── logger.go                       # Logging configuration and utilities
│
├── models/                             # Data models and structures
└── sbom/
└── sbom.go                             # SBOM processing and generation logic
```

---

## Local Debugging

You can run the collector locally against your current Kubernetes context (`~/.kube/config`). It requires access to a running [kubernetes agent](https://github.com/AikidoSec/kubernetes-agent).

### Required Environment Variables

Before running the agent, set the following:

```bash
export POD_NAME="kubernetes-agent-rs001-001"
export AGENT_NAMESPACE="aikido"
export ENVIRONMENT="local"
export AGENT_URL="http://localhost:8080"
```

## Local Deployment with Minikube

Deploy the collector to a local **Minikube** cluster using a locally built image and the Helm chart.

> Prerequisites: Minikube is installed and running (`minikube start`), Docker is installed.

### 1) Point Docker to Minikube’s Docker daemon
This ensures the image you build is placed **inside** Minikube’s Docker registry, so the cluster can pull it without pushing to a remote registry.

```bash
eval $(minikube docker-env)
```

After this, all docker commands run against the Docker daemon inside the Minikube VM.

### 2) Build the collector image for the cluster
Build (and tag) the container image used by the Helm release. The --platform flag ensures compatibility with the Minikube node’s architecture.

```bash
docker buildx build --platform linux/amd64 -t kubernetes-sbom-collector:$imageTag .
```

### 3) Install the chart with your API settings
Use Helm to install the [chart](https://github.com/AikidoSec/helm-charts), passing your API endpoint and token at install time.
This command will create a new namespace called `aikido` if it doesn’t already exist and install the kubernetes-agent and kubernetes-sbom-collector components.

```bash
helm install aikido ./kubernetes-agent -n aikido \
  --set sbomCollector.enabled=true \
  --set sbomCollector.image.repository=kubernetes-sbom-collector \
  --set sbomCollector.image.tag=$imageTag \
  --set config.apiEndpoint=$apiEndpoint \
  --set config.apiToken=$apiToken \
  --create-namespace
```
