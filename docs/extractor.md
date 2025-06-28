# Extractors

The RBAC-Ops tool includes several extractors that analyze Kubernetes manifests to gather information about identities, workloads, and RBAC configurations.

## Identity Extractor

The Identity Extractor (`IdentityExtractor`) analyzes ServiceAccount resources to identify:

- Service account names and namespaces
- Automount token settings
- Associated secrets
- Image pull secrets
- Labels and annotations

### Identity Extractor Output

```json
{
  "identities": {
    "my-service-account": {
      "default": {
        "name": "my-service-account",
        "namespace": "default",
        "automountToken": false,
        "secrets": [
          "my-secret"
        ],
        "imagePullSecrets": [
          "registry-secret"
        ],
        "labels": {
          "app": "my-app"
        },
        "annotations": {
          "description": "Service account for my app"
        }
      }
    }
  }
}
```

## Workload Extractor

The Workload Extractor (`WorkloadExtractor`) analyzes various Kubernetes workload resources:

- Pods
- Deployments
- StatefulSets
- DaemonSets
- Jobs
- CronJobs

For each workload, it extracts:

- Type, name, and namespace
- Associated service account
- Security context settings
- Container information (name, image, security context, resources)
- Labels and annotations

### Workload Extractor Output

```json
{
  "workloads": {
    "my-service-account": {
      "default": [
        {
          "type": "Deployment",
          "name": "my-app",
          "namespace": "default",
          "serviceAccount": "my-service-account",
          "labels": {
            "app": "my-app"
          },
          "annotations": {
            "description": "My application deployment"
          },
          "securityContext": {
            "runAsNonRoot": true
          },
          "containers": [
            {
              "name": "app",
              "image": "my-app:1.0.0",
              "securityContext": {
                "readOnlyRootFilesystem": true
              },
              "resources": {
                "limits": {
                  "cpu": "1",
                  "memory": "1Gi"
                }
              }
            }
          ]
        }
      ]
    }
  }
}
```

## RBAC Extractor

The RBAC Extractor (`RBACExtractor`) analyzes RBAC-related resources:

- Roles and ClusterRoles
- RoleBindings and ClusterRoleBindings

For each role, it extracts:

- Type (Role/ClusterRole)
- Name and namespace
- Permissions (API groups, resources, and verbs)

For each binding, it extracts:

- Type (RoleBinding/ClusterRoleBinding)
- Name and namespace
- Subject service accounts
- Referenced role name

### RBAC Extractor Output

```json
{
  "roles": [
    {
      "type": "Role",
      "name": "pod-reader",
      "namespace": "default",
      "permissions": {
        "": {
          "pods": {
            "": {
              "get": {},
              "list": {},
              "watch": {}
            }
          }
        }
      }
    }
  ],
  "bindings": [
    {
      "type": "RoleBinding",
      "name": "read-pods",
      "namespace": "default",
      "subjects": [
        {
          "kind": "ServiceAccount",
          "name": "my-service-account",
          "namespace": "default"
        }
      ],
      "roleRef": "pod-reader"
    }
  ],
  "rbac": {
    "my-service-account": {
      "default": {
        "roles": [
          {
            "type": "Role",
            "name": "pod-reader",
            "namespace": "default",
            "permissions": {
              "": {
                "pods": {
                  "": {
                    "get": {},
                    "list": {},
                    "watch": {}
                  }
                }
              }
            }
          }
        ]
      }
    }
  }
}
```

## Common Features

All extractors share these common features:

- Support for strict or lenient parsing (controlled via `StrictParsing` option)
- Metadata output including counts and statistics
- Error handling for invalid or malformed manifests
- Support for multiple manifests in a single input

## Usage

Extractors can be used independently or together through the ingestor:

```go
// Create an extractor
extractor := NewIdentityExtractor(&Options{
    StrictParsing: true,
})

// Extract data from manifests
result, err := extractor.Extract(ctx, manifests)
if err != nil {
    // Handle error
}

// Access extracted data
identities := result.Data["identities"].(map[string]map[string]Identity)
```
