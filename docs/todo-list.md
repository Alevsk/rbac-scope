# RBAC-Ops

## Overview

A curated database of RBAC policies used by popular Kubernetes Operators, with security annotations that spotlight their permissions, potential risks, and abuse scenarios—taking inspiration from GTFOBins and LOLBAS.

## Objective

- Build an **open-source RBAC knowledge base** for operators.  
- **Highlight** over-permissioned roles and risky capability combinations (e.g., `list secrets` + `exec`).  
- Provide **adversary guidance** (“abuse potential”) and **defender guidance** (“hardening advice”).

---

## TODO Checklist

### 📥 Inventory Builder – Ingestion

- [x] **C300** Create ingestor package
- [x] **C301** Create ingest command with the necessary flags
- [x] **C302** Define `SourceResolver` interface (extensible for new sources)  
- [x] **C303** Implement **LocalYAMLResolver** (single file)  
- [x] **C304** Implement **RemoteYAMLResolver** (HTTP/HTTPS)  
- [x] **C305** Implement **FolderResolver** (recursive directory walk)  
- [x] **C306** Write unit tests & fixtures for all resolvers  
- [x] **C307** Document supported sources in `docs/ingestion.md`  

### 🛠 Renderer

- [x] **D400** Create renderer package
- [x] **D401** Define `Renderer` interface (input → rendered manifests)  
- [x] **D402** Implement **YAMLRenderer** (using `yaml`/`json` libs)
- [x] **D403** Implement **HelmRenderer** (using `chartutil`/`engine`)  
- [x] **D404** Implement **KustomizeRenderer** (using `kust build` libs)  
- [x] **D405** Ingestor integrate **YAMLRenderer** when **LocalYAMLResolver** is used
- [x] **D406** Ingestor integrate **YAMLRenderer** when **RemoteYAMLResolver** is used
- [x] **D407** Ingestor integrate **HelmRenderer** when **FolderResolver** is used and folder contains a `Chart.yaml` file
- [x] **D408** Ingestor integrate **KustomizeRenderer** when **FolderResolver** is used and folder contains a `kustomization.yaml` file
- [x] **D409** Document supported renderers in `docs/renderer.md`

### 🔍 Extractor

- [x] **E500** Create extractor package
- [x] **E501** Define `Extractor` interface, the goal is to go from rendered to structured data  
- [x] **E502** Implement **IdentityExtractor**: What service accounts or identities are being defined or used?: Who are the identities? extract ServiceAccounts and their namespaces using Kubernetes standard libraries
- [x] **E503** Implement **WorkloadExtractor**: Extract Namespace + Pod/Deployment/StatefulSet/ReplicaSet/ReplicationController/Job/CronJob/DaemonSet/etc associated with service accounts and the workload metadata such as container image version and securitycontext and any other associated security configuration for the workload using Kubernetes standard libraries
- [x] **E504** Implement **RBACExtractor**: Extract Roles, RoleBindings, ClusterRoles + verbs/resources and scopes the service accounts have access to and on which namespaces using Kubernetes standard libraries
- [x] **E505** On the ingestor.go, modify `reader, metadata, err := resolver.Resolve(ctx)` to return the renderer.Result instead of io.ReadCloser as the reader will not be used, then use each extractor to extract the data from each Manifest and print it to stdout in a tabular format for now
- [x] **E506** Document supported extractors in `docs/extractor.md`

### 🧩 Policy Evaluator

- [ ] **F600** Create additional risk rules in [risks.yaml](../internal/policyevaluation/risks.yaml). Analyze existing rules and use your best security judgement to create additional ones that may enhance the detection of potential abuse scenarios in Kubernetes, each rule would have a name, description, category, risk level, API groups, role type, resources, verbs, and tags. You must reuse existing tags unless you have a reason to create a new tag, if you need to create a new tag then you must create a new RiskTag in [types.go](../internal/policyevaluation/types.go). Finally every newly created rule must be added to the evaluator_test.go file in the MatchRiskRules function to have it tested.
- [ ] **F602** Remove duplicate unit tests from `formatter_test.go`. After an analyze it seems that there are duplicate tests on `formatter_test.go` that are already present on `table_test.go`.
- [ ] **F603** Add Tags for base risk rules that match RiskLevelLow, RiskLevelMedium, RiskLevelHigh, and RiskLevelCritical.
- [ ] **F601** Add support for `nonResourceURLs` evaluation
