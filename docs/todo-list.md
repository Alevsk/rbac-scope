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

- [ ] **D400** Create renderer package
- [ ] **D401** Define `Renderer` interface (input → rendered manifests)  
- [ ] **D402** Implement **HelmRenderer** (using `chartutil`/`engine`)  
- [ ] **D403** Implement **KustomizeRenderer** (using `kust build` libs)  
- [ ] **D404** Create unit tests + golden files for renderers

### 🔍 Extractor

- [ ] **E500** Create extractor package
- [ ] **E501** Define `Extractor` interface (rendered → structured data)  
- [ ] **E502** Implement **RBACExtractor** (service accounts, roles, verbs, scopes)  
- [ ] **E503** Capture workload → container-image mapping  
- [ ] **E504** Correlate roles/verbs to namespaces & CRDs  
- [ ] **E505** Add comprehensive extractor tests (edge cases, malformed YAML)  

### 🧩 Normalizer

- [ ] **F600** Create normalizer package
- [ ] **F601** Design in-memory data model (`Operator`, `ServiceAccount`, `Role`, …)  
- [ ] **F602** Implement concurrency-safe map with mutexes / sync primitives  
- [ ] **F603** Build loader that merges extractor output into the model  
- [ ] **F604** Track operator name + version (`argocd/2.6.7`) in model keys  
- [ ] **F605** Run `go test -race` and fix any data races
- [ ] **F606** Map `ServiceAccount → Workload` usage (e.g., `argocd-server → Deployment/argocd-server`)  
- [ ] **F607** Associate each service account and role with its **namespace** and store in the model  
- [ ] **F608** Aggregate **RBAC capability summaries** per service account (verbs, resources, cluster-scoped vs namespace-scoped)  
- [ ] **F609** Compute **risk flags** for dangerous combinations (e.g., `secrets:get` + `pods/exec`) and attach to summaries  
- [ ] **F60A** Track **operator version lineage** so multiple versions can coexist (`prometheus-operator/0.64.1` vs `0.65.0`)  
- [ ] **F60B** Implement **duplicate-detection / merge logic** when identical objects are discovered across sources  
- [ ] **F60C** Expose **query helpers** (e.g., “What can SA X do across namespaces?”) for later CLI/UI layers  
- [ ] **F60D** Produce **visualization-ready payloads** (e.g., DOT, JSON graph) from normalized data model  
- [ ] **F60E** Add unit tests for namespace mapping, risk flag computation, and lineage handling  
- [ ] **F60F** Benchmark model build under concurrent ingestion to validate mutex strategy (target ≤ 5 ms/op on 8 CPU)  

### 📦 Output Store

- [ ] **G700** Create output store package
- [ ] **G701** Define `OutputStore` interface (model → persistence)  
- [ ] **G702** Implement **FilesystemStore** (folder per operator version)  
- [ ] **G703** Add **JSONSerializer** with indented output  
- [ ] **G704** Add **YAMLSerializer** preserving ordering for diff-friendliness  
- [ ] **G705** Unit tests + sample outputs in `examples/`  
