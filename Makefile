SHELL = /bin/bash

GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD | sed -e 's^/^-^g; s^[.]^-^g;' | tr '[:upper:]' '[:lower:]')
NAMESPACE:=vault-issuer-$(shell echo $${RANDOM})

# Image URL to use all building/pushing image targets
IMG ?= perconalab/percona-vault-issuer:$(GIT_BRANCH)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: manager

# Build manager binary
manager: generate
	go build -o bin/manager main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate
	go run ./main.go

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy:
	kubectl create namespace $(NAMESPACE)
	sed -s 's~vault-issuer-namespace~$(NAMESPACE)~; s~vault-issuer-image~$(IMG)~' ./config/manager/manager.yaml | kubectl apply -f -
	sed -s 's/namespace: \"vault-issuer\"/namespace: \"$(NAMESPACE)\"/' ./config/rbac/rbac.yaml | kubectl apply --namespace=$(NAMESPACE) -f -

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build:
	docker build . -t ${IMG}

# Build and push the docker image
docker-push: docker-build
	docker push ${IMG}

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.3.0 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif
