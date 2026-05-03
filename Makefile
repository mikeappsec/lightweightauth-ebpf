# lwauth-ebpf Makefile
# Builds eBPF C programs and the Go userspace agent.

SHELL := /bin/bash
.DEFAULT_GOAL := all

# Directories
BPF_SRC   := bpf
BPF_OUT   := bpf
CMD_DIR   := cmd/lwauth-ebpf
BIN_DIR   := bin

# Tools
CLANG     ?= clang
LLC       ?= llc
BPFTOOL   ?= bpftool
GO        ?= go

# Build flags
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -I$(BPF_SRC) -Wall -Werror

# eBPF object files
BPF_OBJS := $(BPF_OUT)/lwauth_sockops.o \
            $(BPF_OUT)/lwauth_sk_msg.o \
            $(BPF_OUT)/lwauth_cgroup_skb.o

# Container image
IMAGE     ?= ghcr.io/mikeappsec/lwauth-ebpf
TAG       ?= latest

##@ Build

.PHONY: all
all: bpf build ## Build everything

.PHONY: bpf
bpf: $(BPF_OBJS) ## Compile eBPF programs

$(BPF_OUT)/%.o: $(BPF_SRC)/%.c $(BPF_SRC)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

.PHONY: build
build: ## Build the Go agent binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" \
		-o $(BIN_DIR)/lwauth-ebpf ./$(CMD_DIR)

.PHONY: build-local
build-local: ## Build for the local platform
	$(GO) build -o $(BIN_DIR)/lwauth-ebpf ./$(CMD_DIR)

##@ Container

.PHONY: image
image: bpf build ## Build container image
	docker build -t $(IMAGE):$(TAG) .

.PHONY: push
push: image ## Push container image
	docker push $(IMAGE):$(TAG)

##@ Development

.PHONY: vmlinux
vmlinux: ## Generate vmlinux.h from BTF (requires running on Linux with BTF)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_SRC)/vmlinux.h

.PHONY: test
test: ## Run Go tests
	$(GO) test ./...

.PHONY: lint
lint: ## Lint Go code
	golangci-lint run ./...

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf $(BIN_DIR)
	rm -f $(BPF_OUT)/*.o

.PHONY: fmt
fmt: ## Format Go code
	$(GO) fmt ./...
	$(CLANG)-format -i $(BPF_SRC)/*.c

##@ Help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
