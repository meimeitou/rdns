# rdns Makefile

# 默认目标
.PHONY: default
default: help

.PHONY: all
all: build-ebpf build

# ============ 构建 ============

# 构建 eBPF 程序 (需要 nightly)
.PHONY: build-ebpf
build-ebpf:
	cargo +nightly build --package=rdns-ebpf \
		-Z build-std=core \
		--target=bpfel-unknown-none \
		--release

# 构建用户态程序 (debug)
.PHONY: build
build: build-ebpf
	cargo build --package=rdns

# 构建用户态程序 (release)
.PHONY: build-release
build-release: build-ebpf
	SKIP_EBPF_BUILD=1 cargo build --package=rdns --release

# ============ 运行 ============

# 运行 (需要 sudo)
.PHONY: run
run: build
	sudo ./target/debug/rdns -c config.toml

# 运行 release 版本
.PHONY: run-release
run-release: build-release
	sudo ./target/release/rdns -c config.toml

# 运行 debug 模式
.PHONY: run-debug
run-debug: build
	sudo RUST_LOG=debug ./target/debug/rdns -c config.toml

# ============ 测试 ============

.PHONY: test
test:
	cargo test --package=rdns
	cargo test --package=rdns-common

# ============ 检查 ============

.PHONY: check
check:
	cargo check --package=rdns
	cargo check --package=rdns-common

.PHONY: clippy
clippy:
	cargo clippy --package=rdns -- -D warnings
	cargo clippy --package=rdns-common -- -D warnings

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: fmt-check
fmt-check:
	cargo fmt --all -- --check

# ============ 清理 ============

.PHONY: clean
clean:
	cargo clean

.PHONY: clean-ebpf
clean-ebpf:
	rm -rf target/bpfel-unknown-none

.PHONY: clean-dist
clean-dist:
	rm -rf dist

# ============ 打包 ============

# 打包发布版本
.PHONY: package
package:
	@chmod +x scripts/package.sh
	@scripts/package.sh

# 仅构建不打包
.PHONY: dist
dist: build-release
	@mkdir -p dist
	@cp target/release/rdns dist/
	@cp target/bpfel-unknown-none/release/rdns-xdp dist/
	@cp target/bpfel-unknown-none/release/rdns-tc dist/
	@cp config.toml dist/config.toml.example
	@echo "Output files in dist/"

# ============ 安装依赖 ============

.PHONY: setup
setup:
	rustup install nightly
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker

# ============ 帮助 ============

.PHONY: help
help:
	@echo "rdns Makefile"
	@echo ""
	@echo "构建:"
	@echo "  make all          - 构建 eBPF 和用户态程序 (debug)"
	@echo "  make build-ebpf   - 仅构建 eBPF 程序"
	@echo "  make build        - 构建用户态程序 (debug)"
	@echo "  make build-release- 构建用户态程序 (release)"
	@echo ""
	@echo "运行:"
	@echo "  make run          - 运行程序 (需要 sudo)"
	@echo "  make run-release  - 运行 release 版本"
	@echo "  make run-debug    - 运行 debug 日志模式"
	@echo ""
	@echo "打包:"
	@echo "  make package      - 完整打包 (构建+打包+压缩)"
	@echo "  make dist         - 简单打包 (仅复制产物到 dist/)"
	@echo ""
	@echo "测试与检查:"
	@echo "  make test         - 运行测试"
	@echo "  make check        - 检查编译"
	@echo "  make clippy       - 运行 clippy"
	@echo "  make fmt          - 格式化代码"
	@echo "  make fmt-check    - 检查代码格式"
	@echo ""
	@echo "其他:"
	@echo "  make setup        - 安装构建依赖"
	@echo "  make clean        - 清理构建产物"
	@echo "  make clean-dist   - 清理打包产物"
	@echo "  make help         - 显示帮助"
