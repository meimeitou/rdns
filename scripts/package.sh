#!/bin/bash
# rdns 打包脚本
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# 版本号
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo "0.1.0")
# 目标架构
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
esac
# 操作系统
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# 输出目录
DIST_DIR="$PROJECT_ROOT/dist"
PACKAGE_NAME="rdns-${VERSION}-${OS}-${ARCH}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_NAME"

# 清理旧的打包
clean_dist() {
    info "Cleaning previous builds..."
    rm -rf "$DIST_DIR"
    mkdir -p "$DIST_DIR"
}

# 构建
build_all() {
    info "Building eBPF programs..."
    cd "$PROJECT_ROOT/rdns-ebpf"
    cargo +nightly build \
        -Z build-std=core \
        --target=bpfel-unknown-none \
        --release
    cd "$PROJECT_ROOT"

    info "Building userspace program (release)..."
    # 设置 SKIP_EBPF_BUILD 跳过 build.rs 中的 eBPF 构建（已经单独构建过了）
    SKIP_EBPF_BUILD=1 cargo build --package=rdns --release
}

# 打包
package() {
    info "Creating package directory: $PACKAGE_NAME"
    mkdir -p "$PACKAGE_DIR"
    mkdir -p "$PACKAGE_DIR/bin"
    mkdir -p "$PACKAGE_DIR/lib/ebpf"
    mkdir -p "$PACKAGE_DIR/etc/rdns"

    # 复制二进制文件
    info "Copying binaries..."
    cp "$PROJECT_ROOT/target/release/rdns" "$PACKAGE_DIR/bin/"
    
    # 复制 eBPF 程序
    info "Copying eBPF programs..."
    cp "$PROJECT_ROOT/target/bpfel-unknown-none/release/rdns-xdp" "$PACKAGE_DIR/lib/ebpf/"
    cp "$PROJECT_ROOT/target/bpfel-unknown-none/release/rdns-tc" "$PACKAGE_DIR/lib/ebpf/"

    # 复制配置文件
    info "Copying configuration files..."
    cp "$PROJECT_ROOT/config.toml" "$PACKAGE_DIR/etc/rdns/config.toml.example"
    
    # 生成默认配置（使用打包路径）
    cat > "$PACKAGE_DIR/etc/rdns/config.toml" << 'EOF'
# rdns 配置文件

# 要监控的网卡列表（支持多个）
interfaces = ["eth0"]

[server]
http_addr = "0.0.0.0:8080"
metrics_addr = "0.0.0.0:9090"

[ebpf]
# 部署模式:
#   - "xdp": 仅 XDP（过滤 + 抓取入口流量）
#   - "tc": 仅 TC（抓取双向流量，无过滤）
#   - "xdp_tc": XDP + TC（XDP 过滤，TC 抓取双向流量）【推荐】
mode = "xdp_tc"
xdp_flags = "default"
tc_direction = "both"
xdp_capture_enabled = true
# 使用安装路径
xdp_program_path = "/usr/lib/rdns/ebpf/rdns-xdp"
tc_program_path = "/usr/lib/rdns/ebpf/rdns-tc"

[filter]
[filter.ip]
blacklist = []
whitelist = []

[filter.domain]
blacklist = []
whitelist = []

[logging]
level = "info"
EOF

    # 复制文档
    info "Copying documentation..."
    cp "$PROJECT_ROOT/README.md" "$PACKAGE_DIR/" 2>/dev/null || true
    cp "$PROJECT_ROOT/LICENSE" "$PACKAGE_DIR/" 2>/dev/null || true

    # 创建安装脚本
    cat > "$PACKAGE_DIR/install.sh" << 'INSTALL_EOF'
#!/bin/bash
set -e

PREFIX="${PREFIX:-/usr}"
CONF_DIR="${CONF_DIR:-/etc/rdns}"

echo "Installing rdns to $PREFIX..."

# 创建目录
sudo mkdir -p "$PREFIX/bin"
sudo mkdir -p "$PREFIX/lib/rdns/ebpf"
sudo mkdir -p "$CONF_DIR"

# 安装二进制文件
sudo cp bin/rdns "$PREFIX/bin/"
sudo chmod +x "$PREFIX/bin/rdns"

# 安装 eBPF 程序
sudo cp lib/ebpf/* "$PREFIX/lib/rdns/ebpf/"

# 安装配置文件（不覆盖已有配置）
if [ ! -f "$CONF_DIR/config.toml" ]; then
    sudo cp etc/rdns/config.toml "$CONF_DIR/"
fi
sudo cp etc/rdns/config.toml.example "$CONF_DIR/"

echo "Installation complete!"
echo ""
echo "Usage:"
echo "  sudo rdns -c $CONF_DIR/config.toml"
echo ""
echo "Edit configuration:"
echo "  sudo vim $CONF_DIR/config.toml"
INSTALL_EOF
    chmod +x "$PACKAGE_DIR/install.sh"

    # 创建卸载脚本
    cat > "$PACKAGE_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash
set -e

PREFIX="${PREFIX:-/usr}"
CONF_DIR="${CONF_DIR:-/etc/rdns}"

echo "Uninstalling rdns..."

sudo rm -f "$PREFIX/bin/rdns"
sudo rm -rf "$PREFIX/lib/rdns"

echo "Configuration files in $CONF_DIR were not removed."
echo "Remove manually if needed: sudo rm -rf $CONF_DIR"
echo ""
echo "Uninstallation complete!"
UNINSTALL_EOF
    chmod +x "$PACKAGE_DIR/uninstall.sh"

    # 创建 systemd service 文件
    cat > "$PACKAGE_DIR/rdns.service" << 'SERVICE_EOF'
[Unit]
Description=rdns - DNS packet capture daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/rdns -c /etc/rdns/config.toml
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
SERVICE_EOF
}

# 创建压缩包
create_archive() {
    info "Creating archive..."
    cd "$DIST_DIR"
    
    # 创建 tar.gz
    tar -czvf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
    
    # 计算校验和
    sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
    
    info "Package created: $DIST_DIR/${PACKAGE_NAME}.tar.gz"
}

# 显示打包内容
show_contents() {
    info "Package contents:"
    tree "$PACKAGE_DIR" 2>/dev/null || find "$PACKAGE_DIR" -type f | sort
    
    echo ""
    info "Archive info:"
    ls -lh "$DIST_DIR/${PACKAGE_NAME}.tar.gz"
    cat "$DIST_DIR/${PACKAGE_NAME}.tar.gz.sha256"
}

# 主流程
main() {
    info "=== rdns Package Builder ==="
    info "Version: $VERSION"
    info "Target: ${OS}-${ARCH}"
    echo ""

    clean_dist
    build_all
    package
    create_archive
    show_contents

    echo ""
    info "=== Package build complete! ==="
    echo ""
    echo "To install:"
    echo "  tar -xzf dist/${PACKAGE_NAME}.tar.gz"
    echo "  cd ${PACKAGE_NAME}"
    echo "  sudo ./install.sh"
}

main "$@"
