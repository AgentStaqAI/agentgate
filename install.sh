#!/usr/bin/env bash
set -e

# --- Configuration ---
# Point this to your Scarf gateway (e.g., https://getagentgate.io/packages) 
# or fallback to GitHub releases directly.
DOWNLOAD_BASE="https://github.com/AgentStaqAI/agentgate/releases/latest/download"
BIN_DIR="/usr/local/bin"
EXE_NAME="agentgate"

# --- Colors for UI ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "    ___                    __  ______      __     "
echo "   /   | ____ ____  ____  / /_/ ____/___ _/ /____ "
echo "  / /| |/ __ \`/ _ \/ __ \/ __/ / __/ __ \`/ __/ _ \\"
echo " / ___ / /_/ /  __/ / / / /_/ /_/ / /_/ / /_/  __/"
echo "/_/  |_\__, /\___/_/ /_/\__/\____/\__,_/\__/\___/ "
echo "      /____/                                      "
echo -e "${NC}"
echo -e "${YELLOW}Installing AgentGate - The Zero-Trust MCP Proxy${NC}\n"

# 1. Detect OS (Matches GoReleaser 'title .Os')
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_TITLE="Linux";;
    Darwin*)    OS_TITLE="Darwin";;
    *)          echo -e "${RED}Error: Unsupported OS '${OS}'. AgentGate currently supports Linux and macOS.${NC}" && exit 1;;
esac

# 2. Detect Architecture (Matches GoReleaser arch overrides)
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  ARCH_MAPPED="x86_64";;
    arm64)   ARCH_MAPPED="arm64";;
    aarch64) ARCH_MAPPED="arm64";;
    *)       echo -e "${RED}Error: Unsupported architecture '${ARCH}'. AgentGate supports x86_64 and arm64.${NC}" && exit 1;;
esac

echo -e "Detected environment: ${GREEN}${OS_TITLE}-${ARCH_MAPPED}${NC}"

# 3. Construct the filename exactly as GoReleaser outputs it
TAR_FILE="agentgate_${OS_TITLE}_${ARCH_MAPPED}.tar.gz"
DOWNLOAD_URL="${DOWNLOAD_BASE}/${TAR_FILE}"

# 4. Create a temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# 5. Download the binary
echo -e "Downloading AgentGate from ${BLUE}${DOWNLOAD_URL}${NC}..."
if command -v curl >/dev/null 2>&1; then
    # -f fails silently on server errors (404), -L follows redirects (Scarf)
    curl -fSL -o "${TAR_FILE}" "${DOWNLOAD_URL}" || { echo -e "${RED}Download failed. Check if release exists.${NC}"; exit 1; }
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${TAR_FILE}" "${DOWNLOAD_URL}" || { echo -e "${RED}Download failed. Check if release exists.${NC}"; exit 1; }
else
    echo -e "${RED}Error: curl or wget is required to download AgentGate.${NC}"
    exit 1
fi

# 6. Extract the binary
echo -e "Extracting archive..."
tar -xzf "${TAR_FILE}"

if [ ! -f "${EXE_NAME}" ]; then
    echo -e "${RED}Error: Extraction failed. Expected to find '${EXE_NAME}' in archive.${NC}"
    exit 1
fi

# 7. Install to BIN_DIR
echo -e "Installing to ${BIN_DIR}..."

# Check if we need sudo to write to /usr/local/bin
if [ -w "${BIN_DIR}" ]; then
    mv "${EXE_NAME}" "${BIN_DIR}/${EXE_NAME}"
else
    echo -e "${YELLOW}Sudo privileges required to install to ${BIN_DIR}.${NC}"
    sudo mv "${EXE_NAME}" "${BIN_DIR}/${EXE_NAME}"
fi

chmod +x "${BIN_DIR}/${EXE_NAME}"

# 8. Clean up
cd - > /dev/null
rm -rf "$TMP_DIR"

# 9. Success Message
echo -e "\n${GREEN}✔ AgentGate installed successfully!${NC}"
echo -e "Run ${YELLOW}agentgate --help${NC} to get started."
echo -e "To launch the dashboard and proxy, run: ${BLUE}agentgate serve${NC}\n"
