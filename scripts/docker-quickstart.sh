#!/bin/bash
# ============================================================================
# Authority Nanos Docker Quickstart Script
#
# Builds and runs the Authority Nanos quickstart Docker environment.
# Provides an instant, ready-to-use development environment.
#
# Usage:
#   ./scripts/docker-quickstart.sh          # Build and run interactively
#   ./scripts/docker-quickstart.sh build    # Just build the image
#   ./scripts/docker-quickstart.sh run      # Run without rebuilding
#   ./scripts/docker-quickstart.sh shell    # Start a shell in running container
#   ./scripts/docker-quickstart.sh stop     # Stop the container
#   ./scripts/docker-quickstart.sh clean    # Remove container and image
#   ./scripts/docker-quickstart.sh compose  # Use docker-compose for development
#   ./scripts/docker-quickstart.sh help     # Show help message
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
IMAGE_NAME="authority-nanos-quickstart"
CONTAINER_NAME="authority-nanos-quickstart"
DOCKERFILE="Dockerfile.quickstart"
COMPOSE_FILE="docker-compose.quickstart.yml"

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ============================================================================
# Helper functions
# ============================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${BOLD}     Authority Nanos - Docker Quickstart${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "  Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    print_info "Docker is available: $(docker --version)"
}

check_files() {
    cd "$PROJECT_ROOT"

    # Check for required files
    local missing_files=()

    if [ ! -f "Dockerfile.quickstart" ]; then
        missing_files+=("Dockerfile.quickstart")
    fi

    if [ ! -d "sdk/python" ]; then
        missing_files+=("sdk/python/")
    fi

    if [ ! -d "examples" ]; then
        missing_files+=("examples/")
    fi

    if [ ! -f "src/agentic/libak.c" ]; then
        missing_files+=("src/agentic/libak.c")
    fi

    if [ ${#missing_files[@]} -ne 0 ]; then
        print_error "Missing required files:"
        for f in "${missing_files[@]}"; do
            echo "  - $f"
        done
        exit 1
    fi

    # Check for kernel binary (warn but don't fail)
    if [ ! -f "output/platform/pc/bin/kernel.img" ]; then
        print_warning "Kernel binary not found at output/platform/pc/bin/kernel.img"
        print_warning "You may need to build the kernel first: make PLATFORM=pc"
    fi

    # Check for minops (warn but don't fail)
    if [ ! -f "tools/minops/minops" ]; then
        print_warning "minops not found. You may need to build it:"
        print_warning "  cd tools/minops && go build -o minops main.go"
    fi

    # Check for mkfs (warn but don't fail)
    if [ ! -f "output/tools/bin/mkfs" ]; then
        print_warning "mkfs not found. You may need to build it:"
        print_warning "  make -C tools all"
    fi
}

# ============================================================================
# Commands
# ============================================================================

cmd_build() {
    print_banner
    print_info "Building Authority Nanos quickstart image..."
    echo ""

    cd "$PROJECT_ROOT"
    check_files

    # Build the Docker image
    print_info "Building Docker image: $IMAGE_NAME"
    docker build \
        -f "$DOCKERFILE" \
        -t "$IMAGE_NAME:latest" \
        --progress=plain \
        .

    print_success "Docker image built successfully!"
    echo ""
    echo -e "Image: ${CYAN}$IMAGE_NAME:latest${NC}"
    echo ""
}

cmd_run() {
    print_banner
    print_info "Running Authority Nanos quickstart container..."
    echo ""

    cd "$PROJECT_ROOT"

    # Check if image exists
    if ! docker image inspect "$IMAGE_NAME:latest" &> /dev/null; then
        print_warning "Image not found. Building first..."
        cmd_build
    fi

    # Stop existing container if running
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        print_info "Stopping existing container..."
        docker stop "$CONTAINER_NAME" &> /dev/null || true
    fi

    # Remove existing container
    if docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
        print_info "Removing existing container..."
        docker rm "$CONTAINER_NAME" &> /dev/null || true
    fi

    # Create workspace directory if it doesn't exist
    mkdir -p "$PROJECT_ROOT/workspace"

    # Run the container interactively
    print_info "Starting container: $CONTAINER_NAME"
    echo ""

    docker run -it \
        --name "$CONTAINER_NAME" \
        --hostname authority-nanos \
        -v "$PROJECT_ROOT/examples:/opt/authority-nanos/examples:rw" \
        -v "$PROJECT_ROOT/sdk/python:/opt/authority-nanos/sdk/python:rw" \
        -v "$PROJECT_ROOT/workspace:/workspace:rw" \
        -p 8080:8080 \
        -p 8443:8443 \
        -e "AUTHORITY_NANOS_DEV=1" \
        "$IMAGE_NAME:latest"
}

cmd_shell() {
    print_info "Opening shell in running container..."

    if ! docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        print_error "Container is not running. Start it first with: $0 run"
        exit 1
    fi

    docker exec -it "$CONTAINER_NAME" /bin/bash
}

cmd_stop() {
    print_info "Stopping container..."

    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        docker stop "$CONTAINER_NAME"
        print_success "Container stopped."
    else
        print_info "Container is not running."
    fi
}

cmd_clean() {
    print_info "Cleaning up Docker resources..."

    # Stop container if running
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        print_info "Stopping container..."
        docker stop "$CONTAINER_NAME" &> /dev/null || true
    fi

    # Remove container
    if docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
        print_info "Removing container..."
        docker rm "$CONTAINER_NAME" &> /dev/null || true
    fi

    # Remove image
    if docker image inspect "$IMAGE_NAME:latest" &> /dev/null; then
        print_info "Removing image..."
        docker rmi "$IMAGE_NAME:latest" &> /dev/null || true
    fi

    print_success "Cleanup complete."
}

cmd_compose() {
    print_banner
    print_info "Starting development environment with docker-compose..."
    echo ""

    cd "$PROJECT_ROOT"

    # Check if compose file exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        print_error "Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    # Create workspace directory if it doesn't exist
    mkdir -p "$PROJECT_ROOT/workspace"
    mkdir -p "$PROJECT_ROOT/policies"

    # Build and start services
    print_info "Building and starting services..."
    docker-compose -f "$COMPOSE_FILE" up -d --build

    print_success "Development environment is running!"
    echo ""
    echo -e "To open a shell: ${CYAN}docker-compose -f $COMPOSE_FILE exec authority-nanos bash${NC}"
    echo -e "To view logs:    ${CYAN}docker-compose -f $COMPOSE_FILE logs -f${NC}"
    echo -e "To stop:         ${CYAN}docker-compose -f $COMPOSE_FILE down${NC}"
    echo ""
}

cmd_logs() {
    print_info "Showing container logs..."

    if ! docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
        print_error "Container not found."
        exit 1
    fi

    docker logs -f "$CONTAINER_NAME"
}

cmd_status() {
    print_banner
    echo -e "${BLUE}Container Status:${NC}"

    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        echo -e "  Status: ${GREEN}Running${NC}"
        docker ps -f name="$CONTAINER_NAME" --format "  ID: {{.ID}}\n  Image: {{.Image}}\n  Created: {{.CreatedAt}}\n  Ports: {{.Ports}}"
    elif docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
        echo -e "  Status: ${YELLOW}Stopped${NC}"
    else
        echo -e "  Status: ${RED}Not created${NC}"
    fi

    echo ""
    echo -e "${BLUE}Image Status:${NC}"
    if docker image inspect "$IMAGE_NAME:latest" &> /dev/null; then
        echo -e "  Status: ${GREEN}Available${NC}"
        docker images "$IMAGE_NAME:latest" --format "  ID: {{.ID}}\n  Size: {{.Size}}\n  Created: {{.CreatedAt}}"
    else
        echo -e "  Status: ${RED}Not built${NC}"
    fi
    echo ""
}

cmd_help() {
    print_banner
    echo -e "${BLUE}Usage:${NC} $0 [command]"
    echo ""
    echo -e "${BLUE}Commands:${NC}"
    echo "  (none)    Build image and run container interactively"
    echo "  build     Build the Docker image only"
    echo "  run       Run the container interactively"
    echo "  shell     Open a shell in the running container"
    echo "  stop      Stop the container"
    echo "  clean     Remove container and image"
    echo "  compose   Use docker-compose for development"
    echo "  logs      Show container logs"
    echo "  status    Show container and image status"
    echo "  help      Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo ""
    echo "  # Quick start - build and run interactively"
    echo -e "  ${CYAN}$0${NC}"
    echo ""
    echo "  # Development mode with live editing"
    echo -e "  ${CYAN}$0 compose${NC}"
    echo ""
    echo "  # Run a specific Python script"
    echo -e "  ${CYAN}docker run -v \$(pwd):/workspace $IMAGE_NAME python3 /workspace/my_script.py${NC}"
    echo ""
    echo "  # Run example in Nanos kernel"
    echo -e "  ${CYAN}docker run -it $IMAGE_NAME minops run /opt/authority-nanos/examples/test-python.py -m 512${NC}"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    check_docker

    case "${1:-}" in
        build)
            cmd_build
            ;;
        run)
            cmd_run
            ;;
        shell)
            cmd_shell
            ;;
        stop)
            cmd_stop
            ;;
        clean)
            cmd_clean
            ;;
        compose)
            cmd_compose
            ;;
        logs)
            cmd_logs
            ;;
        status)
            cmd_status
            ;;
        help|--help|-h)
            cmd_help
            ;;
        "")
            # Default: build and run
            cmd_build
            cmd_run
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            cmd_help
            exit 1
            ;;
    esac
}

main "$@"
