#!/bin/bash

# Ghidra Headless Web Analyzer Deployment Script
# 
# This script helps deploy the web analyzer either standalone or as part of Ghidra build

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
MODULE_NAME="HeadlessWebAnalyzer"

echo "🚀 Deploying Ghidra Headless Web Analyzer"
echo "Module: $MODULE_NAME"
echo "Ghidra Root: $GHIDRA_ROOT"
echo

# Function to print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --build-only     Only build the module, don't run"
    echo "  --run-only       Only run (assumes already built)"
    echo "  --port PORT      Specify port (default: 8080)"
    echo "  --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build and run on port 8080"
    echo "  $0 --port 9090       # Build and run on port 9090"
    echo "  $0 --build-only      # Only build the module"
    echo "  $0 --run-only        # Only run (assumes built)"
}

# Parse command line arguments
BUILD_ONLY=false
RUN_ONLY=false
PORT=8080

while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --run-only)
            RUN_ONLY=true
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Build function
build_module() {
    echo "📦 Building module..."
    cd "$GHIDRA_ROOT"
    
    # Try to build just our module
    if ./gradlew ":$MODULE_NAME:build" 2>/dev/null; then
        echo "✅ Module built successfully"
    else
        echo "⚠️  Full Gradle build not available, checking manual build..."
        
        # Check if we have the required dependencies manually
        if [ -d "$SCRIPT_DIR/build/libs" ]; then
            echo "✅ Build artifacts found"
        else
            echo "❌ Build failed - dependencies may need to be fetched first"
            echo "Run: ./gradlew -I gradle/support/fetchDependencies.gradle"
            return 1
        fi
    fi
}

# Run function  
run_module() {
    echo "🌐 Starting Ghidra Headless Web Analyzer on port $PORT..."
    
    cd "$SCRIPT_DIR"
    
    # Check if we have built artifacts
    if [ -d "build/libs" ] && [ -n "$(find build/libs -name "*.jar" 2>/dev/null)" ]; then
        # Run with built JAR
        CLASSPATH=$(find build/libs -name "*.jar" | tr '\n' ':')
        java -cp "$CLASSPATH" ghidra.features.headlessweb.MalwareAnalysisWebApp "$PORT"
    else
        # Try to run with source files (for development)
        echo "📝 Running in development mode (no JAR found)"
        echo "To build properly, run: ./gradlew :$MODULE_NAME:build"
        echo ""
        echo "🌐 Web interface would be available at: http://localhost:$PORT"
        echo "📚 See README.md for detailed API documentation"
        echo ""
        echo "Example usage:"
        echo "  curl -X POST -F \"file=@malware.exe\" http://localhost:$PORT/api/analyze/file"
        echo "  curl http://localhost:$PORT/api/workflows"
        echo "  curl http://localhost:$PORT/api/malware/categories"
    fi
}

# Main execution
main() {
    if [ "$RUN_ONLY" = false ]; then
        build_module || {
            echo "❌ Build failed"
            exit 1
        }
    fi
    
    if [ "$BUILD_ONLY" = false ]; then
        run_module
    fi
}

# Run main function
main