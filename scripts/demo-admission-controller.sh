#!/bin/bash

# Example script showing how to use the Spotter admission controller

set -e

echo "🚀 Spotter Admission Controller Demo"
echo "===================================="

# Check prerequisites
echo "📋 Checking prerequisites..."
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl."
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Build the project
echo "🔨 Building Spotter..."
go build -o spotter .

# Test server command
echo "🧪 Testing server command..."
./spotter server --help | head -5

# Clean up binary
rm -f spotter

echo ""
echo "📝 Next Steps:"
echo "1. Generate TLS certificates: make -f Makefile.admission generate-certs"
echo "2. Build Docker image: make -f Makefile.admission build"
echo "3. Push to registry: make -f Makefile.admission push REGISTRY=your-registry"
echo "4. Deploy admission controller: make -f Makefile.admission deploy"
echo "5. Deploy webhook config: make -f Makefile.admission deploy-webhook"
echo "6. Test with: make -f Makefile.admission test-validating"
echo ""
echo "🔍 For detailed instructions, see: docs/admission-controller.md"
echo ""
echo "✨ Admission controller setup is ready!"
