#!/bin/bash

# Clean first
make clean

# Create the output directories if they don't exist
mkdir -p ../../obj/musl_mutex
mkdir -p ../../lib

# Build the object files
make

# Check if all object files were created
echo "Checking for object files..."
ls -la *.o

# Display any errors during compilation
if [ $? -ne 0 ]; then
    echo "Error: Failed to build object files"
    exit 1
fi

echo "Build successful!" 