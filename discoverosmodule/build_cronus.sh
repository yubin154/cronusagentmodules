#!/bin/bash

rm -rf ./target
VER=${1:-0.0.1}
cat ~/Work/cronusagent/agent/scripts/cronus_package/package.sh | DIR=. appName=discoveros version=$VER platform=all bash
mkdir target
mv discoveros-$VER.all.cronus* ./target/
