#!/bin/bash

rm -rf ./target
VER=${1:-0.0.1}
curl -sS https://raw.githubusercontent.com/yubin154/cronuspackages/master/common_scripts/package.sh | DIR=. appName=sysmetrics version=$VER platform=all bash
mkdir target
mv sysmetrics-$VER.all.cronus* ./target/
