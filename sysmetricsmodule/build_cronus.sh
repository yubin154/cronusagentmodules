#!/bin/bash

rm -rf ./target
VER=${1:-0.0.1}
curl -sS http://www.stackscaling.com/downloads/package_cronus | DIR=. appname=sysmetrics version=$VER platform=all bash
mkdir target
mv sysmetrics-$VER.all.cronus* ./target/
