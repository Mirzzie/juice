#!/bin/bash
apt-get update
apt-get install -y docker.io
usermod -aG docker ubuntu
