#!/usr/bin/env bash
export LC_ALL=C
set -e
docker build --no-cache -t bitcoincashnode/buildenv:debian-v6 .
#docker push bitcoincashnode/buildenv:debian-v6
