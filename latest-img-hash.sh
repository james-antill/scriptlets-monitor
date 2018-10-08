#! /bin/sh -e

docker images -q "$1" | head -1
