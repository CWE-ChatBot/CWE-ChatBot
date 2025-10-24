#!/bin/sh

# This assumes there's a file called `urls.txt` in the current directory
docker run --rm -v ./:/app/ projectdiscovery/nuclei -l /app/urls.txt -jsonl /app/results.jsonl

# To write the templates and configs locally 
#docker run --rm -u $(id -u):$(id -g) -v ./:/app/ -e HOME=/app/ projectdiscovery/nuclei \
#  -l /app/urls.txt -jsonl /app/results.jsonl
# The results will be written to `./results.jsonl` on the host machine once the container has completed