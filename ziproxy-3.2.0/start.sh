#!/bin/bash
# This is a debug script
sudo src/ziproxy -d -c test/ziproxy.conf
sudo lsof -i:8000
