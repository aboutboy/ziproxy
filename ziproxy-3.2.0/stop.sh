#!/bin/bash
# This is a debug script
sudo src/ziproxy -k -c test/ziproxy.conf
ps -ef |grep ziproxy
#sudo rm logs/*
