#!/bin/bash
# This is a debug script
sudo valgrind --tool=memcheck --leak-check=full ./src/ziproxy -d -c ./test/ziproxy.conf

