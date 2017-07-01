#!/bin/bash
echo "Insecuring system to run PoCs"
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
