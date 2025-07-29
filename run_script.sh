#!/bin/bash

# Activate virtual environment and run the script
source venv/bin/activate
/Users/mkbn/Public/AOS-manual-snapshot-automation/venv/bin/python create_iam_resources.py "$@"