#!/bin/sh
set -e
python bootstrap.py
exec uvicorn main:app --host 0.0.0.0 --port 8000
