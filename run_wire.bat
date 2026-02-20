@echo off
cd /d %~dp0
set PYTHONPATH=src
venv\Scripts\python src\main.py wire 0