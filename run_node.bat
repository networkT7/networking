@echo off
cd /d %~dp0
set PYTHONPATH=src
venv\Scripts\python src\main.py node %1
REM usage: run_node.bat N1