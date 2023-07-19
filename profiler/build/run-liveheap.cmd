@echo on

dotnet tool update -g timeitsharp --version 0.0.10

:: remove DOTNET_ROOT environment variable to ensure we can run
:: the benchmark in x64 and x86
set DOTNET_ROOT=

:: Run x64
dotnet timeit LiveHeap.windows.x64.json

:: Run x86
dotnet timeit LiveHeap.windows.x86.json

