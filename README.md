# ZephyrMiner-Remover
A quick remover for ZephyrMiner malware written in Go
- Checks if device has been infected with ZephyrMiner malware
- Disables ZephyerMiner services
- Remove dropped mining files
- Clear windows defender excluded files
## Download prebuilt remover
Executable file build for x64 systems ready to download in the releases section : https://github.com/r0ttenbeef/ZephyrMiner-Remover/releases/download/ZephyrRemover/zephyrminer-remover.exe
Open cmd command prompt with administrator privileges and run `.\zephyerminer-remover.exe` remover program.

## Compilation steps
Download Go from the official website and clone the project then start to compile the remover using the following commands:
```bash
go get -v .
```

Build for 32bit architectures:
```bash
GOOS=windows GOARCH=386 go build -v .
```

Build for 64bit architectures:
```bash
GOOS=windows GOARCH=386 go build -v .
```
