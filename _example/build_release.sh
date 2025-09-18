export LDFLAGS='-s -w '

CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o definger_linux_x86_64 main.go && upx -9 definger_linux_x86_64
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o definger_linux_arm64 main.go && upx -9 definger_linux_arm64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o definger_windows_x86_64.exe  main.go && upx -9 definger_windows_x86_64.exe
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o definger_windows_arm64.exe  main.go && upx -9 definger_windows_arm64.exe
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o definger_darwin_x86_64  main.go && upx -9 definger_darwin_x86_64
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o definger_darwin_arm64  main.go && upx -9 definger_darwin_arm64
