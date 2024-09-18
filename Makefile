default:
	go build .
r:
	go run . --anomalies 7z2407-x64.exe
br:
	go build . && ./pexp 7z2407-x64.exe
fmt:
	go fmt main.go
