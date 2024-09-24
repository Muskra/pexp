default:
	go build .
r:
	go run . --anomalies samples/7z2407-x64.exe
br:
	go build . && ./pexp -sections -entropy samples/7z2407-x64.exe
fmt:
	go fmt main.go
