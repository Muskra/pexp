default:
	go build .
r:
	go run . 7z2407-x64.exe
br:
	go build . && ./impexp 7z2407-x64.exe
