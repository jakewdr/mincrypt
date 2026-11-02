set minimum-version := '1.55.0'

[windows]
set shell := ["powershell.exe", "-NoLogo", "-Command"]

test:
    go test -C ./src/
