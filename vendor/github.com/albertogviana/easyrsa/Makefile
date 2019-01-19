.PHONY: download-easyrsa
download-easyrsa:
	wget "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.5/EasyRSA-nix-3.0.5.tgz" -O /tmp/EasyRSA-nix-3.0.5.tgz;
	tar -xf /tmp/EasyRSA-nix-3.0.5.tgz -C /tmp;
	mv /tmp/EasyRSA-3.0.5 /tmp/easy-rsa;

.PHONY: download-testify
download-testify:
	go get -u github.com/stretchr/testify

.PHONY: test
test:
	GOCACHE=off go test -race -v -cover -coverprofile=coverage.out ./...
