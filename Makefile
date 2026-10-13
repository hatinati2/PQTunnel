.PHONY: test vet build build-server build-client build-pki shell-check android-aar

test:
	go test ./...

vet:
	go vet ./...

build: build-server build-client build-pki

build-server:
	mkdir -p dist
	go build -trimpath -o dist/pqtunneld ./cmd/pqtunneld

build-client:
	mkdir -p dist
	go build -trimpath -o dist/pqtunnel-client ./cmd/pqtunnel-client

build-pki:
	mkdir -p dist
	go build -trimpath -o dist/pqtunnel-pki ./cmd/pqtunnel-pki

shell-check:
	bash -n scripts/*.sh

# Requires gomobile plus Android SDK/NDK; the resulting AAR is not committed.
android-aar:
	mkdir -p android/app/libs
	gomobile bind -target=android -javapkg=org.pqtunnel -o android/app/libs/pqtunnel-mobile.aar ./mobile
