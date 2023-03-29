src_dir=$(shell pwd)
build_dir=${src_dir}/build
bin_dir=${build_dir}/bin
prog_name=promplus
pkg=cmd/main.go
go_cmd=go
repo=platform9
image_name=monhelper
version=v2.0.2
GOPATH=$(shell go env GOPATH)
TAG?=${repo}/${image_name}:${version}

SRC_ROOT=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))/)
BUILD_ROOT = $(SRC_ROOT)/build

.PHONY: all
all: test binary

.PHONY: clean
clean:
	rm -fr ${build_dir}

${build_dir}:
	mkdir -p ${build_dir}
	mkdir -p ${bin_dir}
	mkdir -p ${GOPATH}/src
	cp -r vendor/*  ${GOPATH}/src
	mkdir -p ${GOPATH}/src/github.com/platform9/prometheus-plus
	cp -r ./* ${GOPATH}/src/github.com/platform9/prometheus-plus/
	rm -rf ${GOPATH}/src/github.com/platform9/prometheus-plus/vendor

binary: ${build_dir}
	${go_cmd} build -o ${bin_dir}/${prog_name} ${pkg}

test:
	go test ./pkg/...

image: go_cmd = GOOS=linux GOARCH=amd64 go
image: binary
	docker build -t ${TAG} .

push: 
	docker push $(TAG) \
	&& docker rmi $(TAG)

scan: 
	mkdir -p $(BUILD_ROOT)/monhelper
	docker run -v $(BUILD_ROOT)/monhelper:/out -v /var/run/docker.sock:/var/run/docker.sock  aquasec/trivy image -s CRITICAL,HIGH -f json  --vuln-type library -o /out/library_vulnerabilities.json --exit-code 22 ${TAG}
	docker run -v $(BUILD_ROOT)/monhelper:/out -v /var/run/docker.sock:/var/run/docker.sock  aquasec/trivy image -s CRITICAL,HIGH -f json  --vuln-type os -o /out/os_vulnerabilities.json --exit-code 22 ${TAG}

