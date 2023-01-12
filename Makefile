src_dir=$(shell pwd)
build_dir=${src_dir}/build
bin_dir=${build_dir}/bin
prog_name=promplus
pkg=cmd/main.go
go_cmd=go
repo=platform9
version=v3.0.1

#registry_url ?= 514845858982.dkr.ecr.us-west-1.amazonaws.com
registry_url ?= docker.io

image_name = ${registry_url}/platform9/monhelper
image_tag = $(version)-pmk-$(TEAMCITY_BUILD_ID)

SRC_ROOT=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))/)
BUILD_ROOT = $(SRC_ROOT)/build

TAG=$(image_name):${image_tag}

.PHONY: all
all: test binary

.PHONY: clean
clean:
	rm -fr ${build_dir}

${build_dir}:
	mkdir -p ${build_dir}
	mkdir -p ${bin_dir}

binary: ${build_dir}
	${go_cmd} build -o ${bin_dir}/${prog_name} ${pkg}

test:
	go test ./pkg/...

image:
	@echo $(TAG)
	docker build -t $(TAG) .

push:
	docker push $(TAG) \
	&& docker rmi $(TAG)

scan: 
	mkdir -p $(BUILD_ROOT)
	docker run -v $(BUILD_ROOT)/monhelper:/out -v /var/run/docker.sock:/var/run/docker.sock  aquasec/trivy image -s CRITICAL,HIGH -f json  --vuln-type library -o /out/library_vulnerabilities.json --exit-code 22 ${TAG}
	docker run -v $(BUILD_ROOT)/monhelper:/out -v /var/run/docker.sock:/var/run/docker.sock  aquasec/trivy image -s CRITICAL,HIGH -f json  --vuln-type os -o /out/os_vulnerabilities.json --exit-code 22 ${TAG}
