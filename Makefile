src_dir=$(shell pwd)
build_dir=${src_dir}/build
bin_dir=${build_dir}/bin
prog_name=monhelper
pkg=cmd/main.go
go_cmd=go
repo=platform9
image_name=monhelper

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
	${go_cmd} test ./pkg/...

image: go_cmd = GOOS=linux GOARCH=amd64 go

image: test binary
	docker build -t ${repo}/${image_name} .

