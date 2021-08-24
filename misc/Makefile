##
# Pulseaudio dev makefile
#
# @file
# @version 0.1

image = pulseaudio-playground
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

init:
	docker build -t $(image) .

meson:
	docker run --rm -v $(mkfile_dir):/project $(image) meson ninja

ninja-reconfigure:
	docker run --rm -v $(mkfile_dir):/project $(image) ninja -C ninja reconfigure

ninja-build:
	docker run --rm -v $(mkfile_dir):/project $(image) ninja -C ninja

# end
