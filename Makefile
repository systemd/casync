# Tiny stub file Makefile, to make editors which only know make be able to build ninja

all:
	test -e build || meson build
	ninja -C build

clean:
	rm -rf build
