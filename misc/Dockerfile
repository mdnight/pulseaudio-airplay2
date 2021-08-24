FROM archlinux:latest

RUN pacman -Sy --noconfirm
RUN pacman -S --noconfirm check meson doxygen gcc git cmake  sbc  vala  tdb  libsndfile  libxtst  m4  libxml2  perl-xml-libxml  libxmlbird perl-xml-parser

WORKDIR /project

RUN git clone https://gitlab.freedesktop.org/pulseaudio/pulseaudio.git
