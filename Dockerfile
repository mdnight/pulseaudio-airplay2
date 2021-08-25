FROM ghcr.io/mdnight/pulseaudio-env:latest

RUN mkdir /project/airplay

COPY . /project/airplay

WORKDIR /project
