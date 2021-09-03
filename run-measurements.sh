#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

MONDAY_DATE=$(date -dlast-monday +%d-%m-%Y)

IN_FILE=../zmap/results/${MONDAY_DATE}-verified.csv

[ ! -e sqlite.db ] || rm -f sqlite.db

sudo ./main tcpfastopen -infile $IN_FILE -p 10
sudo ./main edns -infile $IN_FILE -p 10
sudo ./main 0rtt -infile $IN_FILE -p 10
sudo ./main cert-tls -infile $IN_FILE -p 10
sudo ./main cert-https -infile $IN_FILE -p 10
sudo ./main cert-quic -infile $IN_FILE -p 10
sudo ./main quic-version -infile $IN_FILE -p 10

mkdir -p results
mv sqlite.db results/${MONDAY_DATE}-final.db 2>/dev/null || true