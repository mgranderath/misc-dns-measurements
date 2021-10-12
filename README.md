# Misc DNS Measurements

This repository holds the tooling to collect the miscellaneous DNS measurements

## Build

```shell
go build main.go
```

## Run

Depending on the ports

```shell
./run-measurements.sh
```

or

```shell
./run-measurements_2.sh
``` 

## Merge results

```shell
python final-result merge_db.py <folder>
```

The result will be a file called `merged.db` in <folder>