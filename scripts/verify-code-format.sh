#!/usr/bin/env bash

GO_FILES=$(find . -path ./vendor -prune -o -name '*.go' -print)

FILES=$(gofmt -s -l $GO_FILES)

if [[ -n "$FILES" ]]; then
    echo "gofmt errors found, please run:"
    echo " gofmt -s -w $FILES"
    exit 1
fi

if hash goimports 2>/dev/null; then
    FILES=$(goimports -e -l -local=github.com/guardtime/goksi $GO_FILES)

    if [[ -n "$FILES" ]]; then
        echo "goimports errors found, please run:"
        echo " goimports -e -w -local=github.com/guardtime/goksi $FILES"
        exit 1
    fi
else
    echo >&2 "Skipping goimports since it is not installed."
fi
