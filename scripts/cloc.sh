#!/bin/bash

cloc . \
  --include-ext=go \
  --not-match-f='(\.gen|_test)\.go$'
