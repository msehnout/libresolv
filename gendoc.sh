#!/bin/sh

cargo rustdoc -- --no-defaults --passes collapse-docs --passes unindent-comments
