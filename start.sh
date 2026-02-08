#!/bin/sh

# Start the scanner in the background
./scanner &

# Start the Node.js application
node server.js
