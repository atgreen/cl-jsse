#!/bin/sh
# Generate the throwaway self-signed server identity the handshake spikes use.
# No private key is committed to the repo, so run this once before the spikes:
#
#   JAVA_HOME=/path/to/jdk-25 sh spikes/gen-test-keystore.sh
#
# (The test suite generates its own ephemeral keystore and does not need this.)
set -e
dir=$(dirname "$0")
out="$dir/server.p12"
keytool="${JAVA_HOME:?set JAVA_HOME to a JDK}/bin/keytool"
rm -f "$out"
"$keytool" -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=localhost" -keystore "$out" -storetype PKCS12 \
  -storepass changeit -keypass changeit
echo "wrote $out"
