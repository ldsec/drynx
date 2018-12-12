#!/usr/bin/env bash

bash compileMac.sh

mkdir -p test

./drynx server setupNonInteractive --serverBinding "192.168.1.108:2000" --description "Drynx Server 1" \
        --privateTomlPath "test/srv1-private.toml" --publicTomlPath "test/srv1-public.toml"
./drynx server setupNonInteractive --serverBinding "192.168.1.108:2010" --description "Drynx Server 2" \
        --privateTomlPath "test/srv2-private.toml" --publicTomlPath "test/srv2-public.toml"
./drynx server setupNonInteractive --serverBinding "192.168.1.108:2020" --description "Drynx Server 3" \
        --privateTomlPath "test/srv3-private.toml" --publicTomlPath "test/srv3-public.toml"

cat test/srv*-public.toml > "test/groupServers.toml"

./drynx server setupNonInteractive --serverBinding "192.168.1.108:2200" --description "Drynx VN 1" \
        --privateTomlPath "test/vn1-private.toml" --publicTomlPath "test/vn1-public.toml"
./drynx server setupNonInteractive --serverBinding "192.168.1.108:2210" --description "Drynx VN 2" \
        --privateTomlPath "test/vn2-private.toml" --publicTomlPath "test/vn2-public.toml"
./drynx server setupNonInteractive --serverBinding "192.168.1.108:2220" --description "Drynx VN 3" \
        --privateTomlPath "test/vn3-private.toml" --publicTomlPath "test/vn3-public.toml"

cat test/vn*-public.toml > "test/groupVNs.toml"