#!/usr/bin/env bash

mkdir -p test

./drynx server setupNonInteractive --serverBinding "192.168.1.108:2100" --description "Drynx DP 1" \
        --privateTomlPath "test/dp1-private.toml" --publicTomlPath "test/dp1-public.toml"
./drynx server setupNonInteractive --serverBinding "192.168.1.108:2110" --description "Drynx DP 2" \
        --privateTomlPath "test/dp2-private.toml" --publicTomlPath "test/dp2-public.toml"
./drynx server setupNonInteractive --serverBinding "192.168.1.108:2120" --description "Drynx DP 3" \
        --privateTomlPath "test/dp3-private.toml" --publicTomlPath "test/dp3-public.toml"

cat test/dp*-public.toml > "test/groupDPs.toml"