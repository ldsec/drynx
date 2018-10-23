#!/usr/bin/env bash

./compileMac.sh

mkdir test

./drynx server setupNonInteractive --serverBinding "127.0.0.1:2000" --description "Drynx Server 1" \
        --privateTomlPath "test/srv1-private.toml" --publicTomlPath "test/srv1-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2010" --description "Drynx Server 2" \
        --privateTomlPath "test/srv2-private.toml" --publicTomlPath "test/srv2-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2020" --description "Drynx Server 3" \
        --privateTomlPath "test/srv3-private.toml" --publicTomlPath "test/srv3-public.toml"

cat test/srv*-public.toml > "test/groupServers.toml"

./drynx server setupNonInteractive --serverBinding "127.0.0.1:2100" --description "Drynx DP 1" \
        --privateTomlPath "test/dp1-private.toml" --publicTomlPath "test/dp1-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2110" --description "Drynx DP 2" \
        --privateTomlPath "test/dp2-private.toml" --publicTomlPath "test/dp2-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2120" --description "Drynx DP 3" \
        --privateTomlPath "test/dp3-private.toml" --publicTomlPath "test/dp3-public.toml"

cat test/dp*-public.toml > "test/groupDPs.toml"