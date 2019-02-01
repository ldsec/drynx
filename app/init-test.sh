#!/usr/bin/env bash
bash compileMac.sh
mkdir -p test

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
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2130" --description "Drynx DP 4" \
        --privateTomlPath "test/dp4-private.toml" --publicTomlPath "test/dp4-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2140" --description "Drynx DP 5" \
        --privateTomlPath "test/dp5-private.toml" --publicTomlPath "test/dp5-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2150" --description "Drynx DP 6" \
        --privateTomlPath "test/dp6-private.toml" --publicTomlPath "test/dp6-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2160" --description "Drynx DP 7" \
        --privateTomlPath "test/dp7-private.toml" --publicTomlPath "test/dp7-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2170" --description "Drynx DP 8" \
        --privateTomlPath "test/dp8-private.toml" --publicTomlPath "test/dp8-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2180" --description "Drynx DP 9" \
        --privateTomlPath "test/dp9-private.toml" --publicTomlPath "test/dp9-public.toml"
cat test/dp*-public.toml > "test/groupDPs.toml"


./drynx server setupNonInteractive --serverBinding "127.0.0.1:2200" --description "Drynx VN 1" \
        --privateTomlPath "test/vn1-private.toml" --publicTomlPath "test/vn1-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2210" --description "Drynx VN 2" \
        --privateTomlPath "test/vn2-private.toml" --publicTomlPath "test/vn2-public.toml"
./drynx server setupNonInteractive --serverBinding "127.0.0.1:2220" --description "Drynx VN 3" \
        --privateTomlPath "test/vn3-private.toml" --publicTomlPath "test/vn3-public.toml"
cat test/vn*-public.toml > "test/groupVNs.toml"