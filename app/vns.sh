#!/usr/bin/env bash
./drynx server setupNonInteractive --serverBinding "10.90.39.21:2000" --description "Drynx VN 1" \
        --privateTomlPath "test/vn1-private.toml" --publicTomlPath "test/vn1-public.toml"
./drynx server setupNonInteractive --serverBinding "10.90.39.22:2000" --description "Drynx VN 2" \
        --privateTomlPath "test/vn2-private.toml" --publicTomlPath "test/vn2-public.toml"
./drynx server setupNonInteractive --serverBinding "10.90.39.23:2000" --description "Drynx VN 3" \
        --privateTomlPath "test/vn3-private.toml" --publicTomlPath "test/vn3-public.toml"
cat test/vn*-public.toml > "test/groupVNs.toml"