set -eumo pipefail

readonly node_count=3
readonly host_name=localhost

trap cleanup EXIT QUIT
cleanup() {
	local err=$?
	local pid

	for pid in $nodes
	do
		kill -9 $pid
	done

	for pid in $nodes
	do
		set +e
		wait $pid 2>/dev/null
		local ret=$?
		set -e

		if [ $ret -ne 137 ]
		then
			err=$ret
		fi
	done

	exit $err
}

readonly port_base=$((RANDOM + 1024))
readonly port_top=$((port_base + 2*node_count - 1))
nodes=''
publics=''
start_nodes() {
	[ -n "$nodes" ] && ( echo nodes already started; exit 1 )

	local port

	for port in $(seq $port_base 2 $port_top)
	do
		local conf=$(server gen $host_name:{$port,$((port+1))})
		publics+=" $(echo "$conf" | awk -F \" '/^Public\s*=/ {print $2}')"

		echo "$conf" | DEBUG_COLOR=true server run &
		nodes+=" $!"
	done

	for port in $(seq $port_base $port_top)
	do
		while ! nc -q 0 localhost $port < /dev/null
		do
			sleep 0.1
		done
	done
}

get_nodes() {
	[ -z "$nodes" ] && ( echo asking roster of stopped nodes; exit 1 )

	local port=$port_base
	for public in $publics
	do
		echo $host_name:$port $public
		: $((port += 2))
	done
}

get_client() {
	[ -z "$nodes" ] && ( echo asking for client to stopped nodes; exit 1 )

	echo $host_name:$((port_base+1))
}

client_gen_network() {
	local pipe=$(
		echo -n client network new
		for n in $(get_nodes | tr ' ' ,)
		do
			echo -n " | client network add-node $(echo $n | tr , ' ')"
		done
		echo -n " | client network set-client $(get_client)"
	)
	eval "$pipe"
}
