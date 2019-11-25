# Commands

`/cmd/*` are the executable of the CLI interface.
There is two of theses, `client` and `server`, the former connecting to a
running instance of the latter.

One specificities of theses tools are that they need a lot of configuration.
To allow for easier and reproducable configuration, theses are using stdin and
stdout to read and write the updated config.

## Server

A server can run different flavors, listed below
 * a Data Provider is providing data so that other can query and compute on it
 * a Computing Node is a Client entrypoint, querying on its behalf and
   returning the encrypted result
 * a Verifying Node is ensuring correct query execution and logging what
   happened

If you want to generate a server config, use something like

```sh
server new {1,2}.drynx.c4dt.org |
	server data-provider new file-loader $my_data |
	server computing-node new |
	server verifying-node new >
	$my_node_config
```

Then, you can run the given server

```sh
cat $my_node_config | server run

```

## Client

A client's main purpose is to generate and send a survey to the servers.

If you want to generate a network config, use something like

```sh
client network new |
	client network add-node 1.drynx.c4dt.org 1234abc |
	client network set-client 2.drynx.c4dt.org 5678def >
	$my_network_config
```

If you want to generate a survey config, use something like

```sh
client survey new my-survey |
	client survey set-sources my-column |
	client survey set-operation mean >
	$my_survey_config
```

Then, you can launch a given survey on a given network

```sh
cat $my_network_config $my_survey_config |
	client survey new run
```
