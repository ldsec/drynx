This readme is about the Drynx App, that is used to run Drynx nodes and execute queries in the system.

In order to execute a query using the Drynx App, the following steps are taken:

1) Compile the Drynx app binary. For MAC for example, use "go build -tags vartime -o drynx *.go".

2) Generate the different individual and group toml files (public and private keys) for the Drynx data providers (DPs), computing nodes (CNs), and verifying nodes (VNs). This can be done by executing the script init_test.sh. Also make sure to correctly set the IPs in the script (depending on the IPs of your machine(s)).

3) Run the different Drynx nodes (DPs, CNs, and VNs) using the following command:
.\drynx server -c `TOML_FILE`.toml -db `databasePath` -tb `tableName`

where
- TOML_FILE: toml file corresponding to the private key of the node that you are trying to run (DP, CN, or VN).
- databasePath: path of the local database name at the data provider
- tableName: name of table that exists in the local database name at the data provider

We should note here that the "db" and "table" flags are only used when runnning Drynx DPs, and not CNs and VNs (can be left blank in this case)

4) Execute the query in the system by running the following command:
./drynx run -o `operationName` -d `ID1,ID2,...,IDn` -a `A1,A2,...,Ak` -m `min` -M `max` -p `b` -t `nbrTrials`

where
- operationName: name of operation to be run.
- ID1,ID2,...,IDn: list (comma-separated concatenation) of IDs of the DPs over which the query should be run. e.g. -d 0,2,5 means that the query should be run over DP0, DP2, and DP5.
- A1,A2,...,Ak: list (comma-separated concatenation) of query attributes over which the operation should be executed.
- min: minimum value of query attributes, i.e., all data samples at the DPs having attribute values < min are discarded.
- max: maximum value of query attributes, i.e., all data samples at the DPs having attribute values > max are discarded.
- b: boolean variable. If b = 1, then proofs are generated (by DPs and CNs) and verified (by VNs). If b = 0, proofs are neither generated nor verified.
- nbrTrials: this field is only used for the logistic regression operation. It indicates the total number of trials over which we train (and evaluate) the logistic regression model. In other words, nbrTrials is the number of times the logistic regression operation is executed.

5) Read the query results on the terminal. They can also found in the "History" table of SQLite database "Stats.db".