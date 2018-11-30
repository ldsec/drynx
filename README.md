[![Build Status](https://travis-ci.org/lca1/drynx.svg?branch=master)](https://travis-ci.org/lca1/drynx) [![Go Report Card](https://goreportcard.com/badge/github.com/lca1/drynx)](https://goreportcard.com/report/github.com/lca1/drynx) [![Coverage Status](https://coveralls.io/repos/github/lca1/drynx/badge.svg?branch=master)](https://coveralls.io/github/lca1/drynx?branch=master)
# Drynx
Drynx is a library for simulating a privacy-preserving and verifiable data sharing/querying tool. It offers a series of independent protocols that when combined offer a verifiably-secure and safe way to compute statistics and train basic machine learning models on distributed sensitive data (e.g., medical data).

Drynx is developed by lca1 (Laboratory for Communications and Applications in EPFL) in collaboration with DeDiS (Laboratory for Decentralized and Distributed Systems). It is build on the [UnLynx library](https://github.com/lca1/unlynx) and does an intensive use of [Overlay-network (ONet) library](https://github.com/dedis/onet) and of the [Advanced Crypto (kyber) library](https://github.com/dedis/kyber).

## Documentation

* For more information regarding the underlying architecture please refer to the stable version of ONet `github.com/dedis/onet`
* To check the code organisation, have a look at [Layout](https://github.com/lca1/drynx/wiki/Layout)
* For more information on how to run our protocols, services, simulations and apps, go to [Running Drynx](https://github.com/lca1/drynx/wiki/Running-Drynx)

## Getting Started

To use the code of this repository you need to:

- Install [Golang](https://golang.org/doc/install)
- [Recommended] Install [IntelliJ IDEA](https://www.jetbrains.com/idea/) and the GO plugin
- Set [`$GOPATH`](https://golang.org/doc/code.html#GOPATH) to point to your workspace directory
- Add `$GOPATH/bin` to `$PATH`
- Git clone this repository to $GOPATH/src `git clone https://github.com/lca1/drynx.git` or...
- go get repository: `go get github.com/lca1/drynx`
- **When building use the "-tags vartime" argument to enable the use of the bn256 pairing curve**

## Version

The version in the `master`-branch is stable for simulation and test purposes and has no incompatible changes.

## License

Drynx is licensed under a End User Software License Agreement ('EULA') for non-commercial use. If you need more information, please contact us.

## Contact
You can contact any of the developers for more information or any other member of [lca1](http://lca.epfl.ch/people/lca1/):

* [David Froelicher](https://github.com/froelich) (PHD student) - david.froelicher@epfl.ch
* [Joao Andre Sa](https://github.com/JoaoAndreSa) (Software Engineer) - joao.gomesdesaesousa@epfl.ch

