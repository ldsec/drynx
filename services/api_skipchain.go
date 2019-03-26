package services

import (
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/lca1/drynx/lib"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Send Query
//______________________________________________________________________________________________________________________

// SendSurveyQueryToVNs creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyQueryToVNs(entities *onet.Roster, query *libdrynx.SurveyQuery) error {
	for _, si := range entities.List {
		err := c.SendProtobuf(si, &libdrynx.SurveyQueryToVN{SQ: *query}, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// Wait for proofs' verification
//______________________________________________________________________________________________________________________

// SendEndVerification enables the querier to send a message to wait on the query verification
func (c *API) SendEndVerification(si *network.ServerIdentity, queryInfoID string) (*skipchain.SkipBlock, error) {
	evm := libdrynx.EndVerificationRequest{QueryInfoID: queryInfoID}
	reply := &libdrynx.Reply{}
	err := c.SendProtobuf(si, &evm, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil
}

// Skipchain utilities
//______________________________________________________________________________________________________________________

// SendGetLatestBlock requests the last known block of the skipchain
func (c *API) SendGetLatestBlock(roster *onet.Roster, sb *skipchain.SkipBlock) (*skipchain.SkipBlock, error) {
	if roster == nil {
		return nil, errors.New("No roster provided")
	}
	if sb == nil {
		return nil, errors.New("No block provided")
	}

	reply := &libdrynx.Reply{}
	err := c.SendProtobuf(roster.RandomServerIdentity(), &libdrynx.GetLatestBlock{Roster: roster, Sb: sb}, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil
}

// SendGetGenesis requests the genesis block
func (c *API) SendGetGenesis(toAsk *network.ServerIdentity) (*skipchain.SkipBlock, error) {
	reply := &libdrynx.Reply{}
	err := c.SendProtobuf(toAsk, &libdrynx.GetGenesis{}, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil
}

// SendGetBlock requests the block for a specific query
func (c *API) SendGetBlock(entities *onet.Roster, surveyID string) (*skipchain.SkipBlock, error) {
	reply := &libdrynx.Reply{}
	err := c.SendProtobuf(entities.List[0],
		&libdrynx.GetBlock{ID: surveyID, Roster: entities}, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil

}

// DB utilities
//______________________________________________________________________________________________________________________

// SendGetProofs requests proofs for a specific query
func (c *API) SendGetProofs(serverID *network.ServerIdentity, surveyID string) (map[string][]byte, error) {
	result := libdrynx.ProofsAsMap{}

	err := c.SendProtobuf(serverID, &libdrynx.GetProofs{ID: surveyID}, &result)
	if err != nil {
		return nil, err
	}

	return result.Proofs, err
}

// SendCloseDB requests the closure of the DB of some nodes
func (c *API) SendCloseDB(entities *onet.Roster, request *libdrynx.CloseDB) error {
	for i := range entities.List {
		err := c.SendProtobuf(entities.List[len(entities.List)-i-1], request, nil)
		if err != nil {
			log.Fatal("Error while closing DB", err)
		}
	}
	return nil
}
