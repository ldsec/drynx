package services

import (
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
)

// Send Query
//______________________________________________________________________________________________________________________

// SendSurveyQueryToVNs creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyQueryToVNs(entities *onet.Roster, query *lib.SurveyQuery) error {
	for _, si := range entities.List {
		err := c.SendProtobuf(si, &lib.SurveyQueryToVN{SQ: *query}, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// Wait for proofs' verification
//______________________________________________________________________________________________________________________

func (c *API) SendEndVerification(si *network.ServerIdentity, queryInfoID string) (*skipchain.SkipBlock, error) {
	evm := lib.EndVerificationRequest{QueryInfoID: queryInfoID}
	reply := &lib.Reply{}
	err := c.SendProtobuf(si, &evm, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil
}

// Skipchain utilities
//______________________________________________________________________________________________________________________

func (c *API) SendGetLatestBlock(roster *onet.Roster, sb *skipchain.SkipBlock) (*skipchain.SkipBlock, error) {
	if roster == nil {
		return nil, errors.New("No roster provided")
	}
	if sb == nil {
		return nil, errors.New("No block provided")
	}

	reply := &lib.Reply{}
	err := c.SendProtobuf(roster.RandomServerIdentity(), &lib.GetLatestBlock{Roster: roster, Sb: sb}, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil
}

func (c *API) SendGetGenesis(toAsk *network.ServerIdentity) (*skipchain.SkipBlock, error) {
	reply := &lib.Reply{}
	err := c.SendProtobuf(toAsk, &lib.GetGenesis{}, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil
}

func (c *API) SendGetBlock(entities *onet.Roster, surveyID string) (*skipchain.SkipBlock, error) {
	reply := &lib.Reply{}
	err := c.SendProtobuf(entities.List[0],
		&lib.GetBlock{ID: surveyID, Roster: entities}, reply)
	if err != nil {
		return nil, err
	}
	return reply.Latest, nil

}

// DB utilities
//______________________________________________________________________________________________________________________

func (c *API) SendGetProofs(serverID *network.ServerIdentity, surveyID string) (map[string][]byte, error) {
	result := lib.ProofsAsMap{}

	err := c.SendProtobuf(serverID, &lib.GetProofs{ID: surveyID}, &result)
	if err != nil {
		return nil, err
	}

	return result.Proofs, err
}

func (c *API) SendCloseDB(entities *onet.Roster, request *lib.CloseDB) error {
	for i := range entities.List {
		err := c.SendProtobuf(entities.List[len(entities.List)-i-1], request, nil)
		if err != nil {
			log.Fatal("Error while closing DB", err)
		}
	}
	return nil
}
