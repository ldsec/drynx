package services

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/protocols"
)

// Query Handlers
//______________________________________________________________________________________________________________________

func (s *ServiceLeMal) HandleSurveyQueryToDP(recq *lib.SurveyQueryToDP) (network.Message, error) {

	recq.SQ.Query.IVSigs.InputValidationSigs = recreateRangeSignatures(recq.SQ.Query.IVSigs)

	// only generate ProofCollection protocol instances if proofs is enabled
	var mapPIs map[string]onet.ProtocolInstance
	if recq.SQ.Query.Proofs != 0 {
		mapPIs = s.generateRangePI(recq)
	}

	s.Survey.Put(recq.SQ.SurveyID, Survey{
		SurveyQuery: recq.SQ,
		MapPIs:      mapPIs,
	})

	// signal the root that the data provider has received the query
	err := s.SendRaw(recq.Root, &DPqueryReceived{recq.SQ.SurveyID})
	if err != nil {
		log.Error("[SERVICE] <LEMAL> Server, broadcasting [DPdataFinished] error ", err)
	}

	return nil, nil
}

// Support Functions
//______________________________________________________________________________________________________________________

func (s *ServiceLeMal) generateRangePI(query *lib.SurveyQueryToDP) map[string]onet.ProtocolInstance {
	mapPIs := make(map[string]onet.ProtocolInstance)
	for _, dp := range *query.SQ.ServerToDP[query.Root.String()] {
		if dp.String() == s.ServerIdentity().String() {
			tree := generateProofCollectionRoster(&dp, query.SQ.Query.RosterVNs).GenerateStar()

			pi := s.CreateProofCollectionPIs(tree, query.SQ.SurveyID, protocols.ProofCollectionProtocolName)
			mapPIs["range/"+s.ServerIdentity().String()] = pi
			break
		}

	}

	return mapPIs

}
