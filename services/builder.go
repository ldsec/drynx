package services

import (
	"sync"

	"github.com/fanliao/go-concurrentMap"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	onet_network "go.dedis.ch/onet/v3/network"

	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/provider"
	"github.com/ldsec/drynx/protocols"
)

type builderDataProvider struct {
	loader provider.Loader
}

// Builder is the state of node creation.
type Builder struct {
	dataProvider *builderDataProvider
}

// NewBuilder allow to create a node.
func NewBuilder() Builder {
	return Builder{}
}

// WithComputingNode add support for running as a Computing Node.
func (b Builder) WithComputingNode() Builder {
	// TODO split
	msgTypes.msgSurveyQuery = onet_network.RegisterMessage(&libdrynx.SurveyQuery{})
	msgTypes.msgSurveyQueryToDP = onet_network.RegisterMessage(&libdrynx.SurveyQueryToDP{})
	msgTypes.msgDPqueryReceived = onet_network.RegisterMessage(&DPqueryReceived{})
	msgTypes.msgSyncDCP = onet_network.RegisterMessage(&SyncDCP{})
	msgTypes.msgDPdataFinished = onet_network.RegisterMessage(&DPdataFinished{})

	onet_network.RegisterMessage(&libdrynx.SurveyQueryToVN{})
	onet_network.RegisterMessage(&libdrynx.ResponseDP{})

	onet_network.RegisterMessage(&libdrynx.EndVerificationRequest{})

	onet_network.RegisterMessage(libdrynx.DataBlock{})
	onet_network.RegisterMessage(&libdrynx.GetLatestBlock{})
	onet_network.RegisterMessage(&libdrynx.GetGenesis{})
	onet_network.RegisterMessage(&libdrynx.GetBlock{})
	onet_network.RegisterMessage(&libdrynx.GetProofs{})
	onet_network.RegisterMessage(&libdrynx.CloseDB{})
	return b
}

// WithDataProvider add support for running as a Data Provider.
func (b Builder) WithDataProvider(loader provider.Loader) Builder {
	onet_network.RegisterMessage(protocols.AnnouncementDCMessage{})
	onet_network.RegisterMessage(protocols.DataCollectionMessage{})

	dcp := protocols.NewDataCollectionProtocol(loader)
	_, err := onet.GlobalProtocolRegister(protocols.DataCollectionProtocolName, dcp.ProtocolRegister)
	if err != nil {
		log.Fatal("Error registering <DataCollectionProtocol>:", err)
	}

	b.dataProvider = &builderDataProvider{loader}
	return b
}

// WithVerifyingNode add support for running as a Verifying Node.
func (b Builder) WithVerifyingNode() Builder {
	return b
}

// Start actually starts the node. You still have to start the onet server.
func (b Builder) Start() {
	var loader provider.Loader
	if b.dataProvider != nil {
		loader = b.dataProvider.loader
	}

	_, err := onet.RegisterNewService(ServiceName, func(c *onet.Context) (onet.Service, error) {
		newDrynxInstance := &ServiceDrynx{
			ServiceProcessor: onet.NewServiceProcessor(c),
			Survey:           concurrent.NewConcurrentMap(),
			Mutex:            &sync.Mutex{},
			loader:           loader,
		}

		registerHandler := func(handler interface{}) {
			if err := newDrynxInstance.RegisterHandler(handler); err != nil {
				log.Fatal("[SERVICE] <drynx> Server, Wrong Handler.", err)
			}
		}

		registerHandler(newDrynxInstance.HandleSurveyQuery)
		registerHandler(newDrynxInstance.HandleSurveyQueryToDP)
		registerHandler(newDrynxInstance.HandleSurveyQueryToVN)
		if waitOnLocalChans {
			registerHandler(newDrynxInstance.HandleDPqueryReceived)
			registerHandler(newDrynxInstance.HandleSyncDCP)
			registerHandler(newDrynxInstance.HandleDPdataFinished)
		}
		registerHandler(newDrynxInstance.HandleEndVerification)
		registerHandler(newDrynxInstance.HandleGetLatestBlock)
		registerHandler(newDrynxInstance.HandleGetGenesis)
		registerHandler(newDrynxInstance.HandleGetBlock)
		registerHandler(newDrynxInstance.HandleGetProofs)
		registerHandler(newDrynxInstance.HandleCloseDB)

		c.RegisterProcessor(newDrynxInstance, msgTypes.msgSurveyQuery)
		c.RegisterProcessor(newDrynxInstance, msgTypes.msgSurveyQueryToDP)
		if waitOnLocalChans {
			c.RegisterProcessor(newDrynxInstance, msgTypes.msgDPqueryReceived)
			c.RegisterProcessor(newDrynxInstance, msgTypes.msgSyncDCP)
			c.RegisterProcessor(newDrynxInstance, msgTypes.msgDPdataFinished)
		}

		//Register new verifFunction
		if err := skipchain.RegisterVerification(c, VerifyBitmap, newDrynxInstance.verifyFuncBitmap); err != nil {
			return nil, err
		}

		return newDrynxInstance, nil
	})
	if err != nil {
		log.Fatal("Error registering service:", err)
	}
}
