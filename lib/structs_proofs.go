package libdrynx

import (
	"errors"
	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/lib/proofs"
	"math/rand"

	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
)

//----------------------------------------------------------------------------------------------------------------------
// PROOFs' Structs
//----------------------------------------------------------------------------------------------------------------------

// ProofRequest is an structure that encapsulates all the different proofs. Only one proof is ever active all
// at a time all others are nil.
type ProofRequest struct {
	RangeProof       *RangeProofRequest
	AggregationProof *AggregationProofRequest
	ObfuscationProof *ObfuscationProofRequest
	ShuffleProof     *ShuffleProofRequest
	KeySwitchProof   *KeySwitchProofRequest
}

// ProofToStoreInDB is the proof format when stored in the DB
type ProofToStoreInDB struct {
	Data      []byte
	Signature []byte
}

// RangeProofRequest is the structure sent by the client to the VNs to verify and store a range proof.
type RangeProofRequest struct {
	SurveyID   string
	SenderID   string // the string address of the sender node
	DifferInfo string // string to differentiate proofs from the same SenderID
	Data       []byte
	Signature  []byte
	Roster     *onet.Roster
	SB         *skipchain.SkipBlock
}

// AggregationProofRequest is the structure sent by the client to the VNs to verify and store an aggregation proof.
type AggregationProofRequest struct {
	SurveyID   string
	SenderID   string // the string address of the sender node
	DifferInfo string // string to differentiate proofs from the same SenderID
	Data       []byte
	Signature  []byte
	Roster     *onet.Roster
	SB         *skipchain.SkipBlock
}

// ObfuscationProofRequest is the structure sent by the client to the VNs to verify and store an obfuscation proof.
type ObfuscationProofRequest struct {
	SurveyID   string
	SenderID   string // the string address of the sender node
	DifferInfo string // string to differentiate proofs from the same SenderID
	Data       []byte
	Signature  []byte
	Roster     *onet.Roster
	SB         *skipchain.SkipBlock
}

// ShuffleProofRequest is the structure sent by the client to the VNs to verify and store a shuffle proof.
type ShuffleProofRequest struct {
	SurveyID           string
	SenderID           string // the string address of the sender node
	DifferInfo         string // string to differentiate proofs from the same SenderID
	Data               []byte
	Signature          []byte
	Roster             *onet.Roster
	SB                 *skipchain.SkipBlock
	PreviousShufflerID string
}

// KeySwitchProofRequest is the structure sent by the client to the VNs to verify and store a keySwitch proof.
type KeySwitchProofRequest struct {
	SurveyID              string
	SenderID              string // the string address of the sender node
	DifferInfo            string // string to differentiate proofs from the same SenderID
	Data                  []byte
	Signature             []byte
	Roster                *onet.Roster
	SB                    *skipchain.SkipBlock
	PreviousKeySwitcherID string
}

// Range Proof
//______________________________________________________________________________________________________________________

// NewRangeProofRequest creates a RangeProofRequest to be used in the ProofsCollectionProtocol
func NewRangeProofRequest(proof *RangeProofList, ID, senderID, differInfo string, entities *onet.Roster, priv kyber.Scalar, sb *skipchain.SkipBlock) *RangeProofRequest {
	proofBytes := proof.ToBytes()
	dataToSend, err := network.Marshal(&proofBytes)
	if err != nil {
		log.Fatal("Error marshalling <RangeProofBytes> message")
	}

	sig, err := schnorr.Sign(libunlynx.SuiTe, priv, dataToSend)
	if err != nil {
		log.Fatal("Error when signing range proof")
	}

	rpr := &RangeProofRequest{
		SurveyID:   ID,
		Data:       dataToSend,
		SenderID:   senderID,
		Signature:  sig,
		DifferInfo: differInfo,
		Roster:     entities,
		SB:         sb,
	}
	return rpr
}

// VerifyProof (RangeProofRequest) checks the correctness of the signature and verifies a list of range proofs
func (rpr *RangeProofRequest) VerifyProof(source network.ServerIdentity, sq SurveyQuery) (int64, error) {
	log.Lvl2("VN", source.String(), "handles range proof")
	//time := libunlynx.StartTimer(source.String() + "_VerifyRange")

	verifSign := int64(0)
	err := error(nil)
	wg := libunlynx.StartParallelize(1)
	go func() {
		defer wg.Done()
		err = VerifyProofSignature(sq.IDtoPublic[rpr.SenderID], rpr.Data, rpr.Signature)
		if err != nil {
			verifSign = proofFalseSign
		}
	}()
	verif := verifyRangeProofList(rpr.Data, sq.Threshold, sq.Query.Ranges, sq.Query.IVSigs.InputValidationSigs, sq.RosterServers.Aggregate, sq.RangeProofThreshold)
	log.Lvl2("VN", source.String(), " verified range proof:", verif)
	libunlynx.EndParallelize(wg)
	//libunlynx.EndTimer(time)
	if verifSign != 0 {
		return verifSign, err
	}
	return verif, err
}

func verifyRangeProofList(data []byte, sample float64, ranges []*[]int64, psb []*[]PublishSignatureBytes, p kyber.Point, verifThresold float64) int64 {
	bmInt := proofReceived
	rando := rand.Float64()
	if rando <= sample {
		// we check the proof
		_, proofs, err := network.Unmarshal(data, libunlynx.SuiTe)
		if err != nil {
			log.Fatal("Error unmarshalling RangeProofBytes message")
		}

		toVerify := &RangeProofList{}
		toVerify.FromBytes(*proofs.(*RangeProofListBytes))
		result := RangeProofListVerification(*toVerify, ranges, psb, p, verifThresold)
		if result {
			bmInt = ProofTrue
		} else {
			bmInt = proofFalse
		}
	} else {
		bmInt = proofReceived
	}

	return bmInt
}

// Aggregation Proof
//______________________________________________________________________________________________________________________

// NewAggregationProofRequest creates a AggregationProofRequest to be used in the ProofsCollectionProtocol
func NewAggregationProofRequest(proofs *PublishAggregationProof, ID, senderID, differInfo string, entities *onet.Roster, priv kyber.Scalar, sb *skipchain.SkipBlock) *AggregationProofRequest {
	proofBytes := proofs.ToBytes()
	dataToSend, err := network.Marshal(&proofBytes)
	if err != nil {
		log.Fatal("Error marshalling <PublishAggregationProofBytes> message", err)
	}

	sig, err := schnorr.Sign(libunlynx.SuiTe, priv, dataToSend)
	if err != nil {
		log.Fatal("Error when signing aggregation proof")
	}

	apr := &AggregationProofRequest{
		SurveyID:   ID,
		Data:       dataToSend,
		SenderID:   senderID,
		Signature:  sig,
		DifferInfo: differInfo,
		Roster:     entities,
		SB:         sb,
	}
	return apr
}

// VerifyProof (AggregationProofRequest) checks the correctness of the signature and verifies an aggregation proof
func (apr *AggregationProofRequest) VerifyProof(source network.ServerIdentity, sq SurveyQuery) (int64, error) {
	log.Lvl2("VN", source.String(), "handles aggregation proof")
	//time := libunlynx.StartTimer(source.String() + "_VerifyAggregation")

	verifSign := int64(0)
	err := error(nil)
	wg := libunlynx.StartParallelize(1)
	go func() {
		defer wg.Done()
		err = VerifyProofSignature(sq.IDtoPublic[apr.SenderID], apr.Data, apr.Signature)
		if err != nil {
			verifSign = proofFalseSign
		}
	}()

	verif := verifyAggregation(apr.Data, sq.Threshold)
	log.Lvl2("VN", source.String(), "verified aggregation proof:", verif)
	libunlynx.EndParallelize(wg)
	//libunlynx.EndTimer(time)
	if verifSign != 0 {
		return verifSign, err
	}
	return verif, err
}

func verifyAggregation(data []byte, sample float64) int64 {
	bmInt := proofReceived
	if rand.Float64() <= sample {
		_, proofs, err := network.Unmarshal(data, libunlynx.SuiTe)
		toVerify := &PublishAggregationProof{}
		toVerify.FromBytes(*proofs.(*PublishAggregationProofBytes))
		if err != nil {
			log.Fatal("Error in unmarshalling data from Aggregation request ", err)
		}

		result := ServerAggregationProofVerification(*toVerify)
		if result {
			bmInt = ProofTrue
		} else {
			bmInt = proofFalse
		}
	} else {
		bmInt = proofReceived
	}

	return bmInt
}

// Obfuscation Proof
//______________________________________________________________________________________________________________________

// NewObfuscationProofRequest creates a AggregationProofRequest to be used in the ProofsCollectionProtocol
func NewObfuscationProofRequest(proof *PublishedListObfuscationProof, ID, senderID, differInfo string, entities *onet.Roster, priv kyber.Scalar, sb *skipchain.SkipBlock) *ObfuscationProofRequest {
	proofBytes := proof.ToBytes()
	dataToSend, err := network.Marshal(&proofBytes)
	if err != nil {
		log.Fatal("Error marshalling <PublishObfuscationProofBytes> message", err)
	}

	sig, err := schnorr.Sign(libunlynx.SuiTe, priv, dataToSend)
	if err != nil {
		log.Fatal("Error when signing obfuscation proof")
	}

	opr := &ObfuscationProofRequest{
		SurveyID:   ID,
		Data:       dataToSend,
		SenderID:   senderID,
		Signature:  sig,
		DifferInfo: differInfo,
		Roster:     entities,
		SB:         sb,
	}
	return opr
}

// VerifyProof (ObfuscationProofRequest) checks the correctness of the signature and verifies an aggregation proof
func (apr *ObfuscationProofRequest) VerifyProof(source network.ServerIdentity, sq SurveyQuery) (int64, error) {
	log.Lvl2("VN", source.String(), "handles obfuscation proof")
	//time := libunlynx.StartTimer(source.String() + "_VerifyObfuscation")

	verifSign := int64(0)
	err := error(nil)
	wg := libunlynx.StartParallelize(1)
	go func() {
		defer wg.Done()
		err = VerifyProofSignature(sq.IDtoPublic[apr.SenderID], apr.Data, apr.Signature)
		if err != nil {
			verifSign = proofFalseSign
		}
	}()

	verif := verifyObfuscation(apr.Data, sq.ObfuscationProofThreshold, sq.Threshold)
	log.Lvl2("VN", source.String(), "verified obfuscation proof:", verif)
	libunlynx.EndParallelize(wg)
	//libunlynx.EndTimer(time)
	if verifSign != 0 {
		return verifSign, err
	}
	return verif, err
}

func verifyObfuscation(data []byte, insideProofThresold, sample float64) int64 {
	bmInt := proofReceived
	if rand.Float64() <= sample {
		_, proof, err := network.Unmarshal(data, libunlynx.SuiTe)
		toVerify := &PublishedListObfuscationProof{}
		toVerify.FromBytes(*proof.(*PublishedListObfuscationProofBytes))
		if err != nil {
			log.Fatal("Error in unmarshalling data from Obfuscation request ", err)
		}

		result := ObfuscationListProofVerification(*toVerify, insideProofThresold)
		if result {
			bmInt = ProofTrue
		} else {
			bmInt = proofFalse
		}
	} else {
		bmInt = proofReceived
	}

	return bmInt
}

// Shuffle Proof
//______________________________________________________________________________________________________________________

// NewShuffleProofRequest creates a ShuffleProofRequest to be used in the ProofsCollectionProtocol
func NewShuffleProofRequest(proof *libunlynxproofs.PublishedShufflingProof, ID, senderID, differInfo string, entities *onet.Roster, priv kyber.Scalar, sb *skipchain.SkipBlock) *ShuffleProofRequest {
	psp := proof.ToBytes()
	dataToSend, err := network.Marshal(&psp)
	if err != nil {
		log.Fatal("Error marshalling <PublishedShufflingProofBytes> message", err)

	}
	sig, err := schnorr.Sign(libunlynx.SuiTe, priv, dataToSend)
	if err != nil {
		log.Fatal("Error when signing shuffling proof")
	}
	spr := &ShuffleProofRequest{
		SurveyID:   ID,
		Data:       dataToSend,
		SenderID:   senderID,
		Signature:  sig,
		DifferInfo: differInfo,
		Roster:     entities,
		SB:         sb,
	}
	return spr
}

// VerifyProof (ShuffleProofRequest) checks the correctness of the signature and verifies a shuffle proof
func (spr *ShuffleProofRequest) VerifyProof(source network.ServerIdentity, sq SurveyQuery) (int64, error) {
	log.Lvl2("VN", source.String(), "handles shuffle proof")
	//time := libunlynx.StartTimer(source.String() + "_VerifyShuffle")

	verifSign := int64(0)
	err := error(nil)
	wg := libunlynx.StartParallelize(1)
	go func() {
		defer wg.Done()
		err = VerifyProofSignature(sq.IDtoPublic[spr.SenderID], spr.Data, spr.Signature)
		if err != nil {
			verifSign = proofFalseSign
		}
	}()

	verif := verifyShuffle(spr.Data, sq.Threshold, sq.RosterServers)
	log.Lvl2("VN", source.String(), "verified shuffle proof:", verif)
	libunlynx.EndParallelize(wg)
	//libunlynx.EndTimer(time)
	if verifSign != 0 {
		return verifSign, err
	}
	return verif, err
}

// verifyShuffle verifies a shuffle proof with a given probability
func verifyShuffle(data []byte, sample float64, roster onet.Roster) int64 {
	bmInt := proofReceived
	if rand.Float64() <= sample {
		_, proofs, err := network.Unmarshal(data, libunlynx.SuiTe)
		if err != nil {
			log.Fatal("Error unmarshalling PublishShufflingProofBytes message")
		}

		toVerify := &libunlynxproofs.PublishedShufflingProof{}
		toVerify.FromBytes(*proofs.(*libunlynxproofs.PublishedShufflingProofBytes))
		result := libunlynxproofs.ShufflingProofVerification(*toVerify, roster.Aggregate)

		if result {
			bmInt = ProofTrue
		} else {
			bmInt = proofFalse
		}
	} else {
		bmInt = proofReceived
	}

	return bmInt
}

// Key Switch Proof
//______________________________________________________________________________________________________________________

// NewKeySwitchProofRequest creates a KeySwitchProofRequest to be used in the ProofsCollectionProtocol
func NewKeySwitchProofRequest(proof *libunlynxkeyswitch.PublishedKSListProof, ID, senderID, differInfo string, entities *onet.Roster, priv kyber.Scalar, sb *skipchain.SkipBlock) *KeySwitchProofRequest {
	proofBytes := proof.ToBytes()
	dataToSend, err := network.Marshal(&proofBytes)
	if err != nil {
		log.Fatal("Error marshalling <SwitchKeyListCVProofBytes> message")
	}

	sig, err := schnorr.Sign(libunlynx.SuiTe, priv, dataToSend)
	if err != nil {
		log.Fatal("Error when signing key switch proof")
	}
	kpr := &KeySwitchProofRequest{
		SurveyID:   ID,
		Data:       dataToSend,
		SenderID:   senderID,
		Signature:  sig,
		DifferInfo: differInfo,
		Roster:     entities,
		SB:         sb,
	}
	return kpr
}

// VerifyProof (KeySwitchProofRequest) checks the correctness of the signature and verifies a key switch proof
func (kpr *KeySwitchProofRequest) VerifyProof(source network.ServerIdentity, sq SurveyQuery) (int64, error) {
	log.Lvl2("VN", source.String(), "handles key switch proof")
	//timeRange := libunlynx.StartTimer(source.String() + "_VerifyKeySwitch")

	verifSign := int64(0)
	err := error(nil)
	wg := libunlynx.StartParallelize(1)
	go func() {
		defer wg.Done()
		err = VerifyProofSignature(sq.IDtoPublic[kpr.SenderID], kpr.Data, kpr.Signature)
		if err != nil {
			verifSign = proofFalseSign
		}
	}()

	verif := verifyKeySwitch(kpr.Data, sq.KeySwitchingProofThreshold, sq.Threshold)
	log.Lvl2("VN", source.String(), "verified key switch proof:", verif)
	libunlynx.EndParallelize(wg)
	//libunlynx.EndTimer(timeRange)
	if verifSign != 0 {
		return verifSign, err
	}
	return verif, err
}

func verifyKeySwitch(data []byte, insideProofThresold, sample float64) int64 {
	bmInt := proofReceived
	if rand.Float64() <= sample {
		// we check the proof
		_, proofs, err := network.Unmarshal(data, libunlynx.SuiTe)
		if err != nil {
			log.Fatal("Error unmarshalling SwitchKeyListCVProofBytes message")
		}

		toVerify := &libunlynxkeyswitch.PublishedKSListProof{}
		toVerify.FromBytes(*proofs.(*libunlynxkeyswitch.PublishedKSListProofBytes))

		result := libunlynxkeyswitch.KeySwitchListProofVerification(*toVerify, insideProofThresold)
		if result {
			bmInt = ProofTrue
		} else {
			bmInt = proofFalse
		}
	} else {
		bmInt = proofReceived
	}

	return bmInt
}

// Generic Functions
//______________________________________________________________________________________________________________________

// VerifyProofSignature verifies the signature of the proof
func VerifyProofSignature(pubKey kyber.Point, data []byte, signature []byte) error {
	pair := bn256.NewSuite()
	err := schnorr.Verify(pair.G1(), pubKey, data, signature)
	if err != nil {
		return errors.New("signature is not correct")
	}
	return nil
}
