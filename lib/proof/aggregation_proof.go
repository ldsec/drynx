package proof

import "github.com/lca1/unlynx/lib"

//PublishAggregationProof is an aggregation proof
type PublishAggregationProof struct {
	DPsData        libunlynx.ResponseAllDPs
	AggregatedData libunlynx.ResponseAllDPs
}

//PublishAggregationProofBytes is the bytes' version of PublishAggregationProof
type PublishAggregationProofBytes struct {
	DPsDataByte        libunlynx.ResponseAllDPsBytes
	AggregatedDataByte libunlynx.ResponseAllDPsBytes
}

//ToBytes converts PublishAggregationProof to bytes
func (pap *PublishAggregationProof) ToBytes() PublishAggregationProofBytes {
	return PublishAggregationProofBytes{pap.DPsData.ToBytes(), pap.AggregatedData.ToBytes()}
}

//FromBytes converts bytes back to PublishAggregationProof
func (pap *PublishAggregationProof) FromBytes(papb PublishAggregationProofBytes) {
	pap.DPsData.FromBytes(papb.DPsDataByte)
	pap.AggregatedData.FromBytes(papb.AggregatedDataByte)
}

//ServerAggregationProofCreation creates an aggregation proof
func ServerAggregationProofCreation(dPsData, aggregatedData libunlynx.ResponseAllDPs) PublishAggregationProof {
	return PublishAggregationProof{DPsData: dPsData, AggregatedData: aggregatedData}
}

//ServerAggregationProofVerification verifies an aggregation proof
func ServerAggregationProofVerification(pap PublishAggregationProof) bool {
	proofAggr := libunlynx.ConvertToAggregationStruct(pap.DPsData)
	proofAggrResult := libunlynx.ConvertToAggregationStruct(pap.AggregatedData)

	for k, v := range proofAggrResult {
		if _, ok := proofAggr[k]; !ok {
			return false
		} else {
			tmpGrp := proofAggr[k].GroupByEnc
			tmpAggr := proofAggr[k].AggregatingAttributes
			if !v.GroupByEnc.Equal(&tmpGrp) || !v.AggregatingAttributes.Equal(&tmpAggr) {
				return false
			}
		}
	}

	return true
}