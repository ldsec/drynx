package libdrynx

//PublishAggregationProof is an aggregation proof
type PublishAggregationProof struct {
	DPsData        ResponseAllDPs
	AggregatedData ResponseAllDPs
}

//PublishAggregationProofBytes is the bytes' version of PublishAggregationProof
type PublishAggregationProofBytes struct {
	DPsDataByte        ResponseAllDPsBytes
	AggregatedDataByte ResponseAllDPsBytes
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
func ServerAggregationProofCreation(dPsData, aggregatedData ResponseAllDPs) PublishAggregationProof {
	return PublishAggregationProof{DPsData: dPsData, AggregatedData: aggregatedData}
}

//ServerAggregationProofVerification verifies an aggregation proof
func ServerAggregationProofVerification(pap PublishAggregationProof) bool {
	proofAggr := ConvertToAggregationStruct(pap.DPsData)
	proofAggrResult := ConvertToAggregationStruct(pap.AggregatedData)

	for k, v := range proofAggrResult {
		if _, ok := proofAggr[k]; !ok {
			return false
		}
		tmpGrp := proofAggr[k].GroupByEnc
		tmpAggr := proofAggr[k].AggregatingAttributes

		if !v.GroupByEnc.Equal(&tmpGrp) || !v.AggregatingAttributes.Equal(&tmpAggr) {
			return false
		}
	}

	return true
}
