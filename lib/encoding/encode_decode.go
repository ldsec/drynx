package encoding

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
)

// Encode takes care of computing the query result and encode it for all possible operations.
func Encode(datas [][]int64, pubKey kyber.Point, signatures [][]libdrynx.PublishSignature, ranges []*[]int64, operation libdrynx.Operation) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {

	clearResponse := []int64{}
	encryptedResponse := []libunlynx.CipherText{}
	createPrf := []libdrynx.CreateProof{}
	withProofs := len(ranges) > 0 && len(signatures) > 0

	switch operation.NameOp {
	case "sum":
		tmpEncryptedResponse := &libunlynx.CipherText{}
		tmpPrfs := []libdrynx.CreateProof{}
		if withProofs {
			tmpEncryptedResponse, clearResponse, tmpPrfs = EncodeSumWithProofs(datas[0], pubKey, signatures[0], (*ranges[0])[1], (*ranges[0])[0])
		} else {
			tmpEncryptedResponse, clearResponse = EncodeSum(datas[0], pubKey)
		}
		encryptedResponse = []libunlynx.CipherText{*tmpEncryptedResponse}
		createPrf = tmpPrfs
		break
	case "cosim":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeCosimWithProofs(datas[0], datas[1], pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeCosim(datas[0], datas[1], pubKey)
		}
		break
	case "mean":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeMeanWithProofs(datas[0], pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeMean(datas[0], pubKey)
		}
		break
	case "variance":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeVarianceWithProofs(datas[0], pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeVariance(datas[0], pubKey)
		}
		break
	case "lin_reg":
		d := len(datas)
		numbValues := len(datas[0])
		dataDimensions := make([][]int64, numbValues)
		dataYS := make([]int64, numbValues)
		for j := 0; j < numbValues; j++ {
			dataDimensions[j] = make([]int64, d-1)
			for i := 0; i < d-1; i++ {dataDimensions[j][i] = datas[i][j]}
			dataYS[j] = datas[d-1][j]
		}

		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeLinearRegressionDimsWithProofs(dataDimensions, dataYS, pubKey, signatures, ranges)
		} else {encryptedResponse, clearResponse = EncodeLinearRegressionDims(dataDimensions, dataYS, pubKey)}
		break
	case "frequencyCount":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeFreqCountWithProofs(datas[0], operation.QueryMin, operation.QueryMax, pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeFreqCount(datas[0], operation.QueryMin, operation.QueryMax, pubKey)
		}
		break

	case "bool_AND":
		booleanBit := false
		if datas[0][0] == 1 {
			booleanBit = true
		}
		cipher := &libunlynx.CipherText{}
		clear := int64(0)

		if withProofs {
			prf := libdrynx.CreateProof{}
			cipher, clear, prf = EncodeBitANDWithProof(booleanBit, pubKey, signatures[0], (*ranges[0])[1], (*ranges[0])[0])
			createPrf = []libdrynx.CreateProof{prf}
		} else {
			cipher, clear = EncodeBitAND(booleanBit, pubKey)
		}
		encryptedResponse = []libunlynx.CipherText{*cipher}
		clearResponse = []int64{clear}
		break

	case "bool_OR":
		booleanBit := false
		if datas[0][0] == 1 {
			booleanBit = true
		}
		cipher := &libunlynx.CipherText{}
		clear := int64(0)

		if withProofs {
			prf := libdrynx.CreateProof{}
			cipher, clear, prf = EncodeBitOrWithProof(booleanBit, pubKey, signatures[0], (*ranges[0])[1], (*ranges[0])[0])
			createPrf = []libdrynx.CreateProof{prf}
		} else {
			cipher, clear = EncodeBitOr(booleanBit, pubKey)
		}
		encryptedResponse = []libunlynx.CipherText{*cipher}
		clearResponse = []int64{clear}
		break

	case "min":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeMinWithProofs(datas[0], operation.QueryMax, operation.QueryMin, pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeMin(datas[0], operation.QueryMax, operation.QueryMin, pubKey)
		}

		break

	case "max":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeMaxWithProofs(datas[0], operation.QueryMax, operation.QueryMin, pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeMax(datas[0], operation.QueryMax, operation.QueryMin, pubKey)
		}
		break

	case "union":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeUnionWithProofs(datas[0], operation.QueryMin, operation.QueryMax, pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeUnion(datas[0], operation.QueryMin, operation.QueryMax, pubKey)
		}
		break
	case "inter":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeInterWithProofs(datas[0], operation.QueryMin, operation.QueryMax, pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeInter(datas[0], operation.QueryMin, operation.QueryMax, pubKey)
		}
	case "MLeval":
		if withProofs {
			encryptedResponse, clearResponse, createPrf = EncodeModelEvaluationWithProofs(datas[0], datas[1], pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeModelEvaluation(datas[0], datas[1], pubKey)
		}
	}
	return encryptedResponse, clearResponse, createPrf
}

// Decode decodes and computes the result of a query depending on the operation
func Decode(ciphers []libunlynx.CipherText, secKey kyber.Scalar, operation libdrynx.Operation) []float64 {
	switch operation.NameOp {
	case "sum":
		return []float64{float64(DecodeSum(ciphers[0], secKey))}
	case "cosim":
		return []float64{DecodeCosim(ciphers, secKey)}
	case "mean":
		return []float64{DecodeMean(ciphers, secKey)}
	case "variance":
		return []float64{DecodeVariance(ciphers, secKey)}
	case "lin_reg":
		return DecodeLinearRegressionDims(ciphers, secKey)
	case "frequencyCount":
		freqCount := DecodeFreqCount(ciphers, secKey)
		result := make([]float64, len(freqCount))
		for i := range result {result[i] = float64(freqCount[i])}
		return result
	case "min":
		return []float64{float64(DecodeMin(ciphers, operation.QueryMin, secKey))}
	case "max":
		return []float64{float64(DecodeMax(ciphers, operation.QueryMin, secKey))}
	case "bool_AND":
		boolResult := DecodeBitAND(ciphers[0], secKey)
		result := float64(0)
		if boolResult {result = float64(1)}
		return []float64{result}
	case "bool_OR":
		boolResult := DecodeBitOR(ciphers[0], secKey)
		result := float64(0)
		if boolResult {result = float64(1)}
		return []float64{result}
	case "union":
		unionSet := DecodeUnion(ciphers, secKey)
		result := make([]float64, len(unionSet))
		for i := range result {result[i] = float64(unionSet[i])}
		return result
	case "inter":
		interSet := DecodeInter(ciphers, secKey)
		result := make([]float64, len(interSet))
		for i := range result {result[i] = float64(interSet[i])}
		return result
	case "logreg":
		lrParameters := operation.LRParameters
		return DecodeLogisticRegression(ciphers, secKey, lrParameters)
	case "MLeval":
		return []float64{DecodeModelEvaluation(ciphers, secKey)}
	default:
		log.Info("no such operation:", operation)
		cv := libunlynx.CipherVector(ciphers)
		temp := libunlynx.DecryptIntVectorWithNeg(secKey, &cv)
		result := make([]float64, len(temp))
		for i, v := range temp {result[i] = float64(v)}
		return result
	}
}

// EncodeForFloat encodes floating points
func EncodeForFloat(datas [][]float64, lrParameters libdrynx.LogisticRegressionParameters, pubKey kyber.Point,
	signatures [][]libdrynx.PublishSignature, ranges []*[]int64, operation string) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {

	clearResponse := make([]int64, 0)
	encryptedResponse := make([]libunlynx.CipherText, 0)
	prf := make([]libdrynx.CreateProof, 0)
	withProofs := len(ranges) > 0

	switch operation {
	case "logreg":
		if withProofs {
			encryptedResponse, clearResponse, prf = EncodeLogisticRegressionWithProofs(datas, lrParameters, pubKey, signatures, ranges)
		} else {
			encryptedResponse, clearResponse = EncodeLogisticRegression(datas, lrParameters, pubKey)
		}
	}
	return encryptedResponse, clearResponse, prf
}
