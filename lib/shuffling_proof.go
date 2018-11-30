package libdrynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/shuffle"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/shuffle"
	"math/big"
	"sync"
)

// PublishedShufflingProof contains all infos about proofs for shuffling of a ciphervector
type PublishedShufflingProof struct {
	OriginalList []libunlynx.ProcessResponse
	ShuffledList []libunlynx.ProcessResponse
	G            kyber.Point
	H            kyber.Point
	HashProof    []byte
}

// PublishedShufflingProofBytes is the bytes equivalent of PublishedShufflingProof
type PublishedShufflingProofBytes struct {
	OriginalList *[]byte
	ShuffledList *[]byte
	L1           *[]byte
	L2           *[]byte
	L3           *[]byte
	G            *[]byte
	H            *[]byte
	HashProof    []byte
}

// ToBytes transforms shuffling proof to bytes
func (psp *PublishedShufflingProof) ToBytes() PublishedShufflingProofBytes {
	pspb := PublishedShufflingProofBytes{}
	sm := ShufflingMessage{psp.OriginalList}
	wg := libunlynx.StartParallelize(3)
	go func(sm ShufflingMessage) {
		defer wg.Done()
		tmp, l1, l2, l3 := sm.ToBytes()
		pspb.OriginalList = tmp
		l1tmp := []byte{byte(l1)}
		pspb.L1 = &l1tmp
		l2tmp := []byte{byte(l2)}
		pspb.L2 = &l2tmp
		l3tmp := []byte{byte(l3)}
		pspb.L3 = &l3tmp
	}(sm)
	go func(sm ShufflingMessage) {
		defer wg.Done()
		sm = ShufflingMessage{psp.ShuffledList}
		pspb.ShuffledList, _, _, _ = sm.ToBytes()
	}(sm)
	go func(sm ShufflingMessage) {
		defer wg.Done()
		tmp1 := libunlynx.AbstractPointsToBytes([]kyber.Point{psp.G})
		pspb.G = &tmp1
		tmp2 := libunlynx.AbstractPointsToBytes([]kyber.Point{psp.H})
		pspb.H = &tmp2
		pspb.HashProof = psp.HashProof
	}(sm)
	libunlynx.EndParallelize(wg)
	return pspb
}

// FromBytes transforms bytes back to PublishedShufflingProof
func (psp *PublishedShufflingProof) FromBytes(pspb PublishedShufflingProofBytes) {
	sm := ShufflingMessage{}
	sm.FromBytes(pspb.OriginalList, int((*pspb.L1)[0]), int((*pspb.L2)[0]), int((*pspb.L3)[0]))
	psp.OriginalList = sm.Data
	sm.FromBytes(pspb.ShuffledList, int((*pspb.L1)[0]), int((*pspb.L2)[0]), int((*pspb.L3)[0]))
	psp.ShuffledList = sm.Data
	psp.G = libunlynx.BytesToAbstractPoints(*pspb.G)[0]
	psp.H = libunlynx.BytesToAbstractPoints(*pspb.H)[0]
	psp.HashProof = pspb.HashProof
}

// shuffleProofCreation creates a proof for one shuffle on a list of process response
func shuffleProofCreation(inputList, outputList []libunlynx.ProcessResponse, beta [][]kyber.Scalar, pi []int, h kyber.Point) []byte {
	e := CipherVectorTag(&inputList[0], h)
	k := len(inputList)
	// compress data for each line (each list) into one element
	Xhat := make([]kyber.Point, k)
	Yhat := make([]kyber.Point, k)
	XhatBar := make([]kyber.Point, k)
	YhatBar := make([]kyber.Point, k)

	//var betaCompressed []kyber.Scalar
	wg1 := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		if libunlynx.PARALLELIZE {
			go func(inputList, outputList []libunlynx.ProcessResponse, i int) {
				defer (*wg1).Done()
				CompressProcessResponseMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
			}(inputList, outputList, i)
		} else {
			CompressProcessResponseMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
		}
	}
	libunlynx.EndParallelize(wg1)

	betaCompressed := libunlynxshuffle.CompressBeta(beta, e)

	rand := libunlynx.SuiTe.RandomStream()
	// do k-shuffle of ElGamal on the (Xhat,Yhat) and check it
	k = len(Xhat)
	if k != len(Yhat) {
		panic("X,Y vectors have inconsistent lengths")
	}
	ps := shuffle.PairShuffle{}

	ps.Init(libunlynx.SuiTe, k)

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, nil, h, betaCompressed, Xhat, Yhat, rand, ctx)
	}
	prf, err := proof.HashProve(libunlynx.SuiTe, "PairShuffle", prover)
	if err != nil {
		panic("Shuffle proof failed: " + err.Error())
	}
	return prf
}

// ShufflingProofCreation creates a shuffle proof in its publishable version
func ShufflingProofCreation(originalList, shuffledList []libunlynx.ProcessResponse, g, h kyber.Point, beta [][]kyber.Scalar, pi []int) PublishedShufflingProof {
	prf := shuffleProofCreation(originalList, shuffledList, beta, pi, h)
	return PublishedShufflingProof{originalList, shuffledList, g, h, prf}
}

// checkShuffleProof verifies a shuffling proof
func checkShuffleProof(g, h kyber.Point, Xhat, Yhat, XhatBar, YhatBar []kyber.Point, prf []byte) bool {
	verifier := shuffle.Verifier(libunlynx.SuiTe, g, h, Xhat, Yhat, XhatBar, YhatBar)
	err := proof.HashVerify(libunlynx.SuiTe, "PairShuffle", verifier, prf)
	if err != nil {
		log.LLvl1(err)
		log.LLvl1("-----------verify failed (with XharBar)")
		return false
	}

	return true
}

// ShufflingProofVerification allows to check a shuffling proof
func ShufflingProofVerification(psp PublishedShufflingProof, seed kyber.Point) bool {
	e := CipherVectorTag(&psp.OriginalList[0], seed)
	var x, y, xbar, ybar []kyber.Point
	if libunlynx.PARALLELIZE {
		wg := libunlynx.StartParallelize(2)
		go func() {
			x, y = CompressListProcessResponse(psp.OriginalList, e)
			defer (*wg).Done()
		}()
		go func() {
			xbar, ybar = CompressListProcessResponse(psp.ShuffledList, e)
			defer (*wg).Done()
		}()

		libunlynx.EndParallelize(wg)
	} else {
		x, y = CompressListProcessResponse(psp.OriginalList, e)
		xbar, ybar = CompressListProcessResponse(psp.ShuffledList, e)
	}
	return checkShuffleProof(psp.G, psp.H, x, y, xbar, ybar, psp.HashProof)
}

// ShuffleSequence applies shuffling to a list of process responses
func ShuffleSequence(inputList []libunlynx.ProcessResponse, g, h kyber.Point, precomputed []libunlynx.CipherVectorScalar) ([]libunlynx.ProcessResponse, []int, [][]kyber.Scalar) {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)

	NQ1 := len(inputList[0].GroupByEnc)
	NQ2 := len(inputList[0].WhereEnc)
	NQ3 := len(inputList[0].AggregatingAttributes)

	// number of elgamal pairs
	NQ := NQ1 + NQ2 + NQ3

	k := len(inputList) // number of clients

	rand := libunlynx.SuiTe.RandomStream()
	// Pick a fresh (or precomputed) ElGamal blinding factor for each pair
	beta := make([][]kyber.Scalar, k)
	precomputedPoints := make([]libunlynx.CipherVector, k)
	for i := 0; i < k; i++ {
		if precomputed == nil {
			beta[i] = libunlynx.RandomScalarSlice(NQ)
		} else {
			randInt := random.Int(big.NewInt(int64(maxInt)), rand)

			indice := int(randInt.Int64() % int64(len(precomputed)))
			beta[i] = precomputed[indice].S[0:NQ] //if beta file is bigger than query line responses
			precomputedPoints[i] = precomputed[indice].CipherV[0:NQ]
		}

	}

	// Pick a random permutation
	pi := libunlynx.RandomPermutation(k)

	outputList := make([]libunlynx.ProcessResponse, k)

	wg := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		if libunlynx.PARALLELIZE {
			go func(outputList []libunlynx.ProcessResponse, i int) {
				defer wg.Done()
				processResponseShuffling(pi, i, inputList, outputList, NQ1, NQ2, NQ3, NQ, beta, precomputedPoints, g, h)
			}(outputList, i)
		} else {
			processResponseShuffling(pi, i, inputList, outputList, NQ1, NQ2, NQ3, NQ, beta, precomputedPoints, g, h)
		}
	}

	libunlynx.EndParallelize(wg)

	return outputList, pi, beta
}

// ProcessResponseShuffling applies shuffling and rerandomization to a list of process responses
func processResponseShuffling(pi []int, i int, inputList, outputList []libunlynx.ProcessResponse, NQ1, NQ2, NQ3, NQ int, beta [][]kyber.Scalar, precomputedPoints []libunlynx.CipherVector, g, h kyber.Point) {
	index := pi[i]
	outputList[i].GroupByEnc = *libunlynx.NewCipherVector(NQ1)
	outputList[i].WhereEnc = *libunlynx.NewCipherVector(NQ2)
	outputList[i].AggregatingAttributes = *libunlynx.NewCipherVector(NQ3)
	wg := libunlynx.StartParallelize(NQ)
	for j := 0; j < NQ; j++ {
		var b kyber.Scalar
		var cipher libunlynx.CipherText
		if len(precomputedPoints[0]) == 0 {
			b = beta[index][j]
		} else {
			cipher = precomputedPoints[index][j]
		}
		if libunlynx.PARALLELIZE {
			go func(j int) {
				defer wg.Done()
				if j < NQ1 {
					outputList[i].GroupByEnc.Rerandomize(inputList[index].GroupByEnc, b, b, cipher, g, h, j)
				} else if j < NQ1+NQ2 {
					outputList[i].WhereEnc.Rerandomize(inputList[index].WhereEnc, b, b, cipher, g, h, j-NQ1)
				} else {
					outputList[i].AggregatingAttributes.Rerandomize(inputList[index].AggregatingAttributes, b, b, cipher, g, h, j-(NQ1+NQ2))
				}
			}(j)
		} else {
			if j < NQ1 {
				outputList[i].GroupByEnc.Rerandomize(inputList[index].GroupByEnc, b, b, cipher, g, h, j)
			} else if j < NQ1+NQ2 {
				outputList[i].WhereEnc.Rerandomize(inputList[index].WhereEnc, b, b, cipher, g, h, j-NQ1)
			} else {
				outputList[i].AggregatingAttributes.Rerandomize(inputList[index].AggregatingAttributes, b, b, cipher, g, h, j-(NQ1+NQ2))
			}
		}

	}
	libunlynx.EndParallelize(wg)
}

// CompressProcessResponseMultiple applies shuffling compression to 2 list of process responses corresponding to input and output of shuffling
func CompressProcessResponseMultiple(inputList, outputList []libunlynx.ProcessResponse, i int, e []kyber.Scalar, Xhat, XhatBar, Yhat, YhatBar []kyber.Point) {
	wg := libunlynx.StartParallelize(2)
	go func() {
		defer wg.Done()
		tmp := CompressProcessResponse(inputList[i], e)
		Xhat[i] = tmp.K
		Yhat[i] = tmp.C
	}()
	go func() {
		defer wg.Done()
		tmpBar := CompressProcessResponse(outputList[i], e)
		XhatBar[i] = tmpBar.K
		YhatBar[i] = tmpBar.C
	}()
	libunlynx.EndParallelize(wg)

}

// CipherVectorTag computes all the e for a process response based on a seed h
func CipherVectorTag(cv *libunlynx.ProcessResponse, h kyber.Point) []kyber.Scalar {
	aggrAttrLen := len((*cv).AggregatingAttributes)
	grpAttrLen := len((*cv).GroupByEnc)
	whereAttrLen := len((*cv).WhereEnc)
	es := make([]kyber.Scalar, aggrAttrLen+grpAttrLen+whereAttrLen)

	seed, _ := h.MarshalBinary()
	var wg sync.WaitGroup
	if libunlynx.PARALLELIZE {
		for i := 0; i < aggrAttrLen+grpAttrLen+whereAttrLen; i = i + libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < aggrAttrLen+grpAttrLen+whereAttrLen); j++ {
					es[i+j] = ComputeE(i+j, *cv, seed, aggrAttrLen, grpAttrLen)
				}

			}(i)

		}
		wg.Wait()
	} else {
		for i := 0; i < aggrAttrLen+grpAttrLen+whereAttrLen; i++ {
			//+detAttrLen
			es[i] = ComputeE(i, *cv, seed, aggrAttrLen, grpAttrLen)
		}

	}
	return es
}

// ComputeE computes e used in a shuffle proof. Computation based on a public seed.
func ComputeE(index int, cv libunlynx.ProcessResponse, seed []byte, aggrAttrLen, grpAttrLen int) kyber.Scalar {
	var dataC []byte
	var dataK []byte

	randomCipher := libunlynx.SuiTe.XOF(seed)
	if index < aggrAttrLen {
		dataC, _ = cv.AggregatingAttributes[index].C.MarshalBinary()
		dataK, _ = cv.AggregatingAttributes[index].K.MarshalBinary()

	} else if index < aggrAttrLen+grpAttrLen {
		dataC, _ = cv.GroupByEnc[index-aggrAttrLen].C.MarshalBinary()
		dataK, _ = cv.GroupByEnc[index-aggrAttrLen].K.MarshalBinary()
	} else {
		dataC, _ = cv.WhereEnc[index-aggrAttrLen-grpAttrLen].C.MarshalBinary()
		dataK, _ = cv.WhereEnc[index-aggrAttrLen-grpAttrLen].K.MarshalBinary()
	}

	randomCipher.Write(dataC)
	randomCipher.Write(dataK)

	return libunlynx.SuiTe.Scalar().Pick(randomCipher)
}

// compressCipherVector (slice of ciphertexts) into one ciphertext
func compressCipherVector(ciphervector libunlynx.CipherVector, e []kyber.Scalar) libunlynx.CipherText {
	k := len(ciphervector)

	// check that e and cipher vectors have the same size
	if len(e) != k {
		panic("e is not the right size!")
	}

	ciphertext := *libunlynx.NewCipherText()
	for i := 0; i < k; i++ {
		aux := libunlynx.NewCipherText()
		aux.MulCipherTextbyScalar(ciphervector[i], e[i])
		ciphertext.Add(ciphertext, *aux)
	}
	return ciphertext
}

// CompressProcessResponse applies shuffling compression to a process response
func CompressProcessResponse(processResponse libunlynx.ProcessResponse, e []kyber.Scalar) libunlynx.CipherText {
	m := len(processResponse.GroupByEnc)
	n := len(processResponse.WhereEnc)
	o := len(processResponse.AggregatingAttributes)

	// check size of e
	if len(e) != m+n+o {
		//+o
		panic("e is not the same size as the list")
	}

	sum := *libunlynx.NewCipherText()
	var sum1, sum2, sum3 libunlynx.CipherText
	if libunlynx.PARALLELIZE {
		wg := libunlynx.StartParallelize(3)
		go func() {
			sum1 = compressCipherVector(processResponse.GroupByEnc, e[0:m])
			defer wg.Done()
		}()
		go func() {
			sum2 = compressCipherVector(processResponse.WhereEnc, e[m:m+n])
			defer wg.Done()
		}()
		go func() {
			sum3 = compressCipherVector(processResponse.AggregatingAttributes, e[m+n:m+n+o])
			defer wg.Done()
		}()
		libunlynx.EndParallelize(wg)
	} else {
		sum1 = compressCipherVector(processResponse.GroupByEnc, e[0:m])
		sum2 = compressCipherVector(processResponse.WhereEnc, e[m:m+n])
		sum3 = compressCipherVector(processResponse.AggregatingAttributes, e[m+n:m+n+o])
	}

	sum.Add(sum1, sum2)
	sum.Add(sum, sum3)

	return sum
}

// CompressListProcessResponse applies shuffling compression to a list of process responses
func CompressListProcessResponse(processResponses []libunlynx.ProcessResponse, e []kyber.Scalar) ([]kyber.Point, []kyber.Point) {
	xC := make([]kyber.Point, len(processResponses))
	xK := make([]kyber.Point, len(processResponses))

	wg := libunlynx.StartParallelize(len(processResponses))
	for i, v := range processResponses {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynx.ProcessResponse) {
				tmp := CompressProcessResponse(v, e)
				xK[i] = tmp.K
				xC[i] = tmp.C
				defer wg.Done()
			}(i, v)
		} else {
			tmp := CompressProcessResponse(v, e)
			xK[i] = tmp.K
			xC[i] = tmp.C
		}
	}

	libunlynx.EndParallelize(wg)
	return xK, xC
}

/*
// CompressBeta applies shuffling compression to a list of list of scalars (beta)
func CompressBeta(beta [][]kyber.Scalar, e []kyber.Scalar) []kyber.Scalar {
	k := len(beta)
	NQ := len(beta[0])
	betaCompressed := make([]kyber.Scalar, k)
	wg := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		betaCompressed[i] = libunlynx.SuiTe.Scalar().Zero()
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()
				for j := 0; j < NQ; j++ {
					tmp := libunlynx.SuiTe.Scalar().Mul(beta[i][j], e[j])
					betaCompressed[i] = libunlynx.SuiTe.Scalar().Add(betaCompressed[i], tmp)
				}
			}(i)
		} else {
			for j := 0; j < NQ; j++ {
				tmp := libunlynx.SuiTe.Scalar().Mul(beta[i][j], e[j])
				betaCompressed[i] = libunlynx.SuiTe.Scalar().Add(betaCompressed[i], tmp)
			}
		}

	}
	libunlynx.EndParallelize(wg)

	return betaCompressed
}*/
