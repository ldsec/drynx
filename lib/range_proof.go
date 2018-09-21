package libdrynx

import (
	"crypto/sha256"
	"github.com/cbergoon/merkletree"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"golang.org/x/crypto/sha3"
	"math"
)

//RangeProof contains all information sent by DataProvider to Server
type RangeProof struct {
	Commit libunlynx.CipherText
	RP     *RangeProofData // this can be empty when there is no range proofs
}

//RangeProofList contains all information sent by DataProvider to Server
type RangeProofList struct {
	Data []RangeProof
}

//RangeProofListBytes is the bytes' version of RangeProofList
type RangeProofListBytes struct {
	Data *[]RangeProofBytes
}

//RangeProofData contains the information needed to compute the range proofs
type RangeProofData struct {
	Challenge kyber.Scalar
	Zr        kyber.Scalar
	D         kyber.Point
	Zv        [][]kyber.Scalar
	Zphi      []kyber.Scalar
	V         [][]kyber.Point
	A         [][]kyber.Point
}

//RangeProofBytes contains all information sent by DataProvider to Server
type RangeProofBytes struct {
	//Data from DP
	Commit []byte
	RP     *RangeProofDataBytes
}

//RangeProofDataBytes is the same as RangeProofData but the data are in bytes
type RangeProofDataBytes struct {
	Challenge *[]byte
	Zr        *[]byte
	D         *[]byte
	Zv        *[][]byte
	Zphi      *[]byte
	V         *[][]byte
	A         *[][]byte
}

//CreateProof contains all the elements used to create a range proof
type CreateProof struct {
	Sigs   []PublishSignature
	U      int64
	L      int64
	Secret int64
	R      kyber.Scalar
	CaPub  kyber.Point
	Cipher libunlynx.CipherText
}

//ToBytes converts RangeProofList to bytes
func (prf *RangeProofList) ToBytes() RangeProofListBytes {
	rplb := RangeProofListBytes{}
	tmp := make([]RangeProofBytes, len(prf.Data))
	wg := libunlynx.StartParallelize(len(prf.Data))
	for i, v := range prf.Data {
		go func(i int, v RangeProof) {
			defer wg.Done()
			tmp[i] = v.ToBytes()
		}(i, v)

	}
	libunlynx.EndParallelize(wg)
	rplb.Data = &tmp
	return rplb
}

//ToBytes converts RangeProof to bytes
func (prf *RangeProof) ToBytes() RangeProofBytes {
	prfBytes := RangeProofBytes{RP: &RangeProofDataBytes{}}

	if prf.RP == nil {
		prfBytes.Commit = prf.Commit.ToBytes()
		return prfBytes
	}

	tmpV, tmpA := make([][]byte, len(prf.RP.V)), make([][]byte, len(prf.RP.A))
	tmpZv := make([][]byte, len(prf.RP.Zv))
	wg := libunlynx.StartParallelize(len(prf.RP.V))
	for i := range prf.RP.V {
		go func(i int) {
			defer wg.Done()
			if i == 0 { // to include it in the parallelization
				prfBytes.Commit = prf.Commit.ToBytes()
				tmp, err := prf.RP.Challenge.MarshalBinary()
				if err != nil {
					log.Fatal(err)
				}
				prfBytes.RP.Challenge = &tmp

				tmpR, err := prf.RP.Zr.MarshalBinary()
				if err != nil {
					log.Fatal(err)
				}
				prfBytes.RP.Zr = &tmpR

				tmpD := libunlynx.AbstractPointsToBytes([]kyber.Point{prf.RP.D})
				prfBytes.RP.D = &tmpD

				tmpPhi := []byte{}
				for _, v := range prf.RP.Zphi {
					tmp, err1 := v.MarshalBinary()
					tmpPhi = append(tmpPhi, tmp...)
					if err1 != nil {
						log.Fatal(err1)
					}
				}
				prfBytes.RP.Zphi = &tmpPhi

			}

			for _, w := range prf.RP.V[i] {
				tmp, err := w.MarshalBinary()
				if err != nil {
					log.Fatal(err)
				}
				tmpV[i] = append(tmpV[i], tmp...)
			}
			tmpA[i] = libunlynx.AbstractPointsToBytes(prf.RP.A[i])

			for _, w := range prf.RP.Zv[i] {
				tmp, err2 := w.MarshalBinary()
				tmpZv[i] = append(tmpZv[i], tmp...)
				if err2 != nil {
					log.Fatal(err2)
				}
			}
		}(i)
	}
	libunlynx.EndParallelize(wg)
	prfBytes.RP.V = &tmpV
	prfBytes.RP.A = &tmpA
	prfBytes.RP.Zv = &tmpZv
	return prfBytes
}

// FromBytes converts bytes back to RangeProofList
func (prf *RangeProofList) FromBytes(prpb RangeProofListBytes) {
	prf.Data = make([]RangeProof, len(*prpb.Data))
	wg := libunlynx.StartParallelize(len(*prpb.Data))
	for i, v := range *prpb.Data {
		go func(i int, v RangeProofBytes) {
			defer wg.Done()
			prf.Data[i].FromBytes(v)
		}(i, v)
	}
	libunlynx.EndParallelize(wg)
}

// FromBytes converts bytes back to RangeProof
func (prf *RangeProof) FromBytes(prpb RangeProofBytes) {
	prf.RP = &RangeProofData{}

	if prpb.RP.Challenge == nil {
		prf.Commit.FromBytes(prpb.Commit)
		return
	}

	suitePair := bn256.NewSuite()

	V, A, Zv := make([][]kyber.Point, len(*prpb.RP.V)), make([][]kyber.Point, len(*prpb.RP.A)), make([][]kyber.Scalar, len(*prpb.RP.Zv))
	g2PointLen := (suitePair.G2().PointLen())
	gtPointLen := suitePair.GT().PointLen()
	wg := libunlynx.StartParallelize(len(*prpb.RP.V))
	for i := 0; i < len(*prpb.RP.V); i++ {
		go func(i int) {
			defer wg.Done()
			if i == 0 { // to include in para
				for j := 0; j < len(*prpb.RP.Zphi); j = j + libunlynx.SuiTe.ScalarLen() {
					tmp := libunlynx.SuiTe.Scalar().One()
					tmp.UnmarshalBinary((*prpb.RP.Zphi)[j : j+libunlynx.SuiTe.ScalarLen()])
					prf.RP.Zphi = append(prf.RP.Zphi, tmp)
				}
				prf.Commit.FromBytes(prpb.Commit)
				tmp := libunlynx.SuiTe.Scalar().One()
				err := tmp.UnmarshalBinary(*prpb.RP.Challenge)

				if err != nil {
					log.Fatal(err)
				}
				prf.RP.Challenge = tmp

				prf.RP.D = libunlynx.BytesToAbstractPoints(*prpb.RP.D)[0]

				tmp1 := libunlynx.SuiTe.Scalar().One()
				err = tmp1.UnmarshalBinary(*prpb.RP.Zr)
				prf.RP.Zr = tmp1
				if err != nil {
					log.Fatal(err)
				}

			}
			for j := 0; j < len((*prpb.RP.Zv)[i]); j = j + libunlynx.SuiTe.ScalarLen() {
				scalarPoint := libunlynx.SuiTe.Scalar().One()
				err := scalarPoint.UnmarshalBinary((*prpb.RP.Zv)[i][j : j+libunlynx.SuiTe.ScalarLen()])
				if err != nil {
					log.Fatal(err)
				}
				Zv[i] = append(Zv[i], scalarPoint)
			}

			for j := 0; j < len((*prpb.RP.V)[i]); j = j + g2PointLen {
				g2Point := suitePair.G2().Point()
				err := g2Point.UnmarshalBinary((*prpb.RP.V)[i][j : j+g2PointLen])
				if err != nil {
					log.Fatal(err)
				}
				V[i] = append(V[i], g2Point)
			}
			for j := 0; j < len((*prpb.RP.A)[i]); j = j + gtPointLen {
				gtPoint := suitePair.GT().Point()
				err := gtPoint.UnmarshalBinary((*prpb.RP.A)[i][j : j+gtPointLen])
				if err != nil {
					log.Fatal(err)
				}
				A[i] = append(A[i], gtPoint)
			}
		}(i)
	}
	libunlynx.EndParallelize(wg)
	prf.RP.Zv = Zv
	prf.RP.V = V
	prf.RP.A = A

}



// InitRangeProofSignatureDeterministic is used for simulation puposes to create deterministic servers' signatures
func InitRangeProofSignatureDeterministic(u int64) PublishSignatureBytes {
	suitePair := bn256.NewSuite()
	g2 := suitePair.G2()
	A := make([]byte, 0)

	//pick a pair private(x)/public(y) key at each server
	x := libunlynx.SuiTe.Scalar().SetInt64(12)
	y := libunlynx.SuiTe.Point().Mul(x, libunlynx.SuiTe.Point().Base())

	//signature from private key done by server
	for i := 0; int64(i) < int64(u); i++ {
		scalar := g2.Scalar().SetInt64(int64(i))
		invert := g2.Scalar().Add(x, scalar)
		tmp := g2.Point().Mul(g2.Scalar().Inv(invert), g2.Point().Base())
		tmpByte, _ := tmp.MarshalBinary()
		A = append(A, tmpByte...)
	}
	return PublishSignatureBytes{Signature: A, Public: y}
}

//InitRangeProofSignature create a public/private key pair and return new signatures in a PublishSignature structure. (done by servers)
func InitRangeProofSignature(u int64) PublishSignatureBytes {
	suitePair := bn256.NewSuite()
	g2 := suitePair.G2()
	A := make([]byte, 0)

	//pick a pair private(x)/public(y) key at each server
	x, y := libunlynx.GenKey()

	//signature from private key done by server
	for i := 0; int64(i) < int64(u); i++ {
		scalar := g2.Scalar().SetInt64(int64(i))
		invert := g2.Scalar().Add(x, scalar)
		tmp := g2.Point().Mul(g2.Scalar().Inv(invert), g2.Point().Base())
		tmpByte, _ := tmp.MarshalBinary()
		A = append(A, tmpByte...)
	}
	return PublishSignatureBytes{Signature: A, Public: y}
}

//PublishSignatureBytesToPublishSignatures creates servers' signatures directly in bytes
func PublishSignatureBytesToPublishSignatures(sigsBytes PublishSignatureBytes) PublishSignature {
	suitePair := bn256.NewSuite()
	g2 := suitePair.G2()
	signatures := make([]kyber.Point, 0)
	for i := 0; i < len(sigsBytes.Signature); i = i + g2.PointLen() {
		point := g2.Point()
		point.UnmarshalBinary(sigsBytes.Signature[i : i+g2.PointLen()])
		signatures = append(signatures, point)
	}

	return PublishSignature{Signature: signatures, Public: sigsBytes.Public}
}

//CreatePredicateRangeProofListForAllServers creates range proofs for a list of servers and values
func CreatePredicateRangeProofListForAllServers(cps []CreateProof) []RangeProof {
	rps := make([]RangeProof, len(cps))
	wg := libunlynx.StartParallelize(len(cps))
	for i, v := range cps {
		go func(i int, v CreateProof) {
			defer wg.Done()
			rps[i] = CreatePredicateRangeProofForAllServ(v)
		}(i, v)

	}
	libunlynx.EndParallelize(wg)
	return rps
}

//CreatePredicateRangeProofForAllServ creates a proof for one value for a list of servers
func CreatePredicateRangeProofForAllServ(cp CreateProof) RangeProof {
	// Handle the no proof case by just sending the ciphertext
	if cp.U == 0 && cp.L == 0 {
		return RangeProof{Commit: cp.Cipher}
	}
	//Base
	suitePair := bn256.NewSuite()
	g2 := suitePair.G2()
	//value to pick and calculate
	base := ToBase(int64(cp.Secret), int64(cp.U), int(cp.L))
	//Encryption is E = (C1,C2) , C1 = rB C2 = m + Pr the commit
	//C = m + Pr
	commit := cp.Cipher.C

	a := make([][]kyber.Point, int(len(cp.Sigs)))
	D := libunlynx.SuiTe.Point().Null()
	Zphi := make([]kyber.Scalar, int(len(base)))
	ZV := make([][]kyber.Scalar, int(len(cp.Sigs)))
	v := make([][]kyber.Scalar, int(len(cp.Sigs)))
	V := make([][]kyber.Point, int(len(cp.Sigs)))
	m := libunlynx.SuiTe.Scalar()

	for i := 0; i < int(len(cp.Sigs)); i++ {
		ZV[i] = make([]kyber.Scalar, int(len(base)))
		v[i] = make([]kyber.Scalar, int(len(base)))
		V[i] = make([]kyber.Point, int(len(base)))
		a[i] = make([]kyber.Point, int(len(base)))
	}

	//c = Hash(B,Commitment,y)
	hash := sha3.New512()
	Bbyte, err := libunlynx.SuiTe.Point().Base().MarshalBinary()
	if err != nil {
		log.Fatal("Problem in point To Bytes B ", err)
	}
	hash.Write(Bbyte)

	C1byte, err := commit.MarshalBinary()
	if err != nil {
		log.Fatal("Problem in point To Bytes C ", err)
	}
	hash.Write(C1byte)

	sumPub := libunlynx.SuiTe.Point().Null()
	for _, v := range cp.Sigs {
		sumPub.Add(sumPub, v.Public)
	}

	YByte, err := sumPub.MarshalBinary()
	if err != nil {
		log.Fatal("Problem in point To Bytes Y ", err)
	}
	hash.Write(YByte)

	c := libunlynx.SuiTe.Scalar().SetBytes(hash.Sum(nil))

	for j := 0; j < len(base); j++ {
		sj := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		tj := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		mj := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		m.Add(m, mj)
		//Compute D
		//Bu^js_j
		firstT := libunlynx.SuiTe.Point().Mul(libunlynx.SuiTe.Scalar().Mul(sj, libunlynx.SuiTe.Scalar().SetInt64(int64(math.Pow(float64(cp.U), float64(j))))), libunlynx.SuiTe.Point().Base())
		D.Add(D, firstT)
		secondT := libunlynx.SuiTe.Point().Mul(mj, cp.CaPub)
		D.Add(D, secondT)

		Zphi[j] = libunlynx.SuiTe.Scalar().Sub(sj, libunlynx.SuiTe.Scalar().Mul(c, libunlynx.SuiTe.Scalar().SetInt64(int64(base[j]))))
		for i, s := range cp.Sigs {
			v[i][j] = g2.Scalar().Pick(libunlynx.SuiTe.RandomStream())
			///V_j = B(x+phi_j)^-1(v_j)
			V[i][j] = g2.Point().Mul(v[i][j], s.Signature[base[j]])
			//Compute a_j

			//a[j].Add(a[j], suitePair.Pair(suitePair.Point().Mul(tj, SuiTe.Point().Base()), g2.Point().Base()))
			a[i][j] = suitePair.Pair(libunlynx.SuiTe.Point().Mul(libunlynx.SuiTe.Scalar().Neg(sj), libunlynx.SuiTe.Point().Base()), V[i][j])
			a[i][j].Add(a[i][j], suitePair.Pair(libunlynx.SuiTe.Point().Mul(tj, libunlynx.SuiTe.Point().Base()), g2.Point().Base()))
			ZV[i][j] = libunlynx.SuiTe.Scalar().Sub(tj, libunlynx.SuiTe.Scalar().Mul(c, v[i][j]))
		}
	}
	Zr := libunlynx.SuiTe.Scalar().Sub(m, libunlynx.SuiTe.Scalar().Mul(c, cp.R))

	rp := RangeProofData{D: D, A: a, Challenge: c, V: V, Zphi: Zphi, Zv: ZV, Zr: Zr}
	rProof := RangeProof{Commit: cp.Cipher, RP: &rp}
	return rProof

}

//CreatePredicateRangeProof creates predicate for secret range validation by the data provider
func CreatePredicateRangeProof(sig PublishSignature, u int64, l int64, secret int64, r kyber.Scalar, caPub kyber.Point, cipher libunlynx.CipherText) RangeProof {
	if u == 0 && l == 0 {
		return RangeProof{Commit: cipher, RP: nil}
	}

	suitePair := bn256.NewSuite()
	g2 := suitePair.G2()

	//value to pick and calculate
	base := ToBase(int64(secret), int64(u), int(l))
	commit := cipher.C

	a := make([]kyber.Point, int(len(base)))
	D := libunlynx.SuiTe.Point().Null()
	Zphi := make([]kyber.Scalar, int(len(base)))
	ZV := make([]kyber.Scalar, int(int(len(base))))
	v := make([]kyber.Scalar, int(len(base)))
	V := make([]kyber.Point, int(len(base)))
	m := libunlynx.SuiTe.Scalar()

	//c = Hash(B,Commitment,y)
	hash := sha3.New512()
	Bbyte, err := libunlynx.SuiTe.Point().Base().MarshalBinary()
	if err != nil {
		log.Fatal("Problem in point To Bytes B ", err)
	}
	hash.Write(Bbyte)

	C1byte, err := commit.MarshalBinary()
	if err != nil {
		log.Fatal("Problem in point To Bytes C ", err)
	}
	hash.Write(C1byte)

	YByte, err := sig.Public.MarshalBinary()
	if err != nil {
		log.Fatal("Problem in point To Bytes Y ", err)
	}
	hash.Write(YByte)

	c := libunlynx.SuiTe.Scalar().SetBytes(hash.Sum(nil))
	for j := 0; j < len(base); j++ {
		v[j] = g2.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		///V_j = B(x+phi_j)^-1(v_j)
		V[j] = g2.Point().Mul(v[j], sig.Signature[base[j]])

		//
		sj := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		tj := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		mj := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		m.Add(m, mj)
		//Compute D
		//Bu^js_j
		firstT := libunlynx.SuiTe.Point().Mul(libunlynx.SuiTe.Scalar().Mul(sj, libunlynx.SuiTe.Scalar().SetInt64(int64(math.Pow(float64(u), float64(j))))), libunlynx.SuiTe.Point().Base())
		D.Add(D, firstT)
		secondT := libunlynx.SuiTe.Point().Mul(mj, caPub)
		D.Add(D, secondT)
		//Compute a_j
		a[j] = suitePair.Pair(libunlynx.SuiTe.Point().Mul(libunlynx.SuiTe.Scalar().Neg(sj), libunlynx.SuiTe.Point().Base()), V[j])
		a[j].Add(a[j], suitePair.Pair(libunlynx.SuiTe.Point().Mul(tj, libunlynx.SuiTe.Point().Base()), g2.Point().Base()))

		Zphi[j] = libunlynx.SuiTe.Scalar().Sub(sj, libunlynx.SuiTe.Scalar().Mul(c, libunlynx.SuiTe.Scalar().SetInt64(int64(base[j]))))
		ZV[j] = libunlynx.SuiTe.Scalar().Sub(tj, libunlynx.SuiTe.Scalar().Mul(c, v[j]))

	}

	Zr := libunlynx.SuiTe.Scalar().Sub(m, libunlynx.SuiTe.Scalar().Mul(c, r))

	rp := RangeProofData{D: D, A: [][]kyber.Point{a}, Challenge: c, V: [][]kyber.Point{V}, Zphi: Zphi, Zv: [][]kyber.Scalar{ZV}, Zr: Zr}
	return RangeProof{Commit: cipher, RP: &rp}

}

//RangeProofListVerification verifies a list of range proofs
func RangeProofListVerification(rangeProofsList RangeProofList, ranges []*[]int64, psb []*[]PublishSignatureBytes, P kyber.Point, verifThresold float64) bool {
	result := true
	nbrVerifs := int(math.Ceil(verifThresold * float64(len(rangeProofsList.Data))))
	wg := libunlynx.StartParallelize(nbrVerifs)
	allRes := make([]bool, nbrVerifs)

	for i := 0; i < nbrVerifs; i++ {
		go func(i int) {
			defer wg.Done()
			allRes[i] = RangeProofVerification(rangeProofsList.Data[i], (*ranges[i])[0], (*ranges[i])[1], ReadColumnYs(psb, i), P)
		}(i)
	}
	libunlynx.EndParallelize(wg)
	for _, v := range allRes {
		result = result && v
	}
	return result
}

//RangeProofVerification is a function that is executed at the server, when he receive the value from the Data Provider to verify the input.
func RangeProofVerification(rangeProof RangeProof, u int64, l int64, y []kyber.Point, P kyber.Point) bool {
	suitePair := bn256.NewSuite()
	g2 := suitePair.G2()

	if int(l) == 0 && u == int64(0) {
		return true
	}
	//check that indeed each value was filled with the good number of value in the base
	if int(4*l)-len(rangeProof.RP.Zphi)-len(rangeProof.RP.Zv[0])-len(rangeProof.RP.A[0])-len(rangeProof.RP.V[0]) != 0 {
		log.Lvl2("Not the same size")
		return false
	}
	//The a_j
	ap := make([][]kyber.Point, len(rangeProof.RP.A[0]))

	//Dp = Cc + PZr + Sum(p)(in for)
	Dp := libunlynx.SuiTe.Point().Add(libunlynx.SuiTe.Point().Mul(rangeProof.RP.Challenge, rangeProof.Commit.C), libunlynx.SuiTe.Point().Mul(rangeProof.RP.Zr, P))
	jBool := make([]bool, len(rangeProof.RP.Zphi))
	wg := libunlynx.StartParallelize(len(rangeProof.RP.Zphi))

	for j := 0; j < len(rangeProof.RP.Zphi); j++ {
		//p = B*u^j*Zphi_j
		//Dp = Cc + PZr + Sum(u^j*Zphi_j)
		point := libunlynx.SuiTe.Point().Set(libunlynx.IntToPoint(int64(math.Pow(float64(u), float64(j)))))
		point.Mul(rangeProof.RP.Zphi[j], point)
		Dp.Add(Dp, point)

		go func(j int) {
			defer wg.Done()
			jBool[j] = true

			//check bipairing
			//a_j = e(Vj,y)(c)+e(Vj,B)(-Zphi_j) + e(B,B)(Zv_j)
			//e(Vj,y*c)
			ap[j] = make([]kyber.Point, len(rangeProof.RP.A))
			for i := 0; i < len(rangeProof.RP.A); i++ {
				ap[j][i] = suitePair.Pair(libunlynx.SuiTe.Point().Mul(rangeProof.RP.Challenge, y[i]), rangeProof.RP.V[i][j])
				//e(Vj,y*c) + e(Vj,B)(Zphi_j)
				ap[j][i].Add(ap[j][i], suitePair.Pair(libunlynx.SuiTe.Point().Mul(libunlynx.SuiTe.Scalar().Neg(rangeProof.RP.Zphi[j]), libunlynx.SuiTe.Point().Base()), rangeProof.RP.V[i][j]))
				////e(Vj,y*c) + e(Vj,B)(Zphi_j) + e(B,B)(Zv_j)
				ap[j][i].Add(ap[j][i], suitePair.Pair(libunlynx.SuiTe.Point().Mul(rangeProof.RP.Zv[i][j], libunlynx.SuiTe.Point().Base()), g2.Point().Base()))

				if !ap[j][i].Equal(rangeProof.RP.A[i][j]) {
					//log.Lvl1("One a is not good")
					jBool[j] = false
				}
			}
		}(j)

	}
	libunlynx.EndParallelize(wg)

	result := true
	for _, v := range jBool {
		result = result && v
	}

	if !Dp.Equal(rangeProof.RP.D) {
		return false
	}
	return result
}

// TestContent contains a point
type TestContent struct {
	x kyber.Point
}

//CalculateHash computes a sha256 hash
func (t TestContent) CalculateHash() []byte {
	h := sha256.New()
	data, err := t.x.MarshalBinary()
	if err != nil {
		log.Fatal("Error in Marshal in Merkle")
	}
	h.Write(data)
	return h.Sum(nil)
}

//Equals tests for equality of two Contents
func (t TestContent) Equals(other merkletree.Content) bool {
	return t.x.Equal(other.(TestContent).x)
}

//ToBase transform n in base 10 to array in base b
func ToBase(n int64, b int64, l int) []int64 {

	digits := make([]int64, 0)
	for n > 0 {
		digits = append(digits, n%b)
		n = n / b
	}
	for len(digits) < l {
		digits = append(digits, 0)
	}
	return digits
}

//ReadColumn reads a column from a 2-D signatures object
func ReadColumn(sigs [][]PublishSignature, column int) []PublishSignature {
	sigi, _ := ReadColumnWithYs(sigs, column)
	return sigi
}

//ReadColumnWithYs reads signatures and Y parts of a column of signatures
func ReadColumnWithYs(sigs [][]PublishSignature, column int) ([]PublishSignature, []kyber.Point) {
	sigi := make([]PublishSignature, len(sigs))
	sigiY := make([]kyber.Point, len(sigs))
	for j := range sigs {
		sigi[j] = sigs[j][column]
		sigiY[j] = sigi[j].Public
	}
	return sigi, sigiY
}

//ReadColumnYs reads Y parts of a column of signatures
func ReadColumnYs(sigs []*[]PublishSignatureBytes, column int) []kyber.Point {
	sigiY := make([]kyber.Point, len(sigs))
	for j := range sigs {
		sigiY[j] = (*sigs[j])[column].Public
	}
	return sigiY
}
