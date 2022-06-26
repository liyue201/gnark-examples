package main

import "math/big"

// returns G * 2 ** 255
// TODO check that this is correct...
func GetDummyPoint(n, k int) [2][100]big.Int {
	//assert(n == 86 && k == 3 || n == 64 && k == 4);
	var ret [2][100]big.Int
	if k == 3 {
		ret[0][0].SetString("34318960048412842733519232", 10)
		ret[0][1].SetString("3417427387252098100392906", 10)
		ret[0][2].SetString("2056756886390887154635856", 10)
		ret[1][0].SetString("35848273954982567597050105", 10)
		ret[1][1].SetString("74802087901123421621824957", 10)
		ret[1][2].SetString("4851915413831746153124691", 10)
	} else {
		ret[0][0].SetString("10184385086782357888", 10)
		ret[0][1].SetString("16068507144229249874", 10)
		ret[0][2].SetString("17097072337414981695", 10)
		ret[0][3].SetString("1961476217642676500", 10)
		ret[1][0].SetString("15220267994978715897", 10)
		ret[1][1].SetString("2812694141792528170", 10)
		ret[1][2].SetString("9886878341545582154", 10)
		ret[1][3].SetString("4627147115546938088", 10)
	}
	return ret
}
