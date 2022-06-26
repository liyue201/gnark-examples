package main

//function div_ceil(m, n) {
//    var ret = 0;
//    if (m % n == 0) {
//        ret = m \ n;
//    } else {
//        ret = m \ n + 1;
//    }
//    return ret;
//}

func DivCel(m, n int) int {
	if m%n == 0 {
		return m / n
	}
	return m/n + 1
}
