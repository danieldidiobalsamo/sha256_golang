package sha256_algo

//    This code defines a structure for variables named as "working variables" in SHA specification
//    It stores intermediary values for the compression function.
//
//    All variables names in this module (a, b, ..., h) are the same as in the specification's formulas

type workingVariables struct {
	a, b, c, d, e, f, g, h uint32
}

func newWorkingVariables(val []uint32) workingVariables {
	return workingVariables{val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]}
}
