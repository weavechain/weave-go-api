package weaveapi

type JavaRandom struct {
	seed int64
}

func NewRandom(seed int64) JavaRandom {
	s := (seed ^ 0x5DEECE66D) & ((int64(1) << 48) - 1)
	return JavaRandom{seed: s}
}

func (random *JavaRandom) Next(bits int64) int64 {
	if bits < 1 {
		bits = 1
	} else if bits > 32 {
		bits = 32
	}

	random.seed = (random.seed*0x5DEECE66D + 0xB) & ((int64(1) << 48) - 1)

	return int64(random.seed >> (48 - bits))
}

func (random *JavaRandom) NextInt(bound int64) (int64, error) {
	if bound <= 0 {
		panic("Argument must be positive!")
	} else if bound > 32 {
		return random.Next(32), nil
	}

	if (bound & -bound) == bound {
		return (bound * int64(random.Next(31))) >> 31, nil
	}

	var bits, val int64
	for next := true; next; next=(bits - val + (bound - 1) < 0) {
		bits = random.Next(31)
		val = bits % int64(bound)
	}
	return val, nil
}

func (random *JavaRandom) NextBytes(l *[32]int64) {

	var n int64
	var b int64
	for i := 0; i < len((*l)); i++ {
		if i % 4 == 0 {
			n = random.Next(32)
		}
		b = n & 0xFF
		if b & 0x80 != 0 {
			b -= 0x100
		}
		(*l)[i] = b
		n >>= 8
	}
}
