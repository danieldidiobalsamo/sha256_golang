package sha256_golang

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSigma0(t *testing.T) {
	assert.Equal(t, sigma_0(0), uint32(0))
	assert.Equal(t, sigma_0(0x3fd29f6b), uint32(0x765f3927))
}

func TestSigma1(t *testing.T) {
	assert.Equal(t, sigma_1(0), uint32(0))
	assert.Equal(t, sigma_1(0x98469ec2), uint32(0x9c9f0e8c))
}

func TestBigSigma0(t *testing.T) {
	assert.Equal(t, bigSigma_0(0x5c6f9c99), uint32(0xda3612b))
}

func TestBigSigma1(t *testing.T) {
	assert.Equal(t, bigSigma_1(0x8236fd0f), uint32(0x84861aea))
}

func TestChoice(t *testing.T) {
	ch := choice(0x8236fd0f, 0x5610b48b, 0x68977312)
	assert.Equal(t, ch, uint32(0x6a91b61b))
}

func TestMajority(t *testing.T) {
	maj := majority(0x5c6f9c99, 0x802dec24, 0xe18de1a7)
	assert.Equal(t, maj, uint32(0xc02deca5))
}
