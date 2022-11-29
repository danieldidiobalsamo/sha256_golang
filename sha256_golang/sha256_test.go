package sha256_golang

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func getShortMessage() string {
	return "hi"
}

func getLongMessage() string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func getShortPreProcessed() []rune {
	rawMsg := getShortMessage()
	return PreProcess([]rune(rawMsg))
}

func TestPreProcessShort(t *testing.T) {

	rawMsg := getShortMessage()
	msg := PreProcess([]rune(rawMsg))

	pre_processed_bytes := []rune{104, 105, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 16}

	assert.Equal(t, pre_processed_bytes, msg)
}

func TestPreProcessLong(t *testing.T) {

	rawMsg := getLongMessage()
	msg := PreProcess([]rune(rawMsg))

	pre_processed_bytes := []rune{97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 128, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 88}

	assert.Equal(t, pre_processed_bytes, msg)
}

func TestParseBlockValid(t *testing.T) {

	msg := getShortPreProcessed()

	block, _ := ParseBlock(msg, 0)

	valid_block := []rune{104, 105, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 16}

	assert.Equal(t, valid_block, block)
}

func TestParseBlockInvalid(t *testing.T) {

	msg := getShortPreProcessed()

	block, err := ParseBlock(msg, 65)

	assert.Equal(t, []int32([]int32(nil)), block)
	assert.EqualError(t, err, "index is greater than the number of 512-bits blocks")

}
