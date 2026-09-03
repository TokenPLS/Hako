package sudoku

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"strings"
)

var (
	ErrInvalidSudokuMapMiss = errors.New("INVALID_SUDOKU_MAP_MISS")
)

type Table struct {
	EncodeTable [256][][4]byte
	DecodeMap   map[uint32]byte
	PaddingPool []byte
	IsASCII     bool
	layout      *byteLayout
	opposite    *Table
	hint        uint32
}

// NewTable initializes the obfuscation tables with built-in layouts.
// Equivalent to calling NewTableWithCustom(key, mode, "").
func NewTable(key string, mode string) *Table {
	t, err := NewTableWithCustom(key, mode, "")
	if err != nil {
		panic(err)
	}
	return t
}

// NewTableWithCustom initializes the uplink/probe Sudoku table using either predefined
// or directional layouts. Directional modes such as "up_ascii_down_entropy" return the
// client->server table and internally attach the opposite direction table for runtime use.
// The customPattern must contain 8 characters with exactly 2 x, 2 p, and 4 v (case-insensitive).
func NewTableWithCustom(key string, mode string, customPattern string) (*Table, error) {
	asciiMode, err := ParseASCIIMode(mode)
	if err != nil {
		return nil, err
	}

	uplinkPattern := customPatternForToken(asciiMode.Uplink, customPattern)
	downlinkPattern := customPatternForToken(asciiMode.Downlink, customPattern)
	hint := tableHintFingerprint(key, asciiMode.Canonical(), uplinkPattern, downlinkPattern)

	uplink, err := newSingleDirectionTable(key, asciiMode.uplinkPreference(), uplinkPattern)
	if err != nil {
		return nil, err
	}
	uplink.hint = hint
	if asciiMode.Uplink == asciiMode.Downlink {
		uplink.opposite = uplink
		return uplink, nil
	}

	downlink, err := newSingleDirectionTable(key, asciiMode.downlinkPreference(), downlinkPattern)
	if err != nil {
		return nil, err
	}
	downlink.hint = hint
	uplink.opposite = downlink
	downlink.opposite = uplink
	return uplink, nil
}

func newSingleDirectionTable(key string, mode string, customPattern string) (*Table, error) {
	layout, err := resolveLayout(mode, customPattern)
	if err != nil {
		return nil, err
	}

	t := &Table{
		DecodeMap: make(map[uint32]byte),
		IsASCII:   layout.name == "ascii",
		layout:    layout,
	}
	t.PaddingPool = append(t.PaddingPool, layout.paddingPool...)

	allGrids := GenerateAllGrids()
	h := sha256.New()
	h.Write([]byte(key))
	seed := int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
	rng := rand.New(rand.NewSource(seed))

	shuffledGrids := make([]Grid, 288)
	copy(shuffledGrids, allGrids)
	rng.Shuffle(len(shuffledGrids), func(i, j int) {
		shuffledGrids[i], shuffledGrids[j] = shuffledGrids[j], shuffledGrids[i]
	})

	var combinations [][]int
	var combine func(int, int, []int)
	combine = func(s, k int, c []int) {
		if k == 0 {
			tmp := make([]int, len(c))
			copy(tmp, c)
			combinations = append(combinations, tmp)
			return
		}
		for i := s; i <= 16-k; i++ {
			c = append(c, i)
			combine(i+1, k-1, c)
			c = c[:len(c)-1]
		}
	}
	combine(0, 4, []int{})

	for byteVal := 0; byteVal < 256; byteVal++ {
		targetGrid := shuffledGrids[byteVal]
		for _, positions := range combinations {
			var currentHints [4]byte

			var rawParts [4]struct{ val, pos byte }

			for i, pos := range positions {
				val := targetGrid[pos] // 1..4
				rawParts[i] = struct{ val, pos byte }{val, uint8(pos)}
			}

			matchCount := 0
			for _, g := range allGrids {
				match := true
				for _, p := range rawParts {
					if g[p.pos] != p.val {
						match = false
						break
					}
				}
				if match {
					matchCount++
					if matchCount > 1 {
						break
					}
				}
			}

			if matchCount == 1 {
				for i, p := range rawParts {
					currentHints[i] = t.layout.hintByte(p.val-1, p.pos)
				}

				t.EncodeTable[byteVal] = append(t.EncodeTable[byteVal], currentHints)
				key := packHintsToKey(currentHints)
				t.DecodeMap[key] = byte(byteVal)
			}
		}
	}
	return t, nil
}

func customPatternForToken(token string, customPattern string) string {
	if token == asciiModeTokenEntropy {
		return customPattern
	}
	return ""
}

func (t *Table) OppositeDirection() *Table {
	if t == nil || t.opposite == nil {
		return t
	}
	return t.opposite
}

func (t *Table) Hint() uint32 {
	if t == nil {
		return 0
	}
	return t.hint
}

func tableHintFingerprint(key string, mode string, uplinkPattern string, downlinkPattern string) uint32 {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"sudoku-table-hint",
		key,
		mode,
		strings.ToLower(strings.TrimSpace(uplinkPattern)),
		strings.ToLower(strings.TrimSpace(downlinkPattern)),
	}, "\x00")))
	return binary.BigEndian.Uint32(sum[:4])
}

func packHintsToKey(hints [4]byte) uint32 {
	return packHintBytes(hints[0], hints[1], hints[2], hints[3])
}

func packHintBytes(h0, h1, h2, h3 byte) uint32 {
	// Sorting network for 4 elements (Bubble sort unrolled)
	// Swap if a > b
	if h0 > h1 {
		h0, h1 = h1, h0
	}
	if h2 > h3 {
		h2, h3 = h3, h2
	}
	if h0 > h2 {
		h0, h2 = h2, h0
	}
	if h1 > h3 {
		h1, h3 = h3, h1
	}
	if h1 > h2 {
		h1, h2 = h2, h1
	}

	return uint32(h0)<<24 | uint32(h1)<<16 | uint32(h2)<<8 | uint32(h3)
}
