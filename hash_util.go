package SSHUtil

import "crypto/sha256"

func PerformOneWayHash(word string) [32]byte {
	sum := sha256.Sum256([]byte(word))
	return sum
}
