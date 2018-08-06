package pac

import (
	"testing"
)


func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}


func TestIp2Long(t *testing.T){
	assertEqual(t, ip2Long("172.16.0.0"), uint32(2886729728))
	assertEqual(t, ip2Long("255.240.0.0"), uint32(4293918720))

}

func TestGeneratePac(t *testing.T){
	generatePac("ac")
}

func TestFetchIpData(t *testing.T)  {
	fetchIpData()
}