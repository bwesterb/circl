package internal

import (
	"encoding/binary"
	"testing"

	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

func TestVectorDeriveUniform(t *testing.T) {
	var p, p2 common.Poly
	var seed [32]byte
	if UseAES {
		p2 = common.Poly{
			6724291, 310295, 6949524, 4464039, 1482136, 2522903,
			7025059, 3006320, 7286364, 7516512, 3361305, 1955529,
			4765954, 1725325, 6933066, 4299100, 6625173, 4272792,
			583034, 4971409, 2259140, 7715362, 3975394, 2341624,
			5481174, 8150082, 365246, 5491939, 1083120, 7517301,
			3104783, 2475292, 184149, 6425226, 4591622, 5964030,
			4729604, 5471092, 1828227, 1082044, 2516245, 1692580,
			3274844, 5443294, 7256740, 4989638, 3191250, 7479519,
			5124211, 5603858, 1230692, 2513454, 2828034, 4254312,
			1512596, 5245430, 5517392, 2814840, 932545, 6826733,
			3511094, 4075348, 3233981, 7268882, 2913733, 4870249,
			4123492, 8124406, 4016949, 5478752, 2750895, 603525,
			5724798, 3985430, 3483012, 6434230, 3136996, 8297976,
			4107616, 7307748, 6962904, 7544473, 1193110, 3448595,
			4814773, 5607932, 8221314, 1054046, 1541208, 1866050,
			8227412, 2925778, 5293953, 2065416, 4972769, 3616283,
			7990594, 1105530, 7121836, 1170740, 7417431, 633146,
			253820, 7235019, 3539504, 6807707, 451390, 5481526,
			2859902, 1063061, 4579730, 7126652, 7033767, 4294814,
			1414604, 7620048, 1953268, 8304556, 1156814, 1182881,
			5311519, 3057534, 5277666, 682843, 2070398, 2874278,
			4859533, 6376664, 6694074, 1590242, 2620706, 8331066,
			5643845, 5037538, 2891516, 7004879, 3754327, 5031296,
			5463118, 2420870, 8116529, 5517696, 7435129, 3873963,
			710407, 713806, 175647, 4274571, 2655021, 7319503,
			3027243, 7129679, 4213435, 2429323, 4643873, 4568526,
			649664, 1720514, 6497260, 2683517, 7672754, 7105190,
			3148405, 5898369, 5667677, 8050874, 1587139, 7315260,
			4337416, 2202680, 2338714, 557467, 6752058, 2469794,
			485071, 1617604, 3590498, 2151466, 2005823, 7727956,
			7776292, 6783433, 6787146, 1732833, 3596857, 7436284,
			4483349, 4970142, 4472608, 6478342, 1236215, 5695744,
			2280717, 2889355, 3233946, 5187812, 978685, 5177364,
			2922353, 4824807, 5302883, 6739803, 8092453, 5883903,
			816553, 6041174, 8317591, 1459178, 5332455, 1835058,
			1368601, 2820950, 3479224, 2589540, 7992934, 3421045,
			4657128, 8292902, 4153567, 3553988, 7830320, 6722913,
			2555309, 4149801, 8328975, 1560545, 7757473, 3106458,
			4310856, 7135453, 3481032, 652626, 1841361, 8126828,
			6250018, 300536, 7380070, 8174419, 1418793, 6208185,
			3906256, 6679016, 1605701, 3561489, 5819724, 5746996,
			8044214, 7087187, 7102330, 4962927, 4253983, 7108567,
			4119736, 6584065, 441634, 6941656,
		}
	} else {
		p2 = common.Poly{
			2901364, 562527, 5258502, 3885002, 4190126, 4460268, 6884052,
			3514511, 5383040, 213206, 2155865, 5179607, 3551954, 2312357,
			6066350, 8126097, 1179080, 4787182, 6552182, 6713644,
			1561067, 7626063, 7859743, 5052321, 7032876, 7815031, 157938,
			1865184, 490802, 5717642, 3451902, 7000218, 3743250, 1677431,
			1875427, 5596150, 671623, 3819041, 6247594, 1014875, 4933545,
			7122446, 6682963, 3388398, 3335295, 943002, 1145083, 3113071,
			105967, 1916675, 7474561, 1107006, 700548, 2147909, 1603855,
			5049181, 437882, 6118899, 5656914, 6731065, 3066622, 865453,
			5427634, 981549, 4650873, 861291, 4003872, 5104220, 6171453,
			3723302, 7426315, 6137283, 4874820, 6052561, 53441, 5032874,
			5614778, 2248550, 1756499, 8280764, 8263880, 7600081,
			5118374, 795344, 7543392, 6869925, 1841187, 4181568, 584562,
			7483939, 4938664, 6863397, 5126354, 5218129, 6236086,
			4149293, 379169, 4368487, 7490569, 3409215, 1580463, 3081737,
			1278732, 7109719, 7371700, 2097931, 399836, 1700274, 7188595,
			6830029, 1548850, 6593138, 6849097, 1518037, 2859442,
			7772265, 7325153, 3281191, 7856131, 4995056, 4684325,
			1351194, 8223904, 6817307, 2484146, 131782, 397032, 7436778,
			7973479, 3171829, 5624626, 3540123, 7150120, 8313283,
			3604714, 1043574, 117692, 7797783, 7909392, 903315, 7335342,
			7501562, 5826142, 2709813, 8245473, 2369045, 2782257,
			5762833, 6474114, 6862031, 424522, 594248, 2626630, 7659983,
			5642869, 4075194, 1592129, 245547, 5271031, 3205046, 982375,
			267873, 1286496, 7230481, 3208972, 7485411, 676111, 4944500,
			2959742, 5934456, 1414847, 6067948, 1709895, 4648315, 126008,
			8258986, 2183134, 2302072, 4674924, 4306056, 7465311,
			6500270, 4247428, 4016815, 4973426, 294287, 2456847, 3289700,
			2732169, 1159447, 5569724, 140001, 3237977, 8007761, 5874533,
			255652, 3119586, 2102434, 6248250, 8152822, 8006066, 7708625,
			6997719, 6260212, 6186962, 6636650, 7836834, 7998017,
			2061516, 1197591, 1706544, 733027, 2392907, 2700000, 8254598,
			4488002, 160495, 2985325, 2036837, 2703633, 6406550, 3579947,
			6195178, 5552390, 6804584, 6305468, 5731980, 6095195,
			3323409, 1322661, 6690942, 3374630, 5615167, 479044, 3136054,
			4380418, 2833144, 7829577, 1770522, 6056687, 240415, 14780,
			3740517, 5224226, 3547288, 2083124, 4699398, 3654239,
			5624978, 585593, 3655369, 2281739, 3338565, 1908093, 7784706,
			4352830,
		}
	}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniform(&p, &seed, 30000)
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}

func TestDeriveUniform(t *testing.T) {
	var p common.Poly
	var seed [32]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniform(&p, &seed, uint16(i))
		if !PolyNormalized(&p) {
			t.Fatal()
		}
	}
}

func TestDeriveUniformLeqEta(t *testing.T) {
	var p common.Poly
	var seed [32]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniformLeqEta(&p, &seed, uint16(i))
		for j := 0; j < common.N; j++ {
			if p[j] < common.Q-Eta || p[j] > common.Q+Eta {
				t.Fatal()
			}
		}
	}
}

func TestDeriveUniformLeGamma1(t *testing.T) {
	var p common.Poly
	var seed [48]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniformLeGamma1(&p, &seed, uint16(i))
		for j := 0; j < common.N; j++ {
			if p[j] < common.Q-common.Gamma1 || p[j] > common.Q+common.Gamma1 {
				t.Fatal()
			}
		}
	}
}

func TestVectorDeriveUniformLeGamma1(t *testing.T) {
	var p, p2 common.Poly
	var seed [48]byte
	if UseAES {
		p2 = common.Poly{
			90940, 8133770, 8210940, 8218464, 8362467, 431142, 98024,
			320453, 7892373, 144162, 495313, 7910122, 308198, 8024421,
			8313699, 8323445, 8242093, 7946588, 418979, 427179, 353562,
			20972, 455962, 213062, 361787, 8141790, 8321931, 7885366,
			88645, 181202, 8094142, 8303121, 8059515, 7919812, 191865,
			7910073, 7896561, 8096830, 7899355, 8338900, 72693, 236799,
			8183042, 347570, 8153528, 8364233, 8077851, 8312277, 104682,
			8037310, 8356199, 7994081, 240369, 70229, 8108858, 8175836,
			466639, 50909, 339919, 8029663, 341659, 154398, 64345,
			97101, 212245, 8285367, 521225, 325882, 296235, 8110929,
			8015814, 7953234, 158409, 329908, 8331330, 449258, 167701,
			8197796, 8228247, 7940020, 1985, 304704, 475316, 8037482,
			8250449, 304557, 8216567, 432266, 213295, 8162216, 381001,
			7995314, 7988689, 128534, 245586, 67041, 8232744, 398441,
			223116, 443612, 149856, 222852, 158723, 54746, 171906,
			163070, 353915, 8263276, 8016812, 8229081, 31827, 489715,
			450171, 8069106, 53220, 7932381, 7955335, 8197363, 201044,
			8306733, 446376, 8211025, 7889271, 8070595, 495514, 8158685,
			7524, 7973394, 247673, 4293, 184924, 457334, 138349, 8123964,
			284179, 8255307, 8068216, 8291492, 243759, 8060601, 20962,
			8058389, 420953, 8305974, 455136, 8218139, 7121, 147703,
			7951253, 394376, 8127066, 365861, 8062390, 8138732, 366555,
			8280514, 221, 395861, 7968769, 7977119, 8098083, 343056,
			8190769, 223361, 163270, 203059, 109219, 8228600, 8127695,
			321016, 295979, 8201961, 49891, 8335504, 8190386, 8190984,
			8278654, 336364, 7878013, 7922436, 7974101, 8075534, 8200852,
			8333820, 415982, 8089662, 149553, 7946740, 474102, 7937116,
			8026845, 356056, 191053, 86928, 8218644, 8375040, 8029184,
			8025675, 8193350, 295360, 7905768, 487174, 8362961, 386108,
			282213, 8373318, 50167, 8238992, 7911505, 493459, 8335164,
			8079327, 250697, 263154, 221028, 40778, 87515, 8372585,
			504728, 7980935, 8307600, 298972, 427523, 93352, 89915,
			391490, 80320, 7975008, 336136, 7949815, 8048682, 8332244,
			8204778, 8177783, 7910684, 7925292, 518641, 59663, 53608,
			222225, 463772, 8022091, 8173722, 8291385, 472741, 8105898,
			7943299, 267137, 7957660, 371874, 409084, 203750, 477334,
			83412, 111278, 120444,
		}
	} else {
		p2 = common.Poly{
			338083, 7978692, 8044913, 373628, 427855, 79725, 91018,
			349821, 501552, 7955127, 8316400, 290708, 216142, 8199666,
			8040144, 109426, 8177916, 8200218, 8125680, 358131, 160961,
			497383, 25361, 156297, 8033745, 7897189, 48397, 498732,
			464556, 7862704, 8308667, 236080, 91240, 8328377, 326190,
			509979, 8313264, 8106493, 8210965, 8328036, 172602, 8108765,
			8192963, 8361660, 8026473, 7932022, 322006, 8305874, 8254440,
			7866474, 373371, 8023413, 8221878, 486124, 36080, 8324512,
			8042056, 7984472, 8048111, 7910387, 8205382, 8259636, 188609,
			8316587, 59306, 119803, 8067108, 8155455, 8153450, 7983908,
			8222256, 21521, 114297, 8069037, 151621, 8014482, 8052856,
			376107, 8004652, 175001, 8079461, 8351123, 8021484, 144547,
			7908116, 8278100, 8136941, 142399, 8026843, 8081852, 124334,
			242796, 266768, 7919478, 7954016, 28927, 8329064, 514031,
			423911, 27907, 8142788, 8078298, 273978, 382723, 8148646,
			186476, 8030712, 8067268, 356250, 145817, 60045, 122764,
			56856, 8225416, 136437, 199652, 8343127, 8109765, 7936848,
			446966, 8351681, 288663, 409663, 512988, 8350788, 8191864,
			8366223, 281267, 7921696, 8213978, 442484, 67457, 8030602,
			238514, 230458, 8301866, 8359700, 150320, 143893, 461735,
			225443, 8027502, 151113, 365244, 7911438, 82498, 405398,
			8207009, 8108255, 367485, 514660, 8294055, 8168958, 127725,
			402955, 8051625, 7859029, 7980052, 321819, 7949587, 125778,
			8287078, 131972, 499609, 256795, 8180323, 8269393, 5878,
			8145473, 8238676, 383855, 415547, 424071, 241989, 8165743,
			8207329, 149608, 8315331, 7901850, 8114275, 360650, 516061,
			255090, 8277977, 270877, 8125200, 479248, 7991711, 8028595,
			73426, 8215429, 208217, 153872, 429336, 229856, 461204,
			236682, 7930158, 8298847, 228327, 8009399, 8111520, 345025,
			386495, 93454, 8336429, 8161305, 7980811, 286795, 162808,
			224476, 7972825, 85118, 287488, 8029791, 119071, 371, 518524,
			473496, 451205, 127000, 19233, 211519, 2442, 7950959, 481888,
			8041598, 8281176, 437202, 7912610, 8080153, 8237500, 7926828,
			8009421, 204880, 62495, 8192310, 8314388, 98616, 182368,
			323894, 59901, 481049, 8139275, 7872144, 254106, 376257,
			93339, 301342, 366536, 438920, 84773, 461471, 8125755,
			7930085, 405116,
		}
	}
	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeGamma1(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}

func TestDeriveUniformB60(t *testing.T) {
	var p common.Poly
	var w1 VecK
	var seed [48]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniformB60(&p, &seed, &w1)
		nonzero := 0
		for j := 0; j < common.N; j++ {
			if p[j] != 0 {
				if p[j] != 1 && p[j] != common.Q-1 {
					t.Fatal()
				}
				nonzero++
			}
		}
		if nonzero != 60 {
			t.Fatal()
		}
	}
}

func TestDeriveUniformX4(t *testing.T) {
	if !PolyDeriveUniformX4Available {
		t.SkipNow()
	}
	var ps [4]common.Poly
	var p common.Poly
	var seed [32]byte
	nonces := [4]uint16{12345, 54321, 13532, 37377}

	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	PolyDeriveUniformX4([4]*common.Poly{&ps[0], &ps[1], &ps[2], &ps[3]}, &seed,
		nonces)
	for i := 0; i < 4; i++ {
		PolyDeriveUniform(&p, &seed, nonces[i])
		if ps[i] != p {
			t.Fatal()
		}
	}
}
