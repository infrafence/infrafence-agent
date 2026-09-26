package dnswatch

// The most frequent letter pairs in English text (and common in most
// Latin-script languages and brand names). Real words are made mostly of
// them; the random strings of DGA malware mostly aren't.
const commonBigramList = "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo ek ze za zo ka ko ku ja je ji ks kt"

var commonBigrams = func() map[string]bool {
	m := map[string]bool{}
	for i := 0; i+2 <= len(commonBigramList); i += 3 {
		m[commonBigramList[i:i+2]] = true
	}
	return m
}()

// wordLikeness is the share of the label's letter pairs that are common;
// pairs with digits or hyphens count as uncommon.
func wordLikeness(label string) float64 {
	if len(label) < 2 {
		return 1
	}
	common, total := 0, 0
	for i := 0; i+1 < len(label); i++ {
		total++
		if commonBigrams[label[i:i+2]] {
			common++
		}
	}
	return float64(common) / float64(total)
}
