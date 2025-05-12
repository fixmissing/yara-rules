
rule detect_judol_fake_shop
{
    meta:
        description = "Mendeteksi konten judi online yang disamarkan sebagai situs e-commerce"
        author = "Athallah x Cerberus"
        date = "2025-05-03"

    strings:
        $k0 = "aliexpress"
        $k1 = "amazon"
        $k2 = "bhinneka"
        $k3 = "blibli"
        $k4 = "bonus new member"
        $k5 = "bonus slot"
        $k6 = "bukalapak"
        $k7 = "childcategoryname"
        $k8 = "childcategoryurl"
        $k9 = "chip domino"
        $k10 = "daftar slot"
        $k11 = "data-cate"
        $k12 = "ebay"
        $k13 = "elevenia"
        $k14 = "jakartanotebook"
        $k15 = "jakmall"
        $k16 = "jd.id"
        $k17 = "k24klik"
        $k18 = "klikindomaret"
        $k19 = "lzd-site-menu-sub-item"
        $k20 = "olx"
        $k21 = "orami"
        $k22 = "produk maxwin"
        $k23 = "promo-maxwin.shop"
        $k24 = "ruparupa"
        $k25 = "shopee"
        $k26 = "shp.ee"
        $k27 = "sopi.vip"
        $k28 = "tokopedia"
        $k29 = "tokoslot"
        $k30 = "tokped.vip"
        $k31 = "topup slot"
        $k32 = "www.lazada.co.id"
        $k33 = "zalora"
        $k34 = "amz"
        $k35 = "cart.lazada.co.id"
        $k36 = "g.lazcdn.com"
        $k37 = "laz-img-cdn.alicdn.com"

    condition:
        3 of them
}

rule detect_judol_keyword
{
    meta:
        description = "Mendeteksi konten dengan kata eksplisit terkait judi online dan nama-nama slot"
        author = "Athallah x Cerberus"
        date = "2025-05-03"

    strings:
        $k0 = "bet"
        $k1 = "bola88"
        $k2 = "chip gratis"
        $k3 = "dana slot"
        $k4 = "gacor"
        $k5 = "jackpot"
        $k6 = "judi online"
        $k7 = "kasino"
        $k8 = "link rtp"
        $k9 = "live slot"
        $k10 = "login rtp"
        $k11 = "maxwin"
        $k12 = "pragmatic play"
        $k13 = "rtp live"
        $k14 = "situs slot"
        $k15 = "slot"
        $k16 = "togel"
        $k17 = "RTP"
        $k18 = "menang"
        $k19 = "toto"
        $k20 = "bocoran rtp"
        $k21 = "sweet bonanza"
        $k22 = "gate of olympus"
        $k23 = "starlight princess"
        $k24 = "pgsoft"
        $k25 = "habanero"
        $k26 = "microgaming"
        $k27 = "joker gaming"
        $k28 = "slot88"
        $k29 = "mahjong ways"
        $k30 = "wild west gold"
        $k31 = "jualtoto"
        $k32 = "slot gacor malam"
        $k33 = "agen777"
        $k34 = "aresgacor"
        $k35 = "vegaslot77"
        $k36 = "pragmatic"
        $k37 = "zeus"
        $k38 = "mahjong"
        $k39 = "mahjong ways"
        $k40 = "x1000"
        $k41 = "x500"

    condition:
        2 of them
}

rule safe_berita
{
    meta:
        description = "Menandai konten berita atau edukasi hukum agar tidak dikarantina"
        author = "Athallah x Cerberus"
        date = "2025-05-03"

    strings:
        $k0 = "kejaksaan"
        $k1 = "diadili"
        $k2 = "kecanduan"
        $k3 = "literasi keuangan"
        $k4 = "pinjol"
        $k5 = "tertangkap"
        $k6 = "peringatan"
        $k7 = "geram"
        $k8 = "bareskrim"
        $k9 = "ppatk"
        $k10 = "akun dibekukan"
        $k11 = "bappebti"
        $k12 = "dilarang"
        $k13 = "ditangkap"
        $k14 = "hukuman"
        $k15 = "kepolisian"
        $k16 = "kriminal"
        $k17 = "otoritas"
        $k18 = "pemberantasan"
        $k19 = "pemblokiran"
        $k20 = "pidana"
        $k21 = "regulasi"
        $k22 = "revisi uu"
        $k23 = "undang-undang"

    condition:
        2 of them
}


rule detect_amp_redirect
{
    meta:
        description = "Mendeteksi AMP redirect mencurigakan (digunakan untuk menyamarkan situs judi)"
        author = "Athallah x Cerberus"
        date = "2025-05-03"

    strings:
        $amp1 = "<link rel=\"amphtml\""
        $amp2 = ".pages.dev"
        $amp3 = ".slotgacor"
        $amp4 = "?haha="
        $amp5 = "amp slot"
        $amp6 = "amp jackpot"
        $amp7 = ".b-cdn.net"
        $amp8 = ".cloudfront.net"

    condition:
        2 of them
}

rule detect_hidden_judol_slot_meta
{
    meta:
        description = "Deteksi situs slot terselubung dengan meta tag dan AMP redirect"
        author = "Athallah x Cerberus"
        date = "2025-05-03"

    strings:
        $s0 = "<meta property=\"og:type\" content=\"product\">"
        $s1 = "<meta name=\"description\" content=\".*slot"
        $s2 = "<meta property=\"og:title\" content=\".*maxwin"
        $s3 = "<link rel=\"amphtml\" href=\"https://.*pages.dev"
        $s4 = "<link rel=\"manifest\" href=\"https://.*pwa-assets/"
        $s5 = "VEGASSLOT77"
        $s6 = "ARESGACOR"

    condition:
        2 of them
}
