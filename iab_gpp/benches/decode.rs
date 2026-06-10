use criterion::{Criterion, black_box, criterion_group, criterion_main};
use iab_gpp::sections::tcfeuv2::TcfEuV2;
use iab_gpp::v1::GPPString;
use std::str::FromStr;

const GPP_TCF_EU_USP: &str = "DBACNY~CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA~1YNN";
const TCF_EU_V2: &str = "CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA";
// Production-sized consent string with a dense vendor-consent bitfield
// (hundreds of set bits) — the dominant decode shape in ad-serving traffic.
const TCF_EU_V2_LARGE: &str = "CO8_rkAO8_rkAAcABBENBACgAAAAAIAAACiQg1NX_H__bX9v-X7_6ft0eY1f9_j77sQxBhfJs-4F3LvW_JwX32E7NF36tq4KmRoEu3ZBIUNtHJnUTVmxaogVrzHsakWcoTNKJ-BkkHMRe2dYCF5vm4tjeQKZ5_p_d3f52T_9_dv-39zz39Vnv3e9fuf1-Pjde5_9H_v_fRfb-_If9_7-_8v8_t_rk2_eT1__9evv__--________9_8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAEDggCTDUvgIsxLDAkkDSqFECEK4gMgAAAAQjA0TUABAwKdkYBD6CBgAgNQEYEQIEAUYsggAAAAASiICQAsEACAIgEAAIAUICEABAgCCgAkDAIAAQDQMAAoABAkIEjgqOUwICIFogJZKwBKKqQwwhCKCACgAAAA.YAAAAAAAAAAA";

fn bench_gpp_parse(c: &mut Criterion) {
    c.bench_function("gpp_parse", |b| {
        b.iter(|| {
            let gpp = GPPString::from_str(black_box(GPP_TCF_EU_USP)).unwrap();
            black_box(gpp);
        });
    });
}

fn bench_tcf_eu_v2_decode(c: &mut Criterion) {
    c.bench_function("tcf_eu_v2_decode", |b| {
        b.iter(|| {
            let section = TcfEuV2::from_str(black_box(TCF_EU_V2)).unwrap();
            black_box(section);
        });
    });
}

fn bench_tcf_eu_v2_decode_large(c: &mut Criterion) {
    c.bench_function("tcf_eu_v2_decode_large", |b| {
        b.iter(|| {
            let section = TcfEuV2::from_str(black_box(TCF_EU_V2_LARGE)).unwrap();
            black_box(section);
        });
    });
}

fn bench_gpp_decode_all_sections(c: &mut Criterion) {
    c.bench_function("gpp_decode_all_sections", |b| {
        b.iter(|| {
            let gpp = GPPString::from_str(black_box(GPP_TCF_EU_USP)).unwrap();
            let decoded = gpp.decode_all_sections();
            black_box(decoded);
        });
    });
}

criterion_group!(
    benches,
    bench_gpp_parse,
    bench_tcf_eu_v2_decode,
    bench_tcf_eu_v2_decode_large,
    bench_gpp_decode_all_sections
);
criterion_main!(benches);
