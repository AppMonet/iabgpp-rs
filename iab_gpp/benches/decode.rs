use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iab_gpp::sections::tcfeuv2::TcfEuV2;
use iab_gpp::v1::GPPString;
use std::str::FromStr;

const GPP_TCF_EU_USP: &str = "DBACNY~CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA~1YNN";
const TCF_EU_V2: &str = "CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA";

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
    bench_gpp_decode_all_sections
);
criterion_main!(benches);
