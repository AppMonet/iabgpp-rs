use crate::core::{DataRead, Range, base64_bit_reader};
use crate::sections::{IdSet, SectionDecodeError};
use bitstream_io::BitRead;
use iab_gpp_derive::{FromBitStream, GPPSection};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, GPPSection)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
#[gpp(with_optional_segments)]
pub struct TcfEuV2 {
    pub core: Core,
    #[gpp(optional_segment_type = 1, optimized_integer_range)]
    pub disclosed_vendors: Option<IdSet>,
    #[gpp(optional_segment_type = 2, optimized_integer_range)]
    pub allowed_vendors: Option<IdSet>,
    #[gpp(optional_segment_type = 3)]
    pub publisher_purposes: Option<PublisherPurposes>,
}

impl TcfEuV2 {
    /// Decodes only the core segment of a TC string.
    ///
    /// Gives the same result as `TcfEuV2::from_str(s).map(|tcf| tcf.core)`:
    /// the optional segments are still checked and any error they raise is
    /// returned, but their vendor ids are skipped instead of collected.
    pub fn decode_core(s: &str) -> Result<Core, SectionDecodeError> {
        let mut segments = s.split('.');
        let core = segments.next().unwrap_or_default();
        let core: Core = base64_bit_reader(core.as_bytes()).parse()?;

        let mut seen = 0u8;
        for segment in segments {
            let mut r = base64_bit_reader(segment.as_bytes());
            let segment_type = r.read_unsigned::<3, u8>()?;
            match segment_type {
                1 | 2 => skip_optimized_integer_range(&mut r)?,
                3 => {
                    r.parse::<PublisherPurposes>()?;
                }
                n => return Err(SectionDecodeError::UnknownSegmentType { segment_type: n }),
            }
            let bit = 1u8 << segment_type;
            if seen & bit != 0 {
                return Err(SectionDecodeError::DuplicateSegmentType { segment_type });
            }
            seen |= bit;
        }

        Ok(core)
    }
}

/// Reads past an optimized integer range, failing exactly where
/// `read_optimized_integer_range` would.
fn skip_optimized_integer_range<R: BitRead + ?Sized>(r: &mut R) -> std::io::Result<()> {
    let bits = r.read_unsigned::<16, u16>()? as u32;
    if r.read_bit()? {
        for _ in 0..r.read_unsigned::<12, u16>()? {
            let is_group = r.read_bit()?;
            r.read_unsigned::<16, u16>()?;
            if is_group {
                r.read_unsigned::<16, u16>()?;
            }
        }
    } else {
        let mut remaining = bits;
        while remaining > 0 {
            let take = remaining.min(32);
            r.read_unsigned_var::<u32>(take)?;
            remaining -= take;
        }
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq, FromBitStream)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
#[gpp(section_version = 2)]
pub struct Core {
    #[gpp(datetime_as_unix_timestamp)]
    pub created: u64,
    #[gpp(datetime_as_unix_timestamp)]
    pub last_updated: u64,
    pub cmp_id: u16,
    pub cmp_version: u16,
    pub consent_screen: u8,
    #[gpp(string(2))]
    pub consent_language: String,
    pub vendor_list_version: u16,
    pub policy_version: u8,
    pub is_service_specific: bool,
    pub use_non_standard_stacks: bool,
    #[gpp(fixed_bitfield(12))]
    pub special_feature_optins: IdSet,
    #[gpp(fixed_bitfield(24))]
    pub purpose_consents: IdSet,
    #[gpp(fixed_bitfield(24))]
    pub purpose_legitimate_interests: IdSet,
    pub purpose_one_treatment: bool,
    #[gpp(string(2))]
    pub publisher_country_code: String,
    #[gpp(optimized_integer_range)]
    pub vendor_consents: IdSet,
    #[gpp(optimized_integer_range)]
    pub vendor_legitimate_interests: IdSet,
    #[gpp(parse_with = parse_publisher_restrictions)]
    pub publisher_restrictions: Vec<PublisherRestriction>,
}

fn parse_publisher_restrictions<R: BitRead + ?Sized>(
    r: &mut R,
) -> Result<Vec<PublisherRestriction>, SectionDecodeError> {
    let num_restrictions = r.read_unsigned::<12, u16>()?;
    let mut restrictions = Vec::with_capacity(num_restrictions as usize);

    for _ in 0..num_restrictions {
        let purpose_id = match r.read_unsigned::<6, u8>() {
            Ok(purpose_id) => purpose_id,
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(source) => return Err(SectionDecodeError::Read { source }),
        };
        let restriction_type = match r.read_unsigned::<2, u8>() {
            Ok(restriction_type) => restriction_type,
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(source) => return Err(SectionDecodeError::Read { source }),
        };
        let restricted_vendor_ids =
            match read_publisher_restriction_integer_range_compat(r, restrictions.len())? {
                Some(ids) => ids,
                None => break,
            };

        restrictions.push(PublisherRestriction {
            purpose_id,
            restriction_type: RestrictionType::from_u8(restriction_type)
                .unwrap_or(RestrictionType::Undefined),
            restricted_vendor_ids,
        });
    }

    Ok(restrictions)
}

fn read_publisher_restriction_integer_range_compat<R: BitRead + ?Sized>(
    r: &mut R,
    restriction_idx: usize,
) -> Result<Option<IdSet>, SectionDecodeError> {
    let n = match r.read_unsigned::<12, u16>() {
        Ok(n) => n,
        Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(source) => return Err(SectionDecodeError::Read { source }),
    };

    let mut ids = IdSet::new();
    for _entry_idx in 0..n {
        let is_group = match r.read_bit() {
            Ok(is_group) => is_group,
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(source) => return Err(SectionDecodeError::Read { source }),
        };

        let start = match r.read_unsigned::<16, u16>() {
            Ok(start) => start,
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
                return if restriction_idx > 0 {
                    Ok(None)
                } else {
                    Err(SectionDecodeError::Read { source })
                };
            }
            Err(source) => return Err(SectionDecodeError::Read { source }),
        };

        if is_group {
            let end = match r.read_unsigned::<16, u16>() {
                Ok(end) => end,
                Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return if restriction_idx > 0 {
                        Ok(None)
                    } else {
                        Err(SectionDecodeError::Read { source })
                    };
                }
                Err(source) => return Err(SectionDecodeError::Read { source }),
            };

            ids.insert_range(start, end);
        } else {
            ids.insert(start);
        }
    }

    Ok(Some(ids))
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublisherRestriction {
    pub purpose_id: u8,
    pub restriction_type: RestrictionType,
    pub restricted_vendor_ids: IdSet,
}

impl From<Range> for PublisherRestriction {
    fn from(r: Range) -> Self {
        Self {
            purpose_id: r.key,
            restriction_type: RestrictionType::from_u8(r.range_type)
                .unwrap_or(RestrictionType::Undefined),
            restricted_vendor_ids: r.ids,
        }
    }
}

#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RestrictionType {
    NotAllowed = 0,
    RequireConsent = 1,
    RequireLegitimateInterest = 2,
    Undefined = 3,
}

#[derive(Debug, Eq, PartialEq, FromBitStream)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct PublisherPurposes {
    #[gpp(fixed_bitfield(24))]
    pub consents: IdSet,
    #[gpp(fixed_bitfield(24))]
    pub legitimate_interests: IdSet,
    #[gpp(fixed_bitfield(n as usize), where(n = unsigned_var(6)))]
    pub custom_consents: IdSet,
    #[gpp(fixed_bitfield(n as usize))]
    pub custom_legitimate_interests: IdSet,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use test_case::test_case;

    #[test_case("CPX" => matches SectionDecodeError::Read { .. } ; "decode error")]
    #[test_case("" => matches SectionDecodeError::Read { .. } ; "empty string")]
    #[test_case("IFoEUQQgAIQwgIwQABAEAAAAOIAACAIAAAAQAIAgEAACEAAAAAgAQBAAAAAAAGBAAgAAAAAAAFAAECAAAgAAQARAEQAAAAAJAAIAAgAAAYQEAAAQmAgBC3ZAYzUw" => matches SectionDecodeError::UnknownSegmentVersion { .. } ; "disclosed vendors only")]
    #[test_case("ZAAgH9794ulA" => matches SectionDecodeError::UnknownSegmentVersion { .. } ; "publisher purposes only")]
    #[test_case("IFoEUQQgAIQwgIwQABAEAAAAOIAACAIAAAAQAIAgEAACEAAAAAgAQBAAAAAAAGBAAgAAAAAAAFAAECAAAgAAQARAEQAAAAAJAAIAAgAAAYQEAAAQmAgBC3ZAYzUw.ZAAgH9794ulA" => matches SectionDecodeError::UnknownSegmentVersion { .. } ; "disclosed vendors and publisher purposes")]
    #[test_case("ZAAgH9794ulA.IFoEUQQgAIQwgIwQABAEAAAAOIAACAIAAAAQAIAgEAACEAAAAAgAQBAAAAAAAGBAAgAAAAAAAFAAECAAAgAAQARAEQAAAAAJAAIAAgAAAYQEAAAQmAgBC3ZAYzUw" => matches SectionDecodeError::UnknownSegmentVersion { .. } ; "publisher purposes and disclosed vendors")]
    fn error(s: &str) -> SectionDecodeError {
        TcfEuV2::from_str(s).unwrap_err()
    }

    #[test]
    fn decode_eu_v2_legacy_sample() {
        let _ = TcfEuV2::from_str(
            "CQaXJQAQaXJQAAGABCENCCFsAP_gAEPgAAiQKmNR_G_fbXlj8TZ36ftkeYxf99hjrsQxBgaJk24FyJvW7JwW32EzNAzapqYKmRIAu1BBAQNlGIDURUCgKIgVqTDMaESEoTNKJ6BEgBMRA2JYCFxvmwBDWQCY5tp9dld5mB-N7dr8ydzyy4BHn3I5XsS1WBAAAAAAAAAAAAAAAQAAgAAAgAAAAAAAAAAAABAAEAAAIAAAAAACAAAAAAAAAAAAAAAAAACAAAAAQSNgfgAKgAcAB4AFwAVAAuAB-AF0ANAAfABCACKAEcAMsAc4A7gCAQEHAQgAiMBGQEaAI4ASIAn4BUACxAF6AMUAa8A6QB2wD_gIQAR6AlYBMUCZAJlATbApACkQFJgKyAV2AsIBagC4AFxALmAXRAvIC8wF9AMQAYsAyEBkYDRgGmgNTAa8A2gBtgDbgG6AN-AgmBI0BQJA5AAXABQAFQALgAcAA8ACAAF8AMgA1AB4AEwAKoAbwA_QCGAIkATQArQBgADDgGUAZYA2YB3AHfAPYA-IB9gH6AQAAikBFwEYgJEAkwBQYCoAKuAXMAvQBigDaAG4AOIAe0BDoCRAE0gJ2AUOAo8BSIC2AFwALkAXYAu8BhoDJAGTgMuAZmAzmBq4GsgNvAbmFABgCKAXQBI0IAQAA2ACQAjgBKQCdgGiAP6AmUBNgCkAFiALcAX-AwIBtQDhAwAIBNgDahAAMAEgCbAG1CgAQCbAG1DAAQCbAG1DoIQAC4AKAAqABwAEEALgAvgBkAGoAPAAmABTACqAFwAMQAbwA_QCGAIgATQAowBWgDAAGGAMoAaIA2QB3wD2APiAfYB-wEUARiAjoCTAFBgKiAq4BYgC5gF5AMUAbQA3ABxAD2gH2AQ6Ai8BIgCaQE7AKHAUeAqwBYoC2AFugLgAXJAuwC7QF3gMNAY9AyMDJAGTgMqgZYBlwDMwGcwNXA1gBt4D-wI7DwAwAPwBFAERAIyAugCRo4AiACQAKAAfAByAEcAJSATsAzIB_QE2ALEAWyAtwBf4DaoG5gboA4QhAeAAWABQAFwANQAqgBcADEAG8APwAwIB3AHeARQAlIBQYCogKuAXMAxQBtAEOgJpAVYAsUBaIC4AFyALsAZGAycBnID-yIAIAjICYiAAkAB4A5ACOAGZATYAsQBngDagG6EoEQACwAKAAcAB4AEwAKoAXAAxQCGAIkAUYArQBgADKAGiANkAd8A_AD9AIsARgAjoBJQCgwFRAVcAuYBeQDaAG4AOIAe0A-wCHQEXgJEATSAnYBQ4CkwFNAKsAWKAtgBcAC5IF2AXaAw2BkYGSAMngZYBlwDOYGsAayA28B_YEdioAMABQCZQF0FAB4AJAAZABQAC2AOQAfYBBwCOAEpAQgAmwBUgC3AGeQNzA3QtALABqAMAAdwBegD7AKHAU0AqwBcAC7AGZgAAA.f_wAAAAAAAAA",
        )
        .unwrap();
    }

    // Production TC strings: publisher restrictions over thousands of vendors
    // with disclosed vendors, and two-, three- and one-segment strings.
    const PRODUCTION: [&str; 4] = [
        "CQkTQMAQkTQMAB7F7BENCsFsAP_gAAAgAAAAMetR_G__bXlr-bb36btkeYxf9_hr7sQxBgbIkm4FzLvW7JwG32EbJAyatiIKmRIAu3DBIQNlHBDURUCgKIAVrzDMaE2U4TtKJ6BkiFMZYytQCEhvm4tjeQCY4ur_9kd0mR-t6dr82dzy26hnn3a9fuS1UJCdIYesDfv8ZBOS-9IE9-x8v4v4_MbpEm0eSVn9tEtp4jc6Yvv6dBmxt-Tyff6Pn_f7lfW7X__e_n3zv8oXn7r76-__f3-7v__2bf-___7___7Z__u_4MYQPwAagA4ACGAMAAZYAzQB3AEcAL0AZ8A-wCD4EeAR6AlUBMQCbQFDwKaApsBVgC4AF2AMzgaKBowDUwG6AOWAdsA8cCAgEFAIegRpAj0BIgCUYErQJkgTNAmxBNwE3QJzATuAngBRkCjgFJAKXAVSArABXMCwoFiQLVgWtAtzBbsFvALugXsAv8BgKDDAMMgYggxeDGAAoSEFABQAFQALgAcAA8ACAAEgAL4AZABqADwAIYATAAqgBvAD8AISAQwBEgCOAE0AK0AYAAwwBlgDZAHOAO4Ae0A-wD9AIAARSAi4CMQEaARwAkQBJoCfgKDAVABVwC5gF6AMUAaIA2gBuADiAHtAQ7Aj0CRQE0gJ2AUOAo8BSICmwFsALgAXIAuwBd4C8wGGwMjAyQBk4DLgGZgM5AZ9A1cDWQGxgNoAbeA3MBuoDkwHLgPHgfGB8gD_gICAQTAgwBCGCFoIXwQ9BD8CJgEfQJFQSYBJkCWYEtwJfATAAmWBM4CaoE2AJuATmAnSBO4CeEFBwUIAoWBRUCkoFLgKZAU8gp-CoAFRgKnAVdArYBW8CvgFhQLHAWVAtNBawFrQLcgXFAvUBfcC_YF_wMDgYKAxEBimDFYMWAYzAx6OhLAALgAoACoAHAAQAAkgBcAF8AMgA1AB4AEwAKYAVQAugBiADeAH6AQwBEgCOAE0AKMAVoAwABhgDRAGyAOcAdwA9oB9gH7ARQBGICOAJEASaAn4CgwFRAVcAsQBc4C8gL0AYoA2gBuADiAHmAPaAfYBCACHQETgIvgR6BIoCZAE0gJ2AUPAo8CkAFJgKbAVYAsUBbAC3QFwALkgXYBdoC7wF5gL6AYaAx6BkYGSAMnAZVAywDLgGZgM5AZ8A00BqsDVwNYAbQA28BuoDiwHJgOXAeOA-MB8wD6wH3AP7Af8BAECAgEGAIWgQ9AiYBHYCPoEhAJFASZAlXBLMEtAJdAS-AmABMsCZwE1QJsATcAnMBOmCdoJ3ATwAnmBQYChAFCwKJAUVApKBS4CngFPwKjAVOAq6BWwCt4FgwLHgWTAsrBawFrQLcgW7AuKBcsC9QF9wMDgYKAwkBhiDDYMOAYiAxfBjIGMwMekIHoACwAKAAuABqAFUAMQAbwA_ADAAHOAO4AigBHACRAEpAKDAVEBVwC5gGKANoAh0BE4CPQE0gKTAU2AqwBYoC0QFwALkAXYAyMBk4DOQGqgPHAfGA_sCAgEGAIWgQ9AkIBIoCXQEzgJsATmAncBPACeYFBgKKgUlApcBT8CwQFrQLcgYvJQWQAFgAUAA4ACQAHgAQwAmABVADFAIYAiQBHACjAFaAMAAbIA_ACOQFRAVcAuYBigDiAIQAQ6Ai-BHoEigKPAUnApoCmwFigLYAXIAuwBecDIwMkAZOAywBnIDPgGsANvAfGBAECAgEDwIMAQhAh6BH0CRQElQJVgStAl0BL4CZwE1QJsATcAnNBO0E7gJ4ATzAoqBSUClwFPAKjAVOArYBW-CwQLBgWLAseBZUCz0FrAWtAtyBcgC5YF6gL7gYKAwkBhgDDYGIgMXgYzAx6Ug9gALgAoACoAHAAQQAyADQAHgAQwAmABVADEAH6AQwBEgCOAFGAK0AYAA0QBsgDnAHfAPsA_QCLAEYgI4AkQBQYCogKuAXMAvIBigDaAG4AOIAe0A-wCHQETgIvgR6BIoCaQE7AKHAUgApOBTQFNgKsAWKAtgBcAC5IF2AXaAvMBfQDDYGRgZIAyeBlgGXAM5gawBrIDZQG3gN1AcmA8UB44D4wHzAP7Af8BAQCCYEGAIQgQtAhmBDkCHYETAI7AR9AkVBJgEmQJVgSzAl0BL4CYAEywJnATVAmwBOaCdoJ3ATwAnmBQsCioFJQKXAU8Ap-BUYCpwFbAK3gWCAsKBYsCx4FkwLKgWegtYC1oFuQLigXIAvUBgcDBUGGwYcAxFBisGLAMZgY9.IMetR_G__bXlv-bb36btkeYxf9_hr7sQxBgbIsm4FzLvW7JwH32EbNEzatiYKmRIAu3TBIQNtHJjURUChKIgVrzDsaE2U4TtKJ-BkiHMZY2tQCFxvm4tjeQCZ4ur_90d9mR-t7dr-2dzy27hnv3a9fuS1UJidKYetHfv8ZBOT-_IU9_x-_4v4_MbpEm8eS1v_tWtt43c64vv_dpuxt-Tyff7fv__73_e7X__e__33_-qX3_r7____________f__________9____4AA",
        "CQa0zsAQni5QAAHABBENCnFsAP_gAAAAAAiQMrtR_G__bXlr-bb36btkeYxf9_hr7sQxBgbIkm4FzLvW7JwG32EbJAyatiIKmRIAu3TBIQNlHJDURUCgKIgVrzDMaE2U4TtKJ6BkiFMZY2tQCFhvm4tjeQCZ4ur_9kd0mR-t7dr-2dzy26hnv3a9fuS1UJSdIYetDfv-ZhOS-9IE9-x8v4v4_MbpEm8eSVn9tGtp4jc6Yvv6dBmxt-Tyff6Pn_f71fe7X__e_n3zv8oXn7r76-__f3-7___-b_-___7___7Z__u__7_v-DJ0CkAHAAzQDPgHSASqA0YBx4DnwHbAPtAfsBAYCCIEFAI0gR6AkQBJICSgEowJhgT-goICgoFHwKpgVgArIBW0CvgFhALVgW8AuABdoC7wF7AMQAYwAxoBkQDJwAxKADAAEGVykAGAAIMrjoAMAAQZXIQAYAAgyuEgAwABBlctABgACDK4.IMrtR_G__bXlv-bb36btkeYxf9_hr7sQxBgbIsm4FzLvW7JwG32EbJEyatiIKmRIAu3TBIQNtHJjURUChKIgVrzDMaE2U4TtKJ-BkiHMZY2tQCFhvm4tjeQCZ4ur_9kd0mR-t7dr-2dzy27hnv3a9fuS1UJydKYetHfv-ZhOS-_IU9_x-_4v4_MbpEm8eSVv9tWtt43c64vv6dJuxt-Tyff6f__f73fe7X__e__33_-qX3_r76-___3______f_________7d________-AA.f_wAAAAAAAAA",
        "CQnzyTgQnzyTgAfNzBESCoFsAP_gAEPgAAigLTtR_G_fbWlj-TL3abskeYxf99hr5sQxBgLIgk4BzDrW5JwG12ESJEyShiAKmRIAqnRBIQFtGAjURUABIIAVJSDsYESUgRNIJuBAgFMRQwNQCFhvmYthGQCRwkp3cwZgmRsM6Vru2NxAw5gjPUS1IqQlUJgdCYMoCQmsZBKS87IU9-x-v4vw9MboEm8eSVn9tStp4xcIABAAJAAgAAAgBAAABAAABICAAAAAAAAAAgAAAAAAAAAIK0gAmGhUQQlgQCBAICEECABQVhABQIAgAACAggIATBgQ5AwAVWESAEACAAAIAQAAggABAAAJAAhEAEABAIAQIAAoAAQAAAAIAGBAABABQgAQAAgOgYpAAQCBQAJEYQBggQgAIBAC2FAAQBAgLACkAKAAQIgYCAAAAAAoAAAA8LAQkkBKhIIAsILoAEAAAACIESBBIQYAAAAABAAgAAAgBAAABAAAAAAAAAAAAAAAAgAA.ILTtR_G_fbWlj-TL3abskeYxf99hr5sQxBgLIgk4BzDrW5JwG12ESJEyShiAKmRIAqnRBIQFtGAjURUABIIAVJSDsYESUgRNIJuBAgFMRQwNQCFhvmYthGQCRwkp3cwZgmRsM6Vru2NxAw5gjPUS1IqQlUJgdCYMoCQmsZBKS87IU9-x-v4vw9MboEm8eSVn9tStp4xcIABAAJAAgAAAgBAAABAAABICAAAAAAAAAAgAAAAAAAAAIA",
        "CQf9KVgQf9KVgAfPxBJACTFgAP_AAEPAAAigLzNR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHIjURUChKIgVrzDsaE2UoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ4vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1UJidKYetHfv8ZBKT-_IU9_x-_4v4_MbpEm-eS1v_tWtt43d64vP_dpuxt-Tyff7____73_e7X__c__33_-_Xf_7_____________f_BeQAEw0KiCMsiBAIFAwggQAKCsIAKBAEAACQNEBACYMCHIGAC6wmQAgBQADBACAAEGAAIAABIAEIgAgAIBACBAIFAAGABAEBAAwMAAYALEQCAAEB0DFMCCAQLABIjKoNMCUABIICWyoQSAYEFcIQizwCCBETBQAAAgAFAAAAPBYCEkgJWJBAFxBNAAAQAABRAiQIpCzAEFQZotBWBJwGRpgGD5gmSU6DIAmCEjIMiE34TDxTFEKCHKDYpZgDp4gAA",
    ];

    fn assert_decode_core_agrees(s: &str) {
        match (TcfEuV2::from_str(s), TcfEuV2::decode_core(s)) {
            (Ok(full), Ok(core)) => assert_eq!(full.core, core, "{s}"),
            (Err(_), Err(_)) => {}
            (full, core) => panic!(
                "from_str ok={} but decode_core ok={} for {s}",
                full.is_ok(),
                core.is_ok()
            ),
        }
    }

    #[test]
    fn decode_core_agrees_with_from_str() {
        for s in PRODUCTION {
            assert_decode_core_agrees(s);
            for end in 0..s.len() {
                assert_decode_core_agrees(&s[..end]);
            }
            for i in 0..s.len() {
                let mut mutated = s.to_string();
                mutated.replace_range(i..=i, ["A", "_", ".", "!"][i % 4]);
                assert_decode_core_agrees(&mutated);
            }
            let segments: Vec<&str> = s.split('.').collect();
            assert_decode_core_agrees(&format!("{s}.{}", segments.last().unwrap()));
            assert_decode_core_agrees(&format!("{s}."));
            assert_decode_core_agrees(
                &segments.iter().rev().copied().collect::<Vec<_>>().join("."),
            );
        }
    }
}
