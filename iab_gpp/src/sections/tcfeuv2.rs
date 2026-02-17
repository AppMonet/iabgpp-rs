use crate::core::{DataRead, Range};
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

            for id in start..=end {
                ids.insert(id);
            }
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

}
