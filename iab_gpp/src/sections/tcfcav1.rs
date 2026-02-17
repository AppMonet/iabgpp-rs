use crate::core::{DataRead, GenericRange};
use crate::sections::{IdSet, SectionDecodeError};
use bitstream_io::{BitRead, FromBitStream};
use iab_gpp_derive::{FromBitStream, GPPSection};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, GPPSection)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
#[gpp(with_optional_segments)]
pub struct TcfCaV1 {
    pub core: Core,
    #[gpp(optional_segment_type = 1, optimized_range)]
    pub disclosed_vendors: Option<IdSet>,
    #[gpp(optional_segment_type = 3)]
    pub publisher_purposes: Option<PublisherPurposes>,
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct Core {
    pub segment_version: u8,
    pub created: u64,
    pub last_updated: u64,
    pub cmp_id: u16,
    pub cmp_version: u16,
    pub consent_screen: u8,
    pub consent_language: String,
    pub vendor_list_version: u16,
    pub policy_version: u8,
    pub use_non_standard_stacks: bool,
    pub special_feature_express_consents: IdSet,
    pub purpose_express_consents: IdSet,
    pub purpose_implied_consents: IdSet,
    pub vendor_express_consents: IdSet,
    pub vendor_implied_consents: IdSet,
    pub pub_restrictions: Vec<PublisherRestriction>,
}

#[derive(Debug, Eq, PartialEq, FromBitStream)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct CoreData {
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
    pub use_non_standard_stacks: bool,
    #[gpp(fixed_bitfield(12))]
    pub special_feature_express_consents: IdSet,
    #[gpp(fixed_bitfield(24))]
    pub purpose_express_consents: IdSet,
    #[gpp(fixed_bitfield(24))]
    pub purpose_implied_consents: IdSet,
    // BUG: specification says optimized_range
    #[gpp(optimized_integer_range)]
    pub vendor_express_consents: IdSet,
    // BUG: specification says optimized_range
    #[gpp(optimized_integer_range)]
    pub vendor_implied_consents: IdSet,
    /// Introduced in TCF CA v1.1
    #[gpp(parse_with = parse_publisher_restrictions)]
    pub pub_restrictions: Vec<PublisherRestriction>,
}

impl FromBitStream for Core {
    type Error = SectionDecodeError;

    fn from_reader<R: BitRead + ?Sized>(r: &mut R) -> Result<Self, Self::Error> {
        // In the wild (and in IAB's own decoder), TCF CA core appears with segment version 2.
        // The payload layout remains compatible for the fields we decode.
        let segment_version = r.read_unsigned::<6, u8>()?;
        if segment_version != 1 && segment_version != 2 {
            return Err(SectionDecodeError::UnknownSegmentVersion { segment_version });
        }

        let data: CoreData = r.parse()?;
        Ok(Self {
            segment_version,
            created: data.created,
            last_updated: data.last_updated,
            cmp_id: data.cmp_id,
            cmp_version: data.cmp_version,
            consent_screen: data.consent_screen,
            consent_language: data.consent_language,
            vendor_list_version: data.vendor_list_version,
            policy_version: data.policy_version,
            use_non_standard_stacks: data.use_non_standard_stacks,
            special_feature_express_consents: data.special_feature_express_consents,
            purpose_express_consents: data.purpose_express_consents,
            purpose_implied_consents: data.purpose_implied_consents,
            vendor_express_consents: data.vendor_express_consents,
            vendor_implied_consents: data.vendor_implied_consents,
            pub_restrictions: data.pub_restrictions,
        })
    }
}

fn parse_publisher_restrictions<R: BitRead + ?Sized>(
    mut r: &mut R,
) -> Result<Vec<PublisherRestriction>, SectionDecodeError> {
    Ok(r.read_n_array_of_ranges(6, 2)
        .unwrap_or_default()
        .into_iter()
        .map(|r| PublisherRestriction {
            purpose_id: r.key,
            restriction_type: RestrictionType::from_u8(r.range_type)
                .unwrap_or(RestrictionType::Undefined),
            restricted_vendor_ids: r.ids,
        })
        .collect())
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublisherRestriction {
    pub purpose_id: u8,
    pub restriction_type: RestrictionType,
    pub restricted_vendor_ids: IdSet,
}

impl From<GenericRange<u8, u8>> for PublisherRestriction {
    fn from(r: GenericRange<u8, u8>) -> Self {
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
    RequireExpressConsent = 1,
    RequireImpliedConsent = 2,
    Undefined = 3,
}

#[derive(Debug, Eq, PartialEq, FromBitStream)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct PublisherPurposes {
    #[gpp(fixed_bitfield(24))]
    pub purpose_express_consents: IdSet,
    #[gpp(fixed_bitfield(24))]
    pub purpose_implied_consents: IdSet,
    #[gpp(fixed_bitfield(n as usize), where(n = unsigned_var(6)))]
    pub custom_purpose_express_consents: IdSet,
    #[gpp(fixed_bitfield(n as usize))]
    pub custom_purpose_implied_consents: IdSet,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use test_case::test_case;

    #[test_case("BPX" => matches SectionDecodeError::Read { .. } ; "decode error")]
    #[test_case("" => matches SectionDecodeError::Read { .. } ; "empty string")]
    fn error(s: &str) -> SectionDecodeError {
        TcfCaV1::from_str(s).unwrap_err()
    }

    #[test]
    fn section_version_2_decodes() {
        let section = "CPuy0IAPuy0IAPoABABGCyCAAAAAAAAAAAAAAAAA.YAAAAAAAAAA";
        let decoded = TcfCaV1::from_str(section).expect("section should decode");
        assert_eq!(decoded.core.segment_version, 2);
        assert!(!decoded.core.vendor_express_consents.contains(&737));
        assert!(!decoded.core.vendor_implied_consents.contains(&737));
    }
}
