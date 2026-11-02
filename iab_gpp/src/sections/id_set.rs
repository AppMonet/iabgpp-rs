use std::fmt;
use std::slice;

/// A sorted set of `u16` ids backed by a dense `Vec`.
///
/// GPP sections decode id collections (vendor consents, purpose consents,
/// bitfields, ranges) in ascending order, so inserts are almost always an
/// amortized O(1) push instead of a BTree node allocation and walk, and
/// lookups are binary searches over a contiguous, cache-friendly buffer.
/// Large vendor bitfields (thousands of set bits per consent string) make
/// this the hot path of consent-string decoding.
///
/// The API mirrors the `BTreeSet<u16>` subset this crate and its consumers
/// use: iteration is ascending and yields `&u16`, `Debug` renders as a set,
/// and the optional serde representation is the same sequence-of-ids wire
/// format.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct IdSet {
    /// Sorted ascending, no duplicates.
    ids: Vec<u16>,
}

impl IdSet {
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }

    /// Adds an id, returning whether it was newly inserted.
    pub fn insert(&mut self, id: u16) -> bool {
        match self.ids.last() {
            // Ascending insert (the decoding common case): plain push.
            None => {
                self.ids.push(id);
                true
            }
            Some(&last) if id > last => {
                self.ids.push(id);
                true
            }
            Some(&last) if id == last => false,
            _ => match self.ids.binary_search(&id) {
                Ok(_) => false,
                Err(pos) => {
                    self.ids.insert(pos, id);
                    true
                }
            },
        }
    }

    /// Adds every id in `start..=end`. A range past the current maximum, the
    /// decoding common case, is one reserve and a run of pushes.
    pub fn insert_range(&mut self, start: u16, end: u16) {
        if start > end {
            return;
        }
        let above = match self.ids.last() {
            Some(&last) if start <= last => {
                // The ids already held inside the overlap become the full
                // span; a span that is already complete costs two searches.
                let overlap_end = end.min(last);
                let lo = self.ids.partition_point(|&id| id < start);
                let hi = self.ids.partition_point(|&id| id <= overlap_end);
                if hi - lo != usize::from(overlap_end - start) + 1 {
                    self.ids.splice(lo..hi, start..=overlap_end);
                }
                match last.checked_add(1) {
                    Some(next) if next <= end => next,
                    _ => return,
                }
            }
            _ => start,
        };
        self.ids.extend(above..=end);
    }

    pub fn contains(&self, id: &u16) -> bool {
        self.ids.binary_search(id).is_ok()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Iterates ids in ascending order.
    pub fn iter(&self) -> slice::Iter<'_, u16> {
        self.ids.iter()
    }

    pub fn first(&self) -> Option<&u16> {
        self.ids.first()
    }

    pub fn last(&self) -> Option<&u16> {
        self.ids.last()
    }
}

impl fmt::Debug for IdSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.ids.iter()).finish()
    }
}

impl FromIterator<u16> for IdSet {
    fn from_iter<I: IntoIterator<Item = u16>>(iter: I) -> Self {
        let mut ids: Vec<u16> = iter.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }
}

impl<const N: usize> From<[u16; N]> for IdSet {
    fn from(values: [u16; N]) -> Self {
        values.into_iter().collect()
    }
}

impl Extend<u16> for IdSet {
    fn extend<I: IntoIterator<Item = u16>>(&mut self, iter: I) {
        for id in iter {
            self.insert(id);
        }
    }
}

impl<'a> IntoIterator for &'a IdSet {
    type Item = &'a u16;
    type IntoIter = slice::Iter<'a, u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.ids.iter()
    }
}

impl IntoIterator for IdSet {
    type Item = u16;
    type IntoIter = std::vec::IntoIter<u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.ids.into_iter()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for IdSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.ids.iter())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IdSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ids = Vec::<u16>::deserialize(deserializer)?;
        Ok(ids.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::IdSet;

    #[test]
    fn insert_range_matches_inserting_each_id() {
        let ranges = [
            (5, 9),
            (1, 3),
            (4, 6),
            (8, 12),
            (12, 12),
            (20, 15),
            (0, 0),
            (65530, 65535),
        ];
        let mut by_range = IdSet::new();
        let mut by_id = IdSet::new();
        for (start, end) in ranges {
            by_range.insert_range(start, end);
            for id in start..=end {
                by_id.insert(id);
            }
            assert_eq!(by_range, by_id, "after {start}..={end}");
        }
    }

    #[test]
    fn insert_ascending_and_lookup() {
        let mut set = IdSet::new();
        assert!(set.insert(1));
        assert!(set.insert(3));
        assert!(set.insert(800));
        assert!(!set.insert(3));
        assert_eq!(set.len(), 3);
        assert!(set.contains(&1));
        assert!(set.contains(&800));
        assert!(!set.contains(&2));
    }

    #[test]
    fn insert_out_of_order_keeps_sorted_dedup() {
        let mut set = IdSet::new();
        for id in [5u16, 2, 9, 2, 7, 5] {
            set.insert(id);
        }
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![2, 5, 7, 9]);
    }

    #[test]
    fn from_iterator_sorts_and_dedups() {
        let set: IdSet = [9u16, 1, 9, 4].into_iter().collect();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 4, 9]);
        assert_eq!(set, IdSet::from([1, 4, 9]));
    }

    #[test]
    fn debug_renders_as_set() {
        let set = IdSet::from([1, 3]);
        assert_eq!(format!("{set:?}"), "{1, 3}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_matches_btreeset_wire_format() {
        let set = IdSet::from([1, 3, 5]);
        let json = serde_json::to_string(&set).expect("serialize");
        assert_eq!(json, "[1,3,5]");
        let back: IdSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, set);
    }
}
