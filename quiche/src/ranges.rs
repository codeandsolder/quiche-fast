// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::iter::FromIterator;
use std::ops::Range;

use std::collections::BTreeMap;
use std::collections::Bound;

use either::Either;
use smallvec::SmallVec;

const MAX_INLINE_CAPACITY: usize = 4;
const MIN_TO_INLINE: usize = 2;

/// A sorted collection of non overlapping [`u64`] ranges
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub enum RangeSet {
    Inline(InlineRangeSet),
    BTree(BTreeRangeSet),
}

/// A [`RangeSet`] variant backed by a [`SmallVec`] that is capable of storing
/// [`MAX_INLINE_CAPACITY`] of ranges without allocation
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub struct InlineRangeSet {
    inner: SmallVec<[(u64, u64); MAX_INLINE_CAPACITY]>,
    capacity: usize,
}

/// A [`RangeSet`] variant backed by a [`BTreeMap`] that is capable of storing
/// an arbitrary number of ranges
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub struct BTreeRangeSet {
    inner: BTreeMap<u64, u64>,
    capacity: usize,
}

impl RangeSet {
    /// Create a new [`RangeSet`].
    ///
    /// When the number of disjoint ranges exceeds `capacity`, the
    /// lowest-valued range is discarded. Zero capacity retains no ranges.
    pub fn new(capacity: usize) -> Self {
        Self::Inline(InlineRangeSet {
            inner: SmallVec::new(),
            capacity,
        })
    }

    /// The number of nonoverlapping ranges stored in this [`RangeSet`].
    pub fn len(&self) -> usize {
        match self {
            RangeSet::Inline(set) => set.inner.len(),
            RangeSet::BTree(set) => set.inner.len(),
        }
    }

    /// Returns true if the collection contains the given value.
    pub fn contains(&self, item: u64) -> bool {
        match self {
            RangeSet::Inline(set) => set
                .inner
                .iter()
                .any(|&(start, end)| start <= item && item < end),

            RangeSet::BTree(set) =>
                set.prev_to(item).is_some_and(|range| item < range.end),
        }
    }

    /// Converts the inner representation from a BTree to Inline and vice versa
    /// when the proper conditions are met. Keeps the stored data intact.
    #[inline]
    fn fixup(&mut self) {
        match self {
            RangeSet::Inline(set) if set.inner.len() == MAX_INLINE_CAPACITY => {
                let old_inner = std::mem::take(&mut set.inner);
                *self = RangeSet::BTree(BTreeRangeSet {
                    inner: old_inner.into_iter().collect(),
                    capacity: set.capacity,
                });
            },

            RangeSet::BTree(set) if set.inner.len() <= MIN_TO_INLINE => {
                let old_inner = std::mem::take(&mut set.inner);
                *self = RangeSet::Inline(InlineRangeSet {
                    inner: SmallVec::from_iter(old_inner),
                    capacity: set.capacity,
                })
            },

            _ => {},
        }
    }

    /// Insert a new [`Range`] into the collection.
    ///
    /// If the [`Range`] overlaps with any existing range, it may be merged with
    /// one or more other [`Range`]s. If following the insertion the number of
    /// stored ranges exceeds capacity, the lowest-valued range is discarded.
    /// Empty or reversed ranges do not change the set.
    #[inline]
    pub fn insert(&mut self, item: Range<u64>) {
        if item.is_empty() {
            return;
        }
        match self {
            RangeSet::Inline(set) => set.insert(item),
            RangeSet::BTree(set) => set.insert(item),
        }

        self.fixup();
    }

    /// Iterate over the stored ranges in incremental order.
    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = Range<u64>> + ExactSizeIterator + '_
    {
        match self {
            RangeSet::BTree(set) =>
                Either::Left(set.inner.iter().map(|(k, v)| *k..*v)),

            RangeSet::Inline(set) =>
                Either::Right(set.inner.iter().map(|(s, e)| *s..*e)),
        }
    }

    /// Iterate over every single [`u64`] value covered by the ranges in this
    /// [`RangeSet`] in incremental order.
    #[cfg(test)]
    pub fn flatten(&self) -> impl DoubleEndedIterator<Item = u64> + '_ {
        match self {
            RangeSet::BTree(set) =>
                Either::Left(set.inner.iter().flat_map(|(k, v)| *k..*v)),

            RangeSet::Inline(set) =>
                Either::Right(set.inner.iter().flat_map(|(s, e)| *s..*e)),
        }
    }

    /// The smallest value covered by ranges in this collection.
    #[cfg(test)]
    pub fn first(&self) -> Option<u64> {
        match self {
            RangeSet::Inline(set) => set.inner.first().map(|(s, _)| *s),

            RangeSet::BTree(set) => set.inner.first_key_value().map(|(k, _)| *k),
        }
    }

    /// The largest value covered by ranges in this collection.
    pub fn last(&self) -> Option<u64> {
        match self {
            RangeSet::Inline(set) => set.inner.last().map(|(_, e)| *e - 1),

            RangeSet::BTree(set) =>
                set.inner.last_key_value().map(|(_, v)| *v - 1),
        }
    }

    #[inline]
    pub fn remove_until(&mut self, largest: u64) {
        match self {
            RangeSet::Inline(set) => set.remove_until(largest),
            RangeSet::BTree(set) => set.remove_until(largest),
        }

        self.fixup();
    }

    pub fn push_item(&mut self, item: u64) {
        self.insert(item..item + 1)
    }
}

impl InlineRangeSet {
    fn insert(&mut self, item: Range<u64>) {
        if self.capacity == 0 {
            return;
        }

        let start = item.start;
        let mut end = item.end;
        let mut pos = 0;

        loop {
            match self.inner.get_mut(pos) {
                Some((s, e)) => {
                    if start > *e {
                        // Skip while start is greater than end
                        pos += 1;
                        continue;
                    }

                    if end < *s {
                        // Inserted range is entirely before this range. Insert
                        // and return.
                        if self.inner.len() == self.capacity {
                            // The incoming range itself is lowest, so it is
                            // the range that must be discarded.
                            if pos == 0 {
                                return;
                            }
                            self.inner.remove(0);
                            pos -= 1;
                        }

                        self.inner.insert(pos, (start, end));
                        return;
                    }

                    // At this point, `start <= *e`.
                    if start < *s {
                        // We know we are completely past the previous range, so
                        // we can simply adjust the lower bound.
                        *s = start;
                    }

                    if end > *e {
                        // Check for overlap between the expanded range and the
                        // next range.
                        *e = end;
                        break;
                    } else {
                        return;
                    }
                },

                None => {
                    if self.inner.len() == self.capacity {
                        self.inner.remove(0);
                    }

                    self.inner.push((start, end));
                    return;
                },
            }
        }

        // Merge any newly overlapping ranges
        while let Some((s, e)) = self.inner.get(pos + 1).copied() {
            if end < s {
                // We are done, since the next range is completely disjoint
                break;
            }

            let new_e = e.max(end);
            self.inner[pos].1 = new_e;
            end = new_e;
            self.inner.remove(pos + 1);
        }
    }

    fn remove_until(&mut self, largest: u64) {
        while let Some((s, e)) = self.inner.first_mut() {
            if largest >= *e {
                self.inner.remove(0);
                continue;
            }

            *s = (largest + 1).max(*s);
            if *s == *e {
                self.inner.remove(0);
            }

            break;
        }
    }
}

impl BTreeRangeSet {
    fn insert(&mut self, item: Range<u64>) {
        if self.capacity == 0 || item.is_empty() {
            return;
        }

        let mut start = item.start;
        let mut end = item.end;

        // Merge the predecessor if it overlaps or touches the new range.
        if let Some(r) = self.prev_to(start).filter(|r| r.end >= start) {
            self.inner.remove(&r.start);
            start = r.start;
            end = end.max(r.end);
        }

        // Because ranges are sorted and disjoint, the next range can be
        // merged precisely when its start is no greater than the current end.
        while let Some(r) = self.next_to(start).filter(|r| r.start <= end) {
            self.inner.remove(&r.start);
            end = end.max(r.end);
        }

        if self.inner.len() >= self.capacity {
            if self
                .inner
                .first_key_value()
                .is_some_and(|(&first, _)| start < first)
            {
                return;
            }
            self.inner.pop_first();
        }
        self.inner.insert(start, end);
    }

    fn remove_until(&mut self, largest: u64) {
        // Every representable half-open range excludes u64::MAX.
        let Some(first_remaining) = largest.checked_add(1) else {
            self.inner.clear();
            return;
        };

        while let Some((&start, &end)) = self.inner.first_key_value() {
            if start >= first_remaining {
                break;
            }
            self.inner.pop_first();
            if end > first_remaining {
                self.inner.insert(first_remaining, end);
                break;
            }
        }
    }

    fn prev_to(&self, item: u64) -> Option<Range<u64>> {
        self.inner
            .range((Bound::Unbounded, Bound::Included(item)))
            .map(|(&s, &e)| s..e)
            .next_back()
    }

    fn next_to(&self, item: u64) -> Option<Range<u64>> {
        self.inner
            .range((Bound::Included(item), Bound::Unbounded))
            .map(|(&s, &e)| s..e)
            .next()
    }
}

impl Default for RangeSet {
    fn default() -> Self {
        Self::new(usize::MAX)
    }
}

// This implements comparison between `BTreeRangeSet` and standard `Range`. The
// idea is that a `RangeSet` with no gaps (i.e. that only contains a single
// range) is basically equvalent to a normal `Range` so they should be
// comparable.
impl PartialEq<Range<u64>> for RangeSet {
    fn eq(&self, other: &Range<u64>) -> bool {
        // If there is more than one range it means that the range set is not
        // contiguous, so can't be equal to a single range.
        if self.len() != 1 {
            return false;
        }

        self.iter().next().is_some_and(|range| range == *other)
    }
}

impl std::fmt::Debug for RangeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ranges: Vec<Range<u64>> = self
            .iter()
            .map(|mut r| {
                r.end -= 1;
                r
            })
            .collect();

        write!(f, "{ranges:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_inline() {
        let mut r = RangeSet::default();
        assert!(!r.contains(0));
        assert!(!r.contains(u64::MAX));

        r.insert(4..7);
        r.insert(9..12);
        r.insert(u64::MAX - 2..u64::MAX);
        assert!(matches!(r, RangeSet::Inline(_)));

        for item in 0..15 {
            assert_eq!(
                r.contains(item),
                (4..7).contains(&item) || (9..12).contains(&item)
            );
        }

        assert!(!r.contains(u64::MAX - 3));
        assert!(r.contains(u64::MAX - 2));
        assert!(r.contains(u64::MAX - 1));
        assert!(!r.contains(u64::MAX));
    }

    #[test]
    fn contains_btree() {
        let mut r = RangeSet::default();

        for start in [4, 9, 14, u64::MAX - 3] {
            r.insert(start..start + 3);
        }

        assert!(matches!(r, RangeSet::BTree(_)));

        for item in 0..20 {
            assert_eq!(
                r.contains(item),
                (4..7).contains(&item) ||
                    (9..12).contains(&item) ||
                    (14..17).contains(&item)
            );
        }

        assert!(!r.contains(u64::MAX - 4));
        assert!(r.contains(u64::MAX - 3));
        assert!(r.contains(u64::MAX - 1));
        assert!(!r.contains(u64::MAX));

        r.remove_until(13);
        assert!(matches!(r, RangeSet::Inline(_)));
        assert!(!r.contains(12));
        assert!(r.contains(14));
        assert!(r.contains(16));
        assert!(!r.contains(17));
    }

    #[test]
    fn adjacent_singletons_merge() {
        let mut r = RangeSet::default();

        for item in [0, 2, 4, 6] {
            r.push_item(item);
        }

        assert!(matches!(r, RangeSet::BTree(_)));

        for item in [5, 1, 3] {
            assert!(!r.contains(item));
            r.push_item(item);
            assert!(r.contains(item));
        }

        assert_eq!(r, 0..7);
        assert!(matches!(r, RangeSet::Inline(_)));

        for item in 0..7 {
            assert!(r.contains(item));
        }

        assert!(!r.contains(7));
    }

    #[test]
    fn insert_non_overlapping() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        r.insert(4..7);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6]);

        r.insert(9..12);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
    }

    #[test]
    fn insert_contained() {
        let mut r = RangeSet::default();

        r.insert(4..7);
        r.insert(9..12);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(4..7);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(4..6);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(5..6);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(10..11);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(9..11);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
    }

    #[test]
    fn insert_overlapping() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(9..12);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[3, 4, 5, 9, 10, 11]);

        r.insert(5..7);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[3, 4, 5, 6, 9, 10, 11]);

        r.insert(10..15);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 6, 9, 10, 11, 12, 13, 14
        ]);

        r.insert(2..5);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14
        ]);

        r.insert(8..10);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14
        ]);

        r.insert(6..10);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
        ]);
    }

    #[test]
    fn insert_overlapping_multi() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(16..20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 16, 17, 18, 19
        ]);

        r.insert(10..11);
        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 10, 16, 17, 18, 19
        ]);

        assert!(matches!(r, RangeSet::Inline(_)));

        r.insert(13..14);
        assert_eq!(r.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 10, 13, 16, 17, 18, 19
        ]);

        // Make sure it converted to a btree at capacity
        assert!(matches!(r, RangeSet::BTree(_)));

        r.insert(4..17);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19
        ]);

        // Make sure it converted back to inline
        assert!(matches!(r, RangeSet::Inline(_)));
    }

    #[test]
    fn prev_to() {
        let mut r = BTreeRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        };

        r.insert(4..7);
        r.insert(9..12);

        assert_eq!(r.prev_to(2), None);
        assert_eq!(r.prev_to(4), Some(4..7));
        assert_eq!(r.prev_to(15), Some(9..12));
        assert_eq!(r.prev_to(5), Some(4..7));
        assert_eq!(r.prev_to(8), Some(4..7));
    }

    #[test]
    fn next_to() {
        let mut r = BTreeRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        };

        r.insert(4..7);
        r.insert(9..12);

        assert_eq!(r.next_to(2), Some(4..7));
        assert_eq!(r.next_to(12), None);
        assert_eq!(r.next_to(15), None);
        assert_eq!(r.next_to(5), Some(9..12));
        assert_eq!(r.next_to(8), Some(9..12));
    }

    #[test]
    fn push_item() {
        let mut r = RangeSet::default();

        r.insert(4..7);
        r.insert(9..12);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.push_item(15);
        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            4, 5, 6, 9, 10, 11, 15
        ]);

        r.push_item(15);
        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            4, 5, 6, 9, 10, 11, 15
        ]);

        r.push_item(1);
        assert_eq!(r.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 4, 5, 6, 9, 10, 11, 15
        ]);

        r.push_item(12);
        r.push_item(13);
        r.push_item(14);

        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
        ]);

        r.push_item(2);
        r.push_item(3);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
        ]);

        r.push_item(8);
        r.push_item(7);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
        ]);
    }

    #[test]
    fn flatten_rev() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        r.insert(4..7);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[6, 5, 4]);

        r.insert(9..12);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[
            11, 10, 9, 6, 5, 4
        ]);
    }

    #[test]
    fn flatten_one() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        r.insert(0..1);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[0]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[0]);
    }

    #[test]
    fn remove_largest() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(9..11);
        r.insert(13..14);
        r.insert(16..20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            5, 9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(6);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(10);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[13, 16, 17, 18, 19]);

        r.remove_until(17);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[18, 19]);

        r.remove_until(18);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[19]);

        r.remove_until(20);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);
    }

    #[test]
    fn eq_range() {
        let mut r = RangeSet::default();
        assert_ne!(r, 0..0);

        let expected = 3..20;

        r.insert(3..6);
        assert_ne!(r, expected);

        r.insert(16..20);
        assert_ne!(r, expected);

        r.insert(10..11);
        assert_ne!(r, expected);

        r.insert(13..14);
        assert_ne!(r, expected);

        r.insert(4..17);

        assert_eq!(r, expected);
    }

    #[test]
    fn first_last() {
        let mut r = RangeSet::default();
        assert_eq!(r.first(), None);
        assert_eq!(r.last(), None);

        r.insert(10..11);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(10));

        r.insert(13..14);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(13));

        r.insert(3..6);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(13));

        r.insert(16..20);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(19));

        r.insert(4..17);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(19));
    }

    #[test]
    fn bounded_insert_discards_lowest_in_both_representations() {
        for capacity in [0, 1, 3, 4, 8] {
            let mut ranges = RangeSet::new(capacity);
            for value in 1..=capacity {
                ranges.push_item(4 * value as u64);
            }
            let before: Vec<_> = ranges.iter().collect();
            ranges.insert(0..1);
            assert_eq!(ranges.iter().collect::<Vec<_>>(), before);
            ranges.insert(2..2);
            ranges.insert(6..3);
            assert_eq!(ranges.iter().collect::<Vec<_>>(), before);
            assert_eq!(ranges.len(), capacity);
        }
    }

    #[test]
    fn remove_through_maximum_clears_both_representations() {
        for count in [2, 6] {
            let mut ranges = RangeSet::default();
            for value in 0..count {
                ranges.insert(2 * value..2 * value + 1);
            }
            ranges.insert(u64::MAX - 1..u64::MAX);
            ranges.remove_until(u64::MAX);
            assert_eq!(ranges.len(), 0);
            assert_eq!(ranges.last(), None);
        }
    }

    #[test]
    fn mixed_operations_match_dense_reference() {
        const WIDTH: u64 = 32;
        for capacity in 0..=8 {
            let mut actual = RangeSet::new(capacity);
            let mut reference = [false; WIDTH as usize];
            let mut state = 42_u64;
            for _ in 0..4000 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let start = ((state >> 32) % WIDTH) as usize;
                let size = ((state >> 40) % 7) as usize;
                if state & 7 == 0 {
                    actual.remove_until(start as u64);
                    reference[..=start].fill(false);
                } else {
                    let end = (start + size).min(reference.len());
                    actual.insert(start as u64..end as u64);
                    reference[start..end].fill(true);

                    let mut runs = 0;
                    let mut prev = false;
                    for &present in &reference {
                        if present && !prev {
                            runs += 1;
                        }
                        prev = present;
                    }
                    if runs > capacity {
                        let mut removed = 0;
                        for index in 0..reference.len() {
                            if reference[index] {
                                reference[index] = false;
                                if index + 1 == reference.len() ||
                                    !reference[index + 1]
                                {
                                    removed += 1;
                                    if removed == runs - capacity {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                assert_eq!(
                    actual.flatten().collect::<Vec<_>>(),
                    reference
                        .iter()
                        .enumerate()
                        .filter_map(|(i, &present)| present.then_some(i as u64))
                        .collect::<Vec<_>>()
                );
                assert!(actual.len() <= capacity);
            }
        }
    }

    #[test]
    fn capacity() {
        let mut r = RangeSet::new(3);
        assert_eq!(r.first(), None);
        assert_eq!(r.last(), None);

        r.insert(10..11);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(10));

        r.insert(13..14);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(13));

        r.insert(3..6);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(13));

        r.insert(16..20);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(19));

        r.insert(4..17);
        assert_eq!(r.first(), Some(4));
        assert_eq!(r.last(), Some(19));
    }
}
