// Copyright (C) 2022, Cloudflare, Inc.
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

use crate::crypto;
use crate::Error;
use crate::Result;

use crate::frame;

use crate::packet::ConnectionId;

use std::collections::HashSet;
use std::collections::VecDeque;
use std::mem::size_of;

use smallvec::SmallVec;

/// Used to calculate the cap for the queue of retired connection IDs for which
/// a `RETIRED_CONNECTION_ID` frame have not been sent, as a multiple of
/// `active_conn_id_limit` (see RFC 9000, section 5.1.2).
const RETIRED_CONN_ID_LIMIT_MULTIPLIER: usize = 3;

#[derive(Default)]
struct BoundedConnectionIdSeqSet {
    /// The inner set.
    inner: HashSet<u64>,

    /// The maximum number of elements that the set can have.
    capacity: usize,
}

impl BoundedConnectionIdSeqSet {
    /// Creates a set bounded by `capacity`.
    fn new(capacity: usize) -> Self {
        Self {
            inner: HashSet::new(),
            capacity,
        }
    }

    fn insert(&mut self, e: u64) -> Result<bool> {
        if self.inner.contains(&e) {
            return Ok(false);
        }
        if self.inner.len() >= self.capacity {
            return Err(Error::IdLimit);
        }

        Ok(self.inner.insert(e))
    }

    fn remove(&mut self, e: u64) -> bool {
        self.inner.remove(&e)
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A structure holding a `ConnectionId` and all its related metadata.
#[derive(Debug, Default)]
pub struct ConnectionIdEntry {
    /// The Connection ID.
    pub cid: ConnectionId<'static>,

    /// Its associated sequence number.
    pub seq: u64,

    /// Its associated reset token. Initial CIDs may not have any reset token.
    pub reset_token: Option<u128>,

    /// The path identifier using this CID, if any.
    pub path_id: Option<usize>,
}

/// Bounded connection IDs in arrival order, with a structurally nonempty
/// collection. The first entry is inline, so a connection with only its
/// initial identifier does not allocate a deque.
struct BoundedNonEmptyConnectionIdVecDeque {
    oldest: ConnectionIdEntry,
    rest: VecDeque<ConnectionIdEntry>,
    capacity: usize,
}

impl BoundedNonEmptyConnectionIdVecDeque {
    fn new(capacity: usize, oldest: ConnectionIdEntry) -> Self {
        Self {
            oldest,
            rest: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Increase the capacity without discarding live entries.
    const fn resize(&mut self, new_capacity: usize) {
        if new_capacity > self.capacity {
            self.capacity = new_capacity;
        }
    }

    const fn get_oldest(&self) -> &ConnectionIdEntry {
        &self.oldest
    }

    fn get(&self, seq: u64) -> Option<&ConnectionIdEntry> {
        self.iter().find(|e| e.seq == seq)
    }

    fn get_mut(&mut self, seq: u64) -> Option<&mut ConnectionIdEntry> {
        std::iter::once(&mut self.oldest)
            .chain(self.rest.iter_mut())
            .find(|e| e.seq == seq)
    }

    fn iter(&self) -> impl Iterator<Item = &ConnectionIdEntry> {
        std::iter::once(&self.oldest).chain(&self.rest)
    }

    const fn len(&self) -> usize {
        1 + self.rest.len()
    }

    fn insert(&mut self, e: ConnectionIdEntry) -> Result<()> {
        self.insert_retiring(e, 0, |_| {})
    }

    /// Retain the existing entry for a repeated sequence and process any
    /// newly requested retirement. Validate capacity before changing the
    /// collection. A new entry can replace the oldest even if all previous
    /// entries are retired, leaving no transient empty state.
    fn insert_retiring(
        &mut self, e: ConnectionIdEntry, retire_prior_to: u64,
        mut inspect: impl FnMut(&ConnectionIdEntry),
    ) -> Result<()> {
        if e.seq < retire_prior_to {
            return Err(Error::InvalidFrame);
        }
        let already_present = self.get(e.seq).is_some();
        let retained = self.iter().filter(|id| id.seq >= retire_prior_to).count();
        if retained.saturating_add(usize::from(!already_present)) > self.capacity
        {
            return Err(Error::IdLimit);
        }

        let retire_oldest = self.oldest.seq < retire_prior_to;
        if retire_oldest {
            inspect(&self.oldest);
        }
        self.rest.retain(|id| {
            if id.seq < retire_prior_to {
                inspect(id);
                false
            } else {
                true
            }
        });
        if retire_oldest {
            if let Some(next) = self.rest.pop_front() {
                self.oldest = next;
            } else {
                self.oldest = e;
                return Ok(());
            }
        }
        if !already_present {
            self.rest.push_back(e);
        }
        Ok(())
    }

    fn clear_and_insert(&mut self, e: ConnectionIdEntry) {
        self.oldest = e;
        self.rest.clear();
    }

    fn remove(&mut self, seq: u64) -> Result<Option<ConnectionIdEntry>> {
        if self.oldest.seq == seq {
            let next = self.rest.pop_front().ok_or(Error::OutOfIdentifiers)?;
            return Ok(Some(std::mem::replace(&mut self.oldest, next)));
        }
        Ok(self
            .rest
            .iter()
            .position(|e| e.seq == seq)
            .and_then(|index| self.rest.remove(index)))
    }
}

/// Direction of a connection identifier relative to this endpoint.
#[derive(Clone, Copy)]
pub enum CidDirection {
    Source,
    Destination,
}

pub struct ConnectionIdentifiers {
    /// All the Destination Connection IDs provided by our peer.
    dcids: BoundedNonEmptyConnectionIdVecDeque,

    /// All the Source Connection IDs we provide to our peer.
    scids: BoundedNonEmptyConnectionIdVecDeque,

    /// Source Connection IDs that should be announced to the peer.
    advertise_new_scid_seqs: VecDeque<u64>,

    /// Retired Destination Connection IDs that should be announced to the peer.
    retire_dcid_seqs: BoundedConnectionIdSeqSet,

    /// Retired Source Connection IDs that should be notified to the
    /// application.
    retired_scids: VecDeque<ConnectionId<'static>>,

    /// Largest "Retire Prior To" we received from the peer.
    largest_peer_retire_prior_to: u64,

    /// Next sequence number to use.
    next_scid_seq: u64,

    /// "Retire Prior To" value to advertise to the peer.
    retire_prior_to: u64,

    /// The maximum number of source Connection IDs our peer allows us.
    source_conn_id_limit: usize,

    /// Does the host use zero-length source Connection ID.
    zero_length_scid: bool,

    /// Does the host use zero-length destination Connection ID.
    zero_length_dcid: bool,
}

impl ConnectionIdentifiers {
    /// Creates a new `ConnectionIdentifiers` with the specified destination
    /// connection ID limit and initial source Connection ID. The destination
    /// Connection ID is set to the empty one.
    pub fn new(
        mut destination_conn_id_limit: usize, initial_scid: &ConnectionId,
        initial_path_id: usize, reset_token: Option<u128>,
    ) -> Self {
        // It must be at least 2.
        if destination_conn_id_limit < 2 {
            destination_conn_id_limit = 2;
        }

        // Initially, the limit of active source connection IDs is 2.
        let source_conn_id_limit = 2;

        // Record the zero-length SCID status.
        let zero_length_scid = initial_scid.is_empty();

        let initial_scid = ConnectionId::copy_from_slice(initial_scid.as_ref());

        // We need to track up to (2 * source_conn_id_limit - 1) source
        // Connection IDs when the host wants to force their renewal.
        let scids = BoundedNonEmptyConnectionIdVecDeque::new(
            2 * source_conn_id_limit - 1,
            ConnectionIdEntry {
                cid: initial_scid,
                seq: 0,
                reset_token,
                path_id: Some(initial_path_id),
            },
        );

        let dcids = BoundedNonEmptyConnectionIdVecDeque::new(
            destination_conn_id_limit,
            ConnectionIdEntry {
                cid: ConnectionId::default(),
                seq: 0,
                reset_token: None,
                path_id: Some(initial_path_id),
            },
        );

        let size = destination_conn_id_limit
            .saturating_mul(RETIRED_CONN_ID_LIMIT_MULTIPLIER);
        // Because we already inserted the initial SCID.
        let next_scid_seq = 1;
        Self {
            scids,
            dcids,
            retire_dcid_seqs: BoundedConnectionIdSeqSet::new(size),
            next_scid_seq,
            source_conn_id_limit,
            zero_length_scid,
            zero_length_dcid: false,
            advertise_new_scid_seqs: VecDeque::new(),
            retired_scids: VecDeque::new(),
            retire_prior_to: 0,
            largest_peer_retire_prior_to: 0,
        }
    }

    /// Sets the maximum number of source connection IDs our peer allows us.
    pub fn set_source_conn_id_limit(&mut self, v: u64) {
        // Bound conn id limit so our scids queue sizing is valid.
        let v = usize::try_from(v).unwrap_or(usize::MAX).min(usize::MAX / 2);

        // It must be at least 2.
        if v >= 2 {
            self.source_conn_id_limit = v;
            // We need to track up to (2 * source_conn_id_limit - 1) source
            // Connection IDs when the host wants to force their renewal.
            self.scids.resize(2 * v - 1);
        }
    }

    /// Remaining source-ID slots, respecting the actual rotation capacity
    /// and the application's local active-ID limit.
    pub fn scids_left(&self, local_limit: u64) -> usize {
        self.source_conn_id_limit
            .min(usize::try_from(local_limit).unwrap_or(usize::MAX))
            .saturating_sub(self.active_source_cids())
    }

    /// Gets the destination Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_dcid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.dcids.get(seq_num).ok_or(Error::InvalidState)
    }

    /// Gets the source Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_scid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.scids.get(seq_num).ok_or(Error::InvalidState)
    }

    /// Adds a new source identifier, and indicates whether it should be
    /// advertised through a `NEW_CONNECTION_ID` frame or not.
    ///
    /// At any time, the peer cannot have more Destination Connection IDs than
    /// the maximum number of active Connection IDs it negotiated. In such case
    /// (i.e., when [`active_source_cids()`] - `peer_active_conn_id_limit` = 0,
    /// if the caller agrees to request the removal of previous connection IDs,
    /// it sets the `retire_if_needed` parameter. Otherwise, an [`IdLimit`] is
    /// returned.
    ///
    /// Note that setting `retire_if_needed` does not prevent this function from
    /// returning an [`IdLimit`] in the case the caller wants to retire still
    /// unannounced Connection IDs.
    ///
    /// When setting the initial Source Connection ID, the `reset_token` may be
    /// `None`. However, other Source CIDs must have an associated
    /// `reset_token`. Providing `None` as the `reset_token` for non-initial
    /// SCIDs raises an [`InvalidState`].
    ///
    /// In the case the provided `cid` is already present, it does not add it.
    /// If the provided `reset_token` differs from the one already registered,
    /// returns an `InvalidState`.
    ///
    /// Returns the sequence number associated to that new source identifier.
    ///
    /// [`active_source_cids()`]:  struct.ConnectionIdentifiers.html#method.active_source_cids
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`IdLimit`]: enum.Error.html#IdLimit
    pub fn new_scid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        advertise: bool, path_id: Option<usize>, retire_if_needed: bool,
    ) -> Result<u64> {
        if self.zero_length_scid {
            return Err(Error::InvalidState);
        }

        // Re-adding an identifier must be idempotent even at capacity.
        if let Some(e) = self.scids.iter().find(|e| e.cid == cid) {
            if e.reset_token != reset_token {
                return Err(Error::InvalidState);
            }
            return Ok(e.seq);
        }

        let seq = self.next_scid_seq;
        if seq > octets::MAX_VAR_INT || (reset_token.is_none() && seq != 0) {
            return Err(Error::InvalidState);
        }

        // Plan rotation before mutating anything; insertion may fail at the
        // absolute collection capacity even when rotation is permitted.
        let retire_prior_to = if self.scids.len() >= self.source_conn_id_limit {
            if !retire_if_needed {
                return Err(Error::IdLimit);
            }
            self.lowest_usable_scid_seq()? + 1
        } else {
            self.retire_prior_to
        };

        self.scids.insert(ConnectionIdEntry {
            cid,
            seq,
            reset_token,
            path_id,
        })?;
        self.next_scid_seq = seq + 1;
        self.retire_prior_to = retire_prior_to;
        self.advertise_new_scid_seqs
            .retain(|&queued| queued >= retire_prior_to);

        self.mark_advertise_new_scid_seq(seq, advertise);

        Ok(seq)
    }

    /// Sets the initial destination identifier.
    pub fn set_initial_dcid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        path_id: Option<usize>,
    ) {
        // Record the zero-length DCID status.
        self.zero_length_dcid = cid.is_empty();
        self.dcids.clear_and_insert(ConnectionIdEntry {
            cid,
            seq: 0,
            reset_token,
            path_id,
        });
    }

    /// Adds a new Destination Connection ID (originating from a
    /// `NEW_CONNECTION_ID` frame) and process all its related metadata.
    ///
    /// Returns an error if the provided Connection ID or its metadata are
    /// invalid.
    ///
    /// Returns a list of tuples (DCID sequence number, Path ID), containing the
    /// sequence number of retired DCIDs that were linked to their respective
    /// Path ID.
    pub fn new_dcid(
        &mut self, cid: ConnectionId<'static>, seq: u64, reset_token: u128,
        retire_prior_to: u64, retired_path_ids: &mut SmallVec<[(u64, usize); 1]>,
    ) -> Result<()> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        // Check the wire invariant even for repetitions of a known ID.
        if retire_prior_to > seq {
            return Err(Error::InvalidFrame);
        }

        if let Some(e) = self.dcids.iter().find(|e| e.cid == cid || e.seq == seq)
        {
            if e.cid != cid || e.seq != seq || e.reset_token != Some(reset_token)
            {
                return Err(Error::InvalidFrame);
            }
        }

        // IDs older than the highest previously observed retirement point
        // must be retired, not reintroduced by a reordered frame.
        if seq < self.largest_peer_retire_prior_to {
            return self.mark_retire_dcid_seq(seq, true);
        }

        let new_entry = ConnectionIdEntry {
            cid,
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        };
        let retire_prior_to =
            self.largest_peer_retire_prior_to.max(retire_prior_to);
        let retired = &mut self.retire_dcid_seqs;
        let mut retired_dcid_queue_err = None;

        // Repeated identifiers may carry a larger Retire Prior To value.
        // Preserve their existing path association and process retirement
        // even when the ID itself is already present.
        self.dcids
            .insert_retiring(new_entry, retire_prior_to, |e| {
                if let Some(pid) = e.path_id {
                    retired_path_ids.push((e.seq, pid));
                }
                if let Err(error) = retired.insert(e.seq) {
                    // Finish retirement and replacement before reporting queue
                    // exhaustion so the caller can update affected paths.
                    retired_dcid_queue_err.get_or_insert(error);
                }
            })?;
        self.largest_peer_retire_prior_to = retire_prior_to;

        // Propagate the error triggered when inserting a retired DCID seq to
        // the queue.
        if let Some(e) = retired_dcid_queue_err {
            return Err(e);
        }

        Ok(())
    }

    /// Retires the Source Connection ID having the provided sequence number.
    ///
    /// In case the retired Connection ID is the same as the one used by the
    /// packet requesting the retiring, or if the retired sequence number is
    /// greater than any previously advertised sequence numbers, it returns an
    /// [`InvalidState`].
    ///
    /// Returns the path ID that was associated to the retired CID, if any.
    ///
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn retire_scid(
        &mut self, seq: u64, pkt_dcid: &ConnectionId,
    ) -> Result<Option<usize>> {
        if seq >= self.next_scid_seq {
            return Err(Error::InvalidState);
        }

        let Some(entry) = self.scids.get(seq) else {
            return Ok(None);
        };
        if self.scids.len() == 1 {
            return Err(Error::OutOfIdentifiers);
        }
        if entry.cid == *pkt_dcid {
            return Err(Error::InvalidState);
        }
        let lowest_scid_seq = self
            .scids
            .iter()
            .filter(|e| e.seq != seq && e.seq >= self.retire_prior_to)
            .map(|e| e.seq)
            .min()
            .ok_or(Error::OutOfIdentifiers)?;

        let e = self.scids.remove(seq)?.ok_or(Error::InvalidState)?;
        self.retired_scids.push_back(e.cid);
        self.retire_prior_to = lowest_scid_seq;
        self.advertise_new_scid_seqs
            .retain(|&queued| queued >= lowest_scid_seq && queued != seq);
        Ok(e.path_id)
    }

    /// Retires the Destination Connection ID having the provided sequence
    /// number.
    ///
    /// If the caller tries to retire the last destination Connection ID, this
    /// method triggers an [`OutOfIdentifiers`].
    ///
    /// If the caller tries to retire a non-existing Destination Connection
    /// ID sequence number, this method returns an [`InvalidState`].
    ///
    /// Returns the path ID that was associated to the retired CID, if any.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn retire_dcid(&mut self, seq: u64) -> Result<Option<usize>> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        if self.dcids.get(seq).is_none() {
            return Err(Error::InvalidState);
        }
        if self.dcids.len() == 1 {
            return Err(Error::OutOfIdentifiers);
        }
        // The queue can fail at capacity; preserve the ID and its path then.
        self.mark_retire_dcid_seq(seq, true)?;
        let e = self.dcids.remove(seq)?.ok_or(Error::InvalidState)?;
        Ok(e.path_id)
    }

    /// Returns an iterator over the source connection IDs.
    pub fn scids_iter(&self) -> impl Iterator<Item = &ConnectionId<'static>> {
        self.scids.iter().map(|e| &e.cid)
    }

    /// Updates the Source Connection ID entry with the provided sequence number
    /// to indicate that it is now linked to the provided path ID.
    pub fn link_scid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.scids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Updates the Destination Connection ID entry with the provided sequence
    /// number to indicate that it is now linked to the provided path ID.
    pub fn link_dcid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.dcids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Updates the Destination Connection ID entry with the provided sequence
    /// number to indicate that it is no longer linked to any path, so that a
    /// new path can take it.
    pub fn unlink_dcid(&mut self, dcid_seq: u64) {
        if let Some(e) = self.dcids.get_mut(dcid_seq) {
            e.path_id = None;
        }
    }

    /// Gets the minimum Source Connection ID sequence number whose removal has
    /// not been requested yet.
    #[inline]
    pub fn lowest_usable_scid_seq(&self) -> Result<u64> {
        self.scids
            .iter()
            .filter_map(|e| {
                if e.seq >= self.retire_prior_to {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
            .ok_or(Error::InvalidState)
    }

    /// Gets the lowest Destination Connection ID sequence number that is not
    /// associated to a path.
    #[inline]
    pub fn lowest_available_dcid_seq(&self) -> Option<u64> {
        self.dcids
            .iter()
            .filter_map(|e| {
                if e.path_id.is_none() {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
    }

    /// Checks the candidate stateless reset token against all live peer DCIDs.
    ///
    /// The initial DCID can be learned before TLS delivers its transport
    /// parameters, including the initial reset token. Use that token only as
    /// the fallback for DCID sequence zero, and stop accepting it once that
    /// initial ID is retired. Other IDs carry their own NEW_CONNECTION_ID
    /// tokens. Evaluate every candidate even after a match, so matching does
    /// not depend on where the matching token occurs in the live CID set.
    pub fn matches_reset_token(
        &self, candidate: &[u8], initial_reset_token: Option<u128>,
    ) -> bool {
        if candidate.len() != size_of::<u128>() {
            return false;
        }

        let mut matched = false;
        for entry in self.dcids.iter() {
            let token = if entry.seq == 0 {
                entry.reset_token.or(initial_reset_token)
            } else {
                entry.reset_token
            };
            if let Some(token) = token {
                matched |= crypto::verify_slices_are_equal(
                    &token.to_be_bytes(),
                    candidate,
                )
                .is_ok();
            }
        }
        matched
    }

    /// Finds the sequence number of the Source Connection ID having the
    /// provided value and the identifier of the path using it, if any.
    #[inline]
    pub fn find_scid_seq(
        &self, scid: &ConnectionId,
    ) -> Option<(u64, Option<usize>)> {
        self.scids.iter().find_map(|e| {
            if e.cid == *scid {
                Some((e.seq, e.path_id))
            } else {
                None
            }
        })
    }

    /// Returns the number of Source Connection IDs that have not been
    /// assigned to a path yet.
    ///
    /// Note that this function is only meaningful if the host uses non-zero
    /// length Source Connection IDs.
    #[inline]
    pub fn available_scids(&self) -> usize {
        self.scids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Returns the number of Destination Connection IDs that have not been
    /// assigned to a path yet.
    ///
    /// Note that this function returns 0 if the host uses zero length
    /// Destination Connection IDs.
    #[inline]
    pub fn available_dcids(&self) -> usize {
        if self.zero_length_dcid() {
            return 0;
        }
        self.dcids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Selects the active path's connection ID or the oldest remaining ID
    /// of the same direction when that path has no usable identifier.
    pub fn active_or_oldest(
        &self, direction: CidDirection, sequence: Option<u64>,
    ) -> &ConnectionId<'static> {
        let entries = match direction {
            CidDirection::Source => &self.scids,
            CidDirection::Destination => &self.dcids,
        };
        let entry = sequence
            .and_then(|seq| entries.get(seq))
            .unwrap_or_else(|| entries.get_oldest());
        &entry.cid
    }

    /// Adds or remove the source Connection ID sequence number from the
    /// source Connection ID set that need to be advertised to the peer through
    /// `NEW_CONNECTION_ID` frames.
    #[inline]
    pub fn mark_advertise_new_scid_seq(
        &mut self, scid_seq: u64, advertise: bool,
    ) {
        if advertise {
            if scid_seq >= self.retire_prior_to &&
                self.scids.get(scid_seq).is_some() &&
                !self.advertise_new_scid_seqs.contains(&scid_seq)
            {
                self.advertise_new_scid_seqs.push_back(scid_seq);
            }
        } else if let Some(index) = self
            .advertise_new_scid_seqs
            .iter()
            .position(|s| *s == scid_seq)
        {
            self.advertise_new_scid_seqs.remove(index);
        }
    }

    /// Adds or remove the destination Connection ID sequence number from the
    /// retired destination Connection ID set that need to be advertised to the
    /// peer through `RETIRE_CONNECTION_ID` frames.
    #[inline]
    pub fn mark_retire_dcid_seq(
        &mut self, dcid_seq: u64, retire: bool,
    ) -> Result<()> {
        if retire {
            self.retire_dcid_seqs.insert(dcid_seq)?;
        } else {
            self.retire_dcid_seqs.remove(dcid_seq);
        }

        Ok(())
    }

    /// Gets a source Connection ID's sequence number requiring advertising it
    /// to the peer through `NEW_CONNECTION_ID` frame, if any.
    ///
    /// If `Some`, it always returns the same value until it has been removed
    /// using `mark_advertise_new_scid_seq`.
    #[inline]
    pub fn next_advertise_new_scid_seq(&self) -> Option<u64> {
        self.advertise_new_scid_seqs.front().copied()
    }

    /// Returns a copy of the set of destination Connection IDs's sequence
    /// numbers to send `RETIRE_CONNECTION_ID` frames.
    ///
    /// Note that the set includes sequence numbers at the time the copy was
    /// created. To account for newly inserted or removed sequence numbers, a
    /// new copy needs to be created.
    #[inline]
    pub fn retire_dcid_seqs(&self) -> HashSet<u64> {
        self.retire_dcid_seqs.inner.clone()
    }

    /// Returns true if there are new source Connection IDs to advertise.
    #[inline]
    pub const fn has_new_scids(&self) -> bool {
        !self.advertise_new_scid_seqs.is_empty()
    }

    /// Returns true if there are retired destination Connection IDs to\
    /// advertise.
    #[inline]
    pub fn has_retire_dcids(&self) -> bool {
        !self.retire_dcid_seqs.is_empty()
    }

    /// Returns whether zero-length source CIDs are used.
    #[inline]
    pub const fn zero_length_scid(&self) -> bool {
        self.zero_length_scid
    }

    /// Returns whether zero-length destination CIDs are used.
    #[inline]
    pub const fn zero_length_dcid(&self) -> bool {
        self.zero_length_dcid
    }

    /// Gets the `NEW_CONNECTION_ID` frame related to the source connection ID
    /// with sequence `seq_num`.
    pub fn get_new_connection_id_frame_for(
        &self, seq_num: u64,
    ) -> Result<frame::Frame> {
        let e = self.scids.get(seq_num).ok_or(Error::InvalidState)?;
        Ok(frame::Frame::NewConnectionId {
            seq_num,
            retire_prior_to: self.retire_prior_to,
            conn_id: e.cid.clone(),
            reset_token: e.reset_token.ok_or(Error::InvalidState)?.to_be_bytes(),
        })
    }

    /// Returns the number of source Connection IDs that are active. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    #[inline]
    pub fn active_source_cids(&self) -> usize {
        self.scids.len()
    }

    /// Returns the number of source Connection IDs that are retired. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    #[inline]
    pub const fn retired_source_cids(&self) -> usize {
        self.retired_scids.len()
    }

    pub fn pop_retired_scid(&mut self) -> Option<ConnectionId<'static>> {
        self.retired_scids.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_cid_and_reset_token;

    #[test]
    fn matches_initial_and_rotated_stateless_reset_tokens_until_retirement() {
        let mut ids = ConnectionIdentifiers::new(
            4,
            &ConnectionId::from_ref(b"source"),
            0,
            None,
        );
        let initial_token = u128::from_be_bytes([0x11; 16]);
        let rotated_token = u128::from_be_bytes([0x22; 16]);
        let third_token = u128::from_be_bytes([0x33; 16]);
        ids.set_initial_dcid(vec![1].into(), Some(initial_token), Some(0));
        let mut retired_path_ids = SmallVec::new();
        ids.new_dcid(vec![2].into(), 1, rotated_token, 0, &mut retired_path_ids)
            .unwrap();
        ids.new_dcid(vec![3].into(), 2, third_token, 0, &mut retired_path_ids)
            .unwrap();
        assert!(retired_path_ids.is_empty());
        for token in [initial_token, rotated_token, third_token] {
            assert!(ids.matches_reset_token(&token.to_be_bytes(), None));
        }
        assert!(!ids.matches_reset_token(&[0x44; 16], None));
        assert!(!ids.matches_reset_token(&rotated_token.to_be_bytes()[1..], None));

        // Retirement removes the token from the set of valid live tokens.
        assert_eq!(ids.retire_dcid(1), Ok(None));
        assert!(!ids.matches_reset_token(&rotated_token.to_be_bytes(), None));
        assert!(ids.matches_reset_token(&initial_token.to_be_bytes(), None));
        assert!(ids.matches_reset_token(&third_token.to_be_bytes(), None));
    }

    #[test]
    fn late_transport_parameter_token_only_matches_live_initial_dcid() {
        let mut ids = ConnectionIdentifiers::new(
            3,
            &ConnectionId::from_ref(b"source"),
            0,
            None,
        );
        ids.set_initial_dcid(vec![1].into(), None, Some(0));
        let token = u128::from_be_bytes([0x5a; 16]);
        assert!(!ids.matches_reset_token(&token.to_be_bytes(), None));
        assert!(ids.matches_reset_token(&token.to_be_bytes(), Some(token)));

        let mut retired_path_ids = SmallVec::new();
        ids.new_dcid(vec![2].into(), 1, 0xaa, 0, &mut retired_path_ids)
            .unwrap();
        assert_eq!(ids.retire_dcid(0), Ok(Some(0)));
        assert!(!ids.matches_reset_token(&token.to_be_bytes(), Some(token)));
        assert!(ids.matches_reset_token(&0xaa_u128.to_be_bytes(), Some(token)));
    }

    #[test]
    fn repeated_destination_id_advances_retirement_without_replacing_path() {
        let mut ids =
            ConnectionIdentifiers::new(3, &ConnectionId::from_ref(b"s"), 0, None);
        ids.set_initial_dcid(vec![10].into(), None, Some(0));
        let mut retired = SmallVec::new();
        for seq in 1..=2 {
            ids.new_dcid(
                vec![10 + seq as u8].into(),
                seq,
                u128::from(seq),
                0,
                &mut retired,
            )
            .unwrap();
        }
        ids.link_dcid_to_path_id(2, 7).unwrap();
        assert_eq!(
            ids.new_dcid(vec![12].into(), 2, 2, 3, &mut retired),
            Err(Error::InvalidFrame)
        );
        assert_eq!(ids.dcids.len(), 3);
        assert!(retired.is_empty());

        ids.new_dcid(vec![12].into(), 2, 2, 2, &mut retired)
            .unwrap();
        assert_eq!(ids.dcids.len(), 1);
        assert_eq!(ids.dcids.get_oldest().seq, 2);
        assert_eq!(ids.get_dcid(2).unwrap().path_id, Some(7));
        assert_eq!(retired.as_slice(), &[(0, 0)]);
        assert_eq!(ids.retire_dcid_seqs(), HashSet::from([0, 1]));
    }

    #[test]
    fn failed_source_id_operations_preserve_rotation_state() {
        let scid = ConnectionId::from_ref(b"s");
        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        let first = ConnectionId::from_vec(vec![1]);
        assert_eq!(
            ids.new_scid(first.clone(), Some(1), true, None, false),
            Ok(1)
        );
        assert_eq!(
            ids.new_scid(first.clone(), Some(1), true, None, false),
            Ok(1)
        );
        assert_eq!(
            ids.new_scid(first.clone(), Some(2), true, None, true),
            Err(Error::InvalidState)
        );
        assert_eq!(ids.retire_prior_to, 0);
        assert_eq!(
            ids.new_scid(vec![2].into(), Some(2), true, None, true),
            Ok(2)
        );
        assert_eq!(ids.retire_prior_to, 1);
        assert_eq!(
            ids.new_scid(vec![3].into(), Some(3), true, None, true),
            Err(Error::IdLimit)
        );
        assert_eq!(ids.retire_prior_to, 1);
        assert_eq!(ids.next_scid_seq, 3);

        assert_eq!(ids.retire_scid(1, &first), Err(Error::InvalidState));
        assert_eq!(ids.scids.len(), 3);
        assert_eq!(ids.pop_retired_scid(), None);
        ids.mark_advertise_new_scid_seq(1, true);
        ids.mark_advertise_new_scid_seq(0, true);
        assert_eq!(
            ids.advertise_new_scid_seqs
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(ids.retire_scid(1, &scid), Ok(None));
        ids.mark_advertise_new_scid_seq(1, true);
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(2));
    }

    #[test]
    fn full_retirement_queue_is_idempotent_and_preserves_unretired_id() {
        let mut ids =
            ConnectionIdentifiers::new(2, &ConnectionId::from_ref(b"s"), 0, None);
        ids.set_initial_dcid(vec![10].into(), None, Some(0));
        let mut retired = SmallVec::new();
        ids.new_dcid(vec![11].into(), 1, 1, 0, &mut retired)
            .unwrap();
        ids.retire_dcid_seqs.capacity = 1;
        assert_eq!(ids.mark_retire_dcid_seq(99, true), Ok(()));
        assert_eq!(ids.mark_retire_dcid_seq(99, true), Ok(()));
        assert_eq!(ids.retire_dcid(0), Err(Error::IdLimit));
        assert_eq!(ids.get_dcid(0).unwrap().path_id, Some(0));
        assert_eq!(ids.dcids.len(), 2);
        ids.mark_retire_dcid_seq(99, false).unwrap();
        assert_eq!(ids.retire_dcid(0), Ok(Some(0)));
        assert_eq!(ids.dcids.get_oldest().seq, 1);
    }

    #[test]
    fn large_connection_id_limits_do_not_overflow() {
        let scid = ConnectionId::from_ref(b"initial");
        let mut ids = ConnectionIdentifiers::new(usize::MAX, &scid, 0, None);
        assert_eq!(ids.dcids.capacity, usize::MAX);
        assert_eq!(ids.retire_dcid_seqs.capacity, usize::MAX);
        // These are logical bounds, not eager allocation sizes.
        assert_eq!(ids.dcids.len(), 1);
        assert_eq!(ids.scids.len(), 1);
        assert!(ids.retire_dcid_seqs.is_empty());

        ids.set_source_conn_id_limit(u64::MAX);
        assert_eq!(ids.scids_left(u64::MAX), usize::MAX / 2 - 1);
        assert_eq!(ids.scids_left(3), 2);
        assert_eq!(ids.scids_left(1), 0);

        let (next, token) = create_cid_and_reset_token(16);
        assert_eq!(ids.new_scid(next, Some(token), true, None, false), Ok(1));
        assert_eq!(ids.scids_left(u64::MAX), usize::MAX / 2 - 2);
    }

    #[test]
    fn ids_new_scids() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 0);
        assert!(!ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), None);

        let (scid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid2, Some(rt2), true, None, false), Ok(1));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 1);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid3, Some(rt3), true, None, false), Ok(2));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        // If now we give another CID, it reports an error since it exceeds the
        // limit of active CIDs.
        let (scid4, rt4) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid4, Some(rt4), true, None, false),
            Err(Error::IdLimit),
        );
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        // Assume we sent one of them.
        ids.mark_advertise_new_scid_seq(1, false);
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(2));

        // Send the other.
        ids.mark_advertise_new_scid_seq(2, false);

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert!(!ids.has_new_scids());
        assert_eq!(ids.next_advertise_new_scid_seq(), None);
    }

    #[test]
    fn new_dcid_event() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        let (dcid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_dcid(dcid2, 1, rt2, 0, &mut retired_path_ids),
            Ok(()),
        );
        assert_eq!(retired_path_ids, SmallVec::from_buf([]));
        assert_eq!(ids.available_dcids(), 1);
        assert_eq!(ids.dcids.len(), 2);

        // Now we assume that the client wants to advertise more source
        // Connection IDs than the advertised limit. This is valid if it
        // requests its peer to retire enough Connection IDs to fit within the
        // limits.
        let (dcid3, rt3) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.new_dcid(dcid3, 2, rt3, 1, &mut retired_path_ids),
            Ok(())
        );
        assert_eq!(retired_path_ids, SmallVec::from_buf([(0, 0)]));
        // The CID module does not handle path replacing. Fake it now.
        ids.link_dcid_to_path_id(1, 0).unwrap();
        assert_eq!(ids.available_dcids(), 1);
        assert_eq!(ids.dcids.len(), 2);
        assert!(ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), Some(&0));

        // Fake RETIRE_CONNECTION_ID sending.
        let _ = ids.mark_retire_dcid_seq(0, false);
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), None);

        // Now tries to experience CID retirement. If the server tries to remove
        // non-existing DCIDs, it fails.
        assert_eq!(ids.retire_dcid(0), Err(Error::InvalidState));
        assert_eq!(ids.retire_dcid(3), Err(Error::InvalidState));
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.dcids.len(), 2);

        // Now it removes DCID with sequence 1.
        assert_eq!(ids.retire_dcid(1), Ok(Some(0)));
        // The CID module does not handle path replacing. Fake it now.
        ids.link_dcid_to_path_id(2, 0).unwrap();
        assert_eq!(ids.available_dcids(), 0);
        assert!(ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), Some(&1));
        assert_eq!(ids.dcids.len(), 1);

        // Fake RETIRE_CONNECTION_ID sending.
        let _ = ids.mark_retire_dcid_seq(1, false);
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.retire_dcid_seqs().iter().next(), None);

        // Trying to remove the last DCID triggers an error.
        assert_eq!(ids.retire_dcid(2), Err(Error::OutOfIdentifiers));
        assert_eq!(ids.retire_dcid(0), Err(Error::InvalidState));
        assert_eq!(ids.retire_dcid(1), Err(Error::InvalidState));
        assert_eq!(ids.available_dcids(), 0);
        assert!(!ids.has_retire_dcids());
        assert_eq!(ids.dcids.len(), 1);
    }

    #[test]
    fn new_dcid_reordered() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        // Skip DCID #1 (e.g due to packet loss) and insert DCID #2.
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 2, rt, 1, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 1);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 3, rt, 2, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 4, rt, 3, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        // Insert DCID #1 (e.g due to packet reordering). It should be discarded
        // due to `largest_peer_retire_prior_to`.
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 1, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);
        assert!(ids.get_dcid(1).is_err());

        // Try inserting DCID #1 again (e.g. due to retransmission).
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 1, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);
        assert!(ids.get_dcid(1).is_err());
    }

    #[test]
    fn new_dcid_partial_retire_prior_to() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(5, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 1, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 2, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 3);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 3, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 4);

        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 4, rt, 0, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 5);

        // Retire a DCID from the middle of the list
        assert!(ids.retire_dcid(3).is_ok());

        // Retire prior to DCID that was just retired.
        //
        // This is largely to test that `retire_prior_to()` works correctly even
        // if the actual sequence that is searched isn't present in the list.
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 5, rt, 3, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 2);

        // Retire all current DCIDs while adding a new one
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 6, rt, 6, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 1);
    }

    #[test]
    fn new_dcid_partial_retire_out_of_order() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut retired_path_ids = SmallVec::new();

        let mut ids = ConnectionIdentifiers::new(5, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        // Insert 5 DCIDs where some are out of order
        let seq_nums = [5, 3, 2, 19, 8];
        for &seq in &seq_nums {
            let (dcid, rt) = create_cid_and_reset_token(16);
            assert!(ids
                .new_dcid(dcid, seq, rt, 1, &mut retired_path_ids)
                .is_ok());
        }
        assert_eq!(ids.dcids.len(), 5);

        // Trigger a retire of sequence numbers 2 and 3, inserting #20
        let (dcid, rt) = create_cid_and_reset_token(16);
        assert!(ids.new_dcid(dcid, 20, rt, 4, &mut retired_path_ids).is_ok());
        assert_eq!(ids.dcids.len(), 4);
        assert!(ids.get_dcid(20).is_ok());

        for &seq in &seq_nums {
            let dcid = ids.get_dcid(seq);
            assert_eq!(dcid.is_ok(), seq >= 4);
        }

        // Check that the DCID deque maintains insertion order
        let seq_iter = ids.dcids.iter().map(|e| e.seq);
        for (seq, expected) in seq_iter.zip([5, 19, 8, 20]) {
            assert_eq!(seq, expected);
        }
    }

    #[test]
    fn retire_scids() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(3, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));
        ids.set_source_conn_id_limit(3);

        let (scid2, rt2) = create_cid_and_reset_token(16);
        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid2.clone(), Some(rt2), true, None, false),
            Ok(1),
        );
        assert_eq!(ids.scids.len(), 2);
        assert_eq!(
            ids.new_scid(scid3.clone(), Some(rt3), true, None, false),
            Ok(2),
        );
        assert_eq!(ids.scids.len(), 3);

        assert_eq!(ids.pop_retired_scid(), None);

        assert_eq!(ids.retire_scid(0, &scid2), Ok(Some(0)));

        assert_eq!(ids.pop_retired_scid(), Some(scid));
        assert_eq!(ids.pop_retired_scid(), None);

        assert_eq!(ids.retire_scid(1, &scid3), Ok(None));
        assert_eq!(ids.scids.len(), 1);

        // The peer may retransmit RETIRE_CONNECTION_ID.
        assert_eq!(ids.retire_scid(1, &scid3), Ok(None));
        assert_eq!(ids.scids.len(), 1);

        assert_eq!(ids.pop_retired_scid(), Some(scid2));
        assert_eq!(ids.pop_retired_scid(), None);

        // The last SCID cannot be retired.
        assert_eq!(ids.retire_scid(2, &scid3), Err(Error::OutOfIdentifiers));
        assert_eq!(ids.scids.len(), 1);
    }
}
