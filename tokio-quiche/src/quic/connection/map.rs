// Copyright (C) 2025, Cloudflare, Inc.
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

use super::Incoming;
use quiche::ConnectionId;
use quiche::MAX_CONN_ID_LEN;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

const WORD_SIZE: usize = size_of::<u64>();
const WORDS: usize = (MAX_CONN_ID_LEN + 1).div_ceil(WORD_SIZE);

/// Inline keys for all QUIC v1 CIDs; preserve longer long-header IDs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CidOwned {
    Inline([u64; WORDS]),
    Long(Box<[u8]>),
}

impl From<&ConnectionId<'_>> for CidOwned {
    fn from(value: &ConnectionId<'_>) -> Self {
        if value.len() > MAX_CONN_ID_LEN {
            return Self::Long(value.as_ref().into());
        }
        let mut words = [0; WORDS];
        for (word, chunk) in words.iter_mut().zip(value.chunks(WORD_SIZE)) {
            let mut bytes = [0; WORD_SIZE];
            bytes[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        words[WORDS - 1] |= (value.len() as u64) << 56;
        Self::Inline(words)
    }
}

/// Unique within the lifetime of a router; never derived from a rotating CID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::quic) struct RouteOwner(u64);

pub(in crate::quic) enum ConnectionMapCommand {
    Register {
        owner: RouteOwner,
        cid: ConnectionId<'static>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Retire {
        owner: RouteOwner,
        cid: ConnectionId<'static>,
    },
    Close(RouteOwner),
}

/// Moves with the connection, including its unstarted and cancelled states.
/// Dropping it releases every route even when normal worker close is skipped.
pub(in crate::quic) struct RouteLease {
    owner: RouteOwner,
    commands: Option<mpsc::UnboundedSender<ConnectionMapCommand>>,
}

impl RouteLease {
    pub(crate) const fn new(
        owner: RouteOwner, commands: mpsc::UnboundedSender<ConnectionMapCommand>,
    ) -> Self {
        Self {
            owner,
            commands: Some(commands),
        }
    }

    pub(crate) fn raw(
        commands: mpsc::UnboundedSender<ConnectionMapCommand>,
    ) -> Self {
        Self::new(RouteOwner(0), commands)
    }

    pub(crate) async fn register(
        &self, cid: ConnectionId<'static>,
    ) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(router_closed)?
            .send(ConnectionMapCommand::Register {
                owner: self.owner,
                cid,
                reply,
            })
            .map_err(|_| router_closed())?;
        result.await.map_err(|_| router_closed())?
    }

    pub(crate) fn retire(&self, cid: ConnectionId<'static>) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(ConnectionMapCommand::Retire {
                owner: self.owner,
                cid,
            });
        }
    }

    pub(crate) fn close(&mut self) {
        if let Some(commands) = self.commands.take() {
            let _ = commands.send(ConnectionMapCommand::Close(self.owner));
        }
    }
}

impl Drop for RouteLease {
    fn drop(&mut self) {
        self.close();
    }
}

fn router_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "connection router closed")
}

fn collision() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "connection ID is already registered",
    )
}

struct Route {
    owner: RouteOwner,
    sender: mpsc::Sender<Incoming>,
}

struct OwnerRoutes {
    sender: mpsc::Sender<Incoming>,
    ids: BTreeSet<CidOwned>,
}

/// Direct single-lookup packet routing, with an inverse index for bounded
/// owner cleanup. All mutation occurs on the router task.
#[derive(Default)]
pub(in crate::quic) struct ConnectionMap {
    routes: BTreeMap<CidOwned, Route>,
    owners: BTreeMap<RouteOwner, OwnerRoutes>,
    next_owner: u64,
}

impl ConnectionMap {
    pub(crate) fn allocate_owner(&mut self) -> io::Result<RouteOwner> {
        let owner = RouteOwner(self.next_owner);
        self.next_owner = self
            .next_owner
            .checked_add(1)
            .ok_or_else(|| io::Error::other("connection owner ID exhausted"))?;
        Ok(owner)
    }

    pub(crate) fn insert(
        &mut self, owner: RouteOwner, sender: mpsc::Sender<Incoming>,
        scid: &ConnectionId<'_>, pending: Option<&ConnectionId<'_>>,
    ) -> io::Result<()> {
        let ids: BTreeSet<_> = std::iter::once(scid)
            .chain(pending)
            .map(CidOwned::from)
            .collect();
        if self.owners.contains_key(&owner) ||
            ids.iter().any(|id| self.routes.contains_key(id))
        {
            return Err(collision());
        }
        for id in &ids {
            self.routes.insert(id.clone(), Route {
                owner,
                sender: sender.clone(),
            });
        }
        self.owners.insert(owner, OwnerRoutes { sender, ids });
        Ok(())
    }

    pub(crate) fn register(
        &mut self, owner: RouteOwner, cid: &ConnectionId<'_>,
    ) -> io::Result<()> {
        let id = CidOwned::from(cid);
        let routes = self.owners.get_mut(&owner).ok_or_else(router_closed)?;
        // Reusing any active CID, even within one owner, is an error for a
        // fresh NEW_CONNECTION_ID registration.
        if self.routes.contains_key(&id) {
            return Err(collision());
        }
        self.routes.insert(id.clone(), Route {
            owner,
            sender: routes.sender.clone(),
        });
        routes.ids.insert(id);
        Ok(())
    }

    pub(crate) fn retire(&mut self, owner: RouteOwner, cid: &ConnectionId<'_>) {
        let id = CidOwned::from(cid);
        if let Some(routes) = self.owners.get_mut(&owner) {
            if routes.ids.remove(&id) &&
                self.routes
                    .get(&id)
                    .is_some_and(|route| route.owner == owner)
            {
                self.routes.remove(&id);
            }
        }
    }

    pub(crate) fn close(&mut self, owner: RouteOwner) {
        if let Some(routes) = self.owners.remove(&owner) {
            for id in routes.ids {
                if self
                    .routes
                    .get(&id)
                    .is_some_and(|route| route.owner == owner)
                {
                    self.routes.remove(&id);
                }
            }
        }
    }

    pub(crate) fn get(
        &self, id: &ConnectionId<'_>,
    ) -> Option<&mpsc::Sender<Incoming>> {
        self.routes
            .get(&CidOwned::from(id))
            .map(|route| &route.sender)
    }

    pub(crate) fn apply(&mut self, command: ConnectionMapCommand) {
        match command {
            ConnectionMapCommand::Register { owner, cid, reply } => {
                // A cancelled request must not create a route after the
                // connection has already stopped waiting for it.
                if !reply.is_closed() {
                    let result = self.register(owner, &cid);
                    if matches!(reply.send(result), Err(Ok(()))) {
                        self.retire(owner, &cid);
                    }
                }
            },
            ConnectionMapCommand::Retire { owner, cid } =>
                self.retire(owner, &cid),
            ConnectionMapCommand::Close(owner) => self.close(owner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CidOwned;
    use super::ConnectionMap;
    use super::RouteLease;
    use quiche::ConnectionId;
    use quiche::MAX_CONN_ID_LEN;
    use tokio::sync::mpsc;

    #[test]
    fn inline_keys_distinguish_all_lengths_and_zero_suffixes() {
        let bytes = [0; MAX_CONN_ID_LEN + 1];
        let keys: std::collections::BTreeSet<_> = (0..=bytes.len())
            .map(|len| CidOwned::from(&ConnectionId::from_ref(&bytes[..len])))
            .collect();
        assert_eq!(keys.len(), bytes.len() + 1);
        for len in 0..=MAX_CONN_ID_LEN {
            assert!(matches!(
                CidOwned::from(&ConnectionId::from_ref(&bytes[..len])),
                CidOwned::Inline(_)
            ));
        }
        assert!(matches!(
            CidOwned::from(&ConnectionId::from_ref(&bytes)),
            CidOwned::Long(_)
        ));
    }

    #[test]
    fn colliding_initial_registration_is_atomic() -> std::io::Result<()> {
        let mut map = ConnectionMap::default();
        let first = map.allocate_owner()?;
        let second = map.allocate_owner()?;
        let (a, _rx_a) = mpsc::channel(1);
        let (b, _rx_b) = mpsc::channel(1);
        let existing = ConnectionId::from_ref(b"existing");
        let candidate = ConnectionId::from_ref(b"candidate");
        map.insert(first, a.clone(), &existing, None)?;
        assert!(map.insert(second, b, &candidate, Some(&existing)).is_err());
        assert!(map.get(&candidate).is_none());
        assert!(map
            .get(&existing)
            .is_some_and(|sender| sender.same_channel(&a)));
        Ok(())
    }

    #[test]
    fn rotation_and_stale_commands_cannot_steal_or_remove_routes(
    ) -> std::io::Result<()> {
        let mut map = ConnectionMap::default();
        let first = map.allocate_owner()?;
        let second = map.allocate_owner()?;
        let (a, _rx_a) = mpsc::channel(1);
        let (b, _rx_b) = mpsc::channel(1);
        let original = ConnectionId::from_ref(b"original");
        let rotated = ConnectionId::from_ref(b"rotated");
        map.insert(first, a.clone(), &original, None)?;
        map.register(first, &rotated)?;
        assert!(map.register(first, &rotated).is_err());
        map.retire(first, &original);
        map.insert(second, b.clone(), &original, None)?;
        assert!(map.register(first, &original).is_err());
        map.retire(first, &original);
        assert!(map
            .get(&original)
            .is_some_and(|sender| sender.same_channel(&b)));
        map.close(first);
        assert!(map.get(&rotated).is_none());
        assert!(map
            .get(&original)
            .is_some_and(|sender| sender.same_channel(&b)));
        assert!(map.register(first, &rotated).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn lease_registration_is_acknowledged_and_drop_cleans_every_route(
    ) -> crate::QuicResult<()> {
        let mut map = ConnectionMap::default();
        let owner = map.allocate_owner()?;
        let (sender, _receiver) = mpsc::channel(1);
        let original = ConnectionId::from_ref(b"initial");
        let pending = ConnectionId::from_ref(b"pending");
        let rotated = ConnectionId::from_ref(b"rotated");
        map.insert(owner, sender, &original, Some(&pending))?;
        let (commands, mut receiver) = mpsc::unbounded_channel();
        let lease = RouteLease::new(owner, commands);
        let (result, ()) = tokio::join!(lease.register(rotated.clone()), async {
            if let Some(command) = receiver.recv().await {
                map.apply(command);
            }
        });
        result?;
        assert!(map.get(&rotated).is_some());
        drop(lease);
        map.apply(receiver.recv().await.ok_or("missing close command")?);
        assert!(map.get(&original).is_none());
        assert!(map.get(&pending).is_none());
        assert!(map.get(&rotated).is_none());
        Ok(())
    }
}
