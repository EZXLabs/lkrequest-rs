//! Regressions for untrusted DNS responses (RUSTSEC-2026-0488/0491/0517).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use lkrequest::dns::hickory::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts,
};
use lkrequest::dns::hickory::proto::op::{Message, MessageType, OpCode, Query};
use lkrequest::dns::hickory::proto::rr::rdata::A;
use lkrequest::dns::hickory::proto::rr::{Name, RData, Record, RecordType};
use lkrequest::dns::{DnsResolver, HickoryDns};
use tokio::net::UdpSocket;

thread_local! {
    static LARGEST_ALLOCATION: Cell<Option<usize>> = const { Cell::new(None) };
}

struct TrackingAllocator;

fn track(size: usize) {
    let _ = LARGEST_ALLOCATION.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(size)));
        }
    });
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        track(size);
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[test]
fn forged_record_counts_do_not_preallocate_from_untrusted_counts() {
    for count_offset in [4, 6, 8, 10] {
        let mut header = [0; 12];
        header[count_offset..count_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        LARGEST_ALLOCATION.set(Some(0));
        let result = Message::from_vec(&header);
        let largest = LARGEST_ALLOCATION.replace(None).unwrap();
        assert!(result.is_err());
        assert!(largest <= 4096, "12-byte packet allocated {largest} bytes");
    }
}

#[test]
fn tsig_with_short_declared_length_returns_error_without_panicking() {
    // One additional TSIG, root owner, class ANY, RDLENGTH 1; its algorithm,
    // time, fudge and MAC length extend beyond the declared RDATA boundary.
    let mut bytes = vec![0; 12];
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0; 11]);
    let result = std::panic::catch_unwind(|| Message::from_vec(&bytes));
    assert!(result.is_ok(), "malformed TSIG must not panic");
    assert!(result.unwrap().is_err());
}

#[test]
fn legitimate_question_vectors_can_grow_beyond_initial_capacity() {
    let mut message = Message::new(42, MessageType::Query, OpCode::Query);
    for index in 0..16 {
        message.add_query(Query::query(
            Name::from_ascii(format!("q{index}.example.com.")).unwrap(),
            RecordType::A,
        ));
    }
    let decoded = Message::from_vec(&message.to_vec().unwrap()).unwrap();
    assert_eq!(decoded.queries, message.queries);
}

#[tokio::test]
async fn malformed_datagram_with_wrong_id_does_not_abort_valid_lookup() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = server.local_addr().unwrap();
    let mut connection = ConnectionConfig::udp();
    connection.port = address.port();
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::new(address.ip(), true, vec![connection])],
    );
    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_secs(1);
    options.ip_strategy = LookupIpStrategy::Ipv4Only;
    let resolver = HickoryDns::try_with_config(config, options).unwrap();

    let responder = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_vec(&buffer[..length]).unwrap();
        let wrong_id = request.id.wrapping_add(1).to_be_bytes();
        server.send_to(&wrong_id, peer).await.unwrap();
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_queries(request.queries.iter().cloned());
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        server
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        resolver.resolve("dns-security.example.com.", 443),
    )
    .await;
    responder.abort();
    assert_eq!(
        result.unwrap().unwrap(),
        vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))]
    );
}
